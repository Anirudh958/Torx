# TORX v0.1.0-legacy — Limitations

**Scope.** Everything below describes the `LD_PRELOAD` shim in this
repository (`libtorx.so`), which `THREAT_MODEL.md` §3 labels *v0.1.0-legacy*:
a best-effort measurement baseline, not a security tool. Nothing here applies
to the Phase-2 architecture (netns + cgroup BPF + nftables) — see §8.

**Method.** Every leak claim is a row in `tests/leak/results.jsonl`, produced
by `tests/leak/run.sh` (see `tests/leak/README.md`). Verdicts:

| verdict | meaning |
|---|---|
| `VERIFIED` | observation matches expectation |
| `REFUTED` | expectation broken — this is a real, reproducible leak |
| `UNTESTED` | the test could not run; **a claim of absence of test, never of correctness** |
| `FLAKY` | inconsistent across attempts |

CI enforces `expected_verdict` on every `ci_gate` row, **in both
directions**: a leak appearing is a regression, and a leak disappearing is an
undocumented behaviour change until this file says otherwise.

## Current results (18 rows)

| id | class | verdict | one-line statement |
|---|---|---|---|
| `dns.export.getaddrinfo` | dns | **REFUTED** | name resolution is never proxied |
| `hook.export.connect` | tcp | VERIFIED | the interposer is exported (baseline) |
| `elf.textrel` / `elf.stack_protector` / `elf.undefined_symbols` | elf | VERIFIED ×3 | library properties hold |
| `tcp.interception` | tcp | VERIFIED | a public IPv4 `connect()` is intercepted |
| `tcp.passthrough_loopback` | tcp | VERIFIED | loopback bypasses Tor (by design) |
| `tcp.passthrough_private` | tcp | VERIFIED | RFC1918 bypasses Tor (by design) |
| `ipv6.passthrough` | ipv6 | **REFUTED** | IPv6 egress goes out directly |
| `bypass.static_binary` | static | **REFUTED** | `-static` binaries are never seen |
| `bypass.raw_syscall` | direct-syscall | **REFUTED** | `syscall(__NR_connect)` is never seen |
| `udp.export.sendto` | udp | **REFUTED** | no `sendto`/`sendmsg` hook: UDP payload never routes |
| `udp.quic.bypass` | udp | **REFUTED** | HTTP/3 exits direct and identical under the shim — invisibly unproxied |
| `udp.connect_hijack` | udp-correctness | **REFUTED** | UDP `connect()` is routed as TCP |
| `udp.fd_swap` | udp-correctness | **REFUTED** | the UDP fd is silently replaced by a TCP socket |
| `udp.silent_misdelivery` | udp-correctness | **REFUTED** | `sendto()` succeeds after the swap; the address is silently dropped |
| `dns.dynamic.egress` | dns | UNTESTED | egress not observed (needs `CAP_NET_RAW`) |
| `tor.e2e` | tcp | VERIFIED | end-to-end egress is genuinely Tor |

---

## 1. DNS

**Behaviour.** Hostname resolution never touches the shim. `nm -D
--defined-only libtorx.so` exports exactly one symbol — `connect` — so
`getaddrinfo(3)` / `gethostbyname(3)` fall through to glibc's resolver, which
asks the system resolver directly.

**Why.** The shim interposes one function by design. The SOCKS side is
SOCKS4-only and the hook always passes `hostname=NULL` (torx.c:309), so even
the routed path hands Tor a resolved IP, never a name.

**Measured.** Row `dns.export.getaddrinfo` → `REFUTED`, `observed:
not_exported`. Provable with no network and no Tor; also asserted at build
time by `make check`.

**Consequences.**

- Every query name leaves the host in cleartext (unless the *application*
  uses DoH/DoT) — visible to the LAN observer and resolver operator (A1).
  The TCP flow being routed through Tor does not repair this: the destination
  **name** was already disclosed.
- The application connects to the resolver's answer, so resolver hijack,
  NXDOMAIN redirection and captive portals steer the app before Tor sees it.
- DNS answers are not isolated per circuit: `IsolateSOCKSAuth` governs SOCKS
  streams, not the local resolver's cache.

**Fix path.** Phase 2: nftables redirects all `:53` traffic inside the netns
to Tor's `DNSPort`, so every resolution is forced through Tor. Hooking
`getaddrinfo` instead would be a band-aid that §§4 and 5 bypass anyway.

---

## 2. IPv6

**Behaviour.** `connect()` passes anything with `sa_family != AF_INET`
straight to the real libc (torx.c:278) — including `AF_INET6`.

**Measured.** Row `ipv6.passthrough` → `REFUTED`, `observed: direct:2405:201::`
(address masked in `results.jsonl`; the harness never commits full
addresses).

**Why it matters more than it sounds.** Happy Eyeballs and RFC 6724 make
dual-stack hosts prefer native IPv6 by default. On such a host the shim's
protection is not merely incomplete — the *preferred* path bypasses it, while
the UI still says "Tor". The user's stable, prefix-stable IPv6 address is
disclosed to the destination and to every on-path observer.

**Why it cannot be fixed by hooking.** SOCKS4a is IPv4-only. There is no
address family in the protocol to carry an IPv6 destination. The only
options are to block `AF_INET6` or to upgrade to SOCKS5.

**Measured mitigation (host-level, outside this code).** Disabling IPv6 on
the interface removes the leak; the harness reports `UNTESTED` when the host
has no IPv6 route.

**Fix path.** Phase 2: the netns defaults to deny; only explicitly permitted
IPv4 through Tor exists. IPv6 is blocked by policy, not by a missing hook.

---

## 3. TCP

This section is the interposer's blast radius: what it routes, what it
deliberately does not, and what it corrupts on the way.

**Routed (intended).** `AF_INET` `connect()` to a public address → SOCKS4a
through `127.0.0.1:9050` (row `tcp.interception` → `VERIFIED`).

**Passthrough by design (correct, but a boundary to document).**
Loopback, RFC1918, link-local, multicast, broadcast, short/invalid
addresses, and every non-`AF_INET` family (torx.c:275-301). Verified by
rows `tcp.passthrough_loopback` and `tcp.passthrough_private` →
`VERIFIED`. Tor cannot reach these, and hijacking them breaks local
services (including Tor itself).

**Fail-closed vs fail-open.** On the routed path the shim fails closed:
`dial_tor() < 0` returns `-1` and a failed SOCKS handshake returns `-1`
(torx.c:307-313) — Tor down means the connection fails (this is what
`tcp.interception` measures with `TORX_PORT=1`). The passthrough paths fail
*open by definition*: IPv6 and DNS never consult Tor at all (§§1-2).

**The `dup2()` swap (code-level).** On success the app's fd is replaced with
the Tor socket (torx.c:317-323). The original socket is discarded along with
its flags: `O_NONBLOCK` and other per-socket state are not preserved
(torx.c:325-327 admits this), and any data already buffered is lost.
`SOCK_CLOEXEC` is set on the replacement.

**Not routed (by design).** UDP payload, ICMP, raw sockets, `AF_UNIX`
(code-level: `torx.c:279`, not harness-tested), netlink and other families.

<a id="udp"></a>

### UDP — two failure classes

UDP fails in two structurally different ways, and conflating them hides
that each needs a different remediation. The harness keeps them in
separate classes (`udp` vs `udp-correctness`) for the same reason.

**Class 1 — anonymity (`udp.export.sendto` → `REFUTED`).** The shim
exports exactly one symbol, `connect`. There is no `sendto`/`sendmsg`
hook, so no UDP payload — DNS-over-UDP, QUIC, VoIP — can ever be steered
through Tor. Those bytes leave the process on the direct path: UDP is
simply not anonymized (`THREAT_MODEL.md` §6).

**QUIC, measured (`udp.quic.bypass` → `REFUTED`).** The class-1 leak at
browser scale: `curl --http3-only` against
`https://cloudflare-dns.com/dns-query` negotiates HTTP/3 and exits `0`
*identically* with and without `LD_PRELOAD=libtorx.so`, with
`shim_trace_count:0` — QUIC uses unconnected sockets, so there is no
`connect()` for the shim to intercept, and no error anywhere. The app
believes it is proxied; the shim never sees it; the bytes go direct.
Any modern browser speaking HTTP/3 is invisibly unproxied under this
tool. (`method: behavioral` — a real client observed end-to-end, not a
probe; never a CI gate.)

**Class 2 — correctness (`udp.connect_hijack` → `REFUTED`, `udp.fd_swap`
→ `REFUTED`).** The hook never checks `socktype`, so a `SOCK_DGRAM`
`connect()` is routed as if it were TCP (`SOCKS4` is TCP-only, so no
correct routing exists). Against a live Tor the SOCKS reply succeeds and
`dup2()` puts a **TCP socket where the application's UDP socket was**
(`so_type: 1`). Concretely: a resolver that `connect()`s a UDP socket and
then writes datagrams is now writing payload bytes into a TCP stream —
silently, with `connect()` returning success. For anything that uses the
connected UDP socket as a multi-peer endpoint (`sendto()` to other
addresses), the data is misdelivered rather than refused. This is worse
than not anonymizing it — it corrupts it.

**Misdelivery, measured (`udp.silent_misdelivery` → `REFUTED`).** After
the swap, `sendto(8.8.8.8:53)` returns success (`rc:1`, `errno:0`) while
the payload rides the stream opened for `1.1.1.1:53` — the address is
discarded by the kernel because the socket is now connected
(evidence: `intended_dest`, `first_stream_target`, `addr_ignored:true`).
No errno fires on `send`/`sendto`/`connect`; the only in-app tells are
`SO_TYPE` and `getpeername()`, which returns the Tor SOCKS listener
(`127.0.0.1:9050`, evidence `peer_after_swap`) instead of the
destination the app dialed. A second `connect()` re-routes on the same
fd (`reroutes:2`) — a *new* SOCKS stream each time. Whether Tor assigns
a different circuit per stream is policy-dependent and not observable
from the client side here (no control port), so the row records stream
identity, not circuit identity.

**Why the split matters for remediation.** A socktype check (refuse or
bypass `SOCK_DGRAM`) removes class 2 only: the socket stops being
corrupted and UDP reverts to class 1 — a bare leak, which is at least
honest. Removing class 1 needs a real UDP path (SOCKS `UDPASSOCIATE`, a
`sendto`/`sendmsg` hook, or Phase-2 nftables/DNSPort). Only the Phase-2
architecture removes both at once.

---

## 4. Static binaries

<a id="static"></a>

**Behaviour.** A `-static` binary has no `PT_INTERP`, so no dynamic loader
runs, so `LD_PRELOAD` is never consulted. The shim does not fail; it is
never *loaded*.

**Measured.** Row `bypass.static_binary` → `REFUTED`, `observed: bypassed`
(exit 0 with no shim trace — the connection simply succeeds unaided).

**Same class, not individually tested:** any binary without a cooperating
dynamic linker — `AT_SECURE`/setuid (glibc drops `LD_PRELOAD` in secure
execution mode), static Go/musl builds, and anything the wrapped application
spawns outside its environment. See §6.

**Why this is fatal to the design.** The guarantee lives in the *target's*
loader. The hostile application (A4) chooses the binary format; a defender
cannot make `LD_PRELOAD` loadable, and cannot audit an `LD_PRELOAD` chain
they did not start. This is one of the two structural arguments for
abandoning `LD_PRELOAD`.

---

## 5. Raw syscalls

<a id="raw-syscall"></a>

**Behaviour.** `LD_PRELOAD` interposes dynamic *symbol* resolution. A direct
`syscall(__NR_connect, ...)` never consults libc and therefore never consults
the shim.

**Measured.** Row `bypass.raw_syscall` → `REFUTED`, `observed: bypassed`
(the probe reaches the target while the shim reports nothing).

**Same class, not individually tested:** `io_uring` `IORING_OP_CONNECT`
(the request is processed in-kernel, never entering libc), assembly-level
direct syscalls, and runtimes that never use libc for connect (Go's
`net` package on Linux). See §6.

**Why this is fatal.** One probe program, fifteen lines, defeats the entire
mechanism. Any bypass of the dynamic linker defeats the shim — the general
form of §4, and the second structural argument for abandoning `LD_PRELOAD`.

---

## 6. Untested classes (`UNTESTED`)

Absence of a test here is not evidence of safety. Each row says what would
settle it.

| class | why untested | what would settle it |
|---|---|---|
| `dns.dynamic.egress` | observing DNS egress needs `CAP_NET_RAW` (tcpdump) or a controlled resolver | capture in a netns with a dedicated resolver |
| `AT_SECURE` / setuid preload drop | needs a setuid helper binary we control | build one in the test tree, compare traces |
| `io_uring` connect | needs an `io_uring_setup` probe (kernel ≥ 5.6) | `probe_uring.c` |
| Go binaries (raw syscalls) | needs the Go toolchain in CI | `probe_go.go` |
| `AF_UNIX` passthrough | code reading only (`torx.c:279`) | add a unix-socket probe row |
| circuit isolation (`IsolateSOCKSAuth`) | needs Stem/`GETINFO circuit-status` | compare circuit ids across two processes |
| dial/handshake timeouts | `dial_tor()`/`socks4_handshake()` have no explicit deadline (code reading) — a stalled Tor could hang the app | a slow-TOR test double |
| `strace`-based cross-checks | `strace` is absent on the build host | install strace; the harness deliberately avoids needing it (`TORX_PORT=1`) |

---

## 7. Enforcement

- `tests/leak/run.sh --static` runs on every PR: no network, no Tor,
  deterministic (`nm`/`readelf`/`ldd`).
- The dynamic half runs on a scheduled/tagged job where egress exists; with
  no egress it degrades to `UNTESTED` instead of failing, so a dead runner
  is never mistaken for a leak.
- Partial runs merge into `results.jsonl` by id — a static run can never
  erase recorded dynamic evidence (and dynamic degradation never touches
  static rows).
- Every `results.jsonl` starts with a `_meta` line (schema, generated,
  commit, mode, host, Tor version), so a committed snapshot is
  self-describing: `commit` is the revision the run executed at.
- `make check` backstops the headline claim at build time (DNS assertion:
  if `getaddrinfo` ever becomes exported, the build fails until this file
  and the assertion are updated).
- The Phase-2 enforcement harness is gated the same way —
  `tests/enforce/run.sh` (`tests/enforce/README.md`): its `signal.*`
  static rows run on every PR; `control.loopback` and the boundary rows
  record wherever dynamic mode runs, degrading to `UNTESTED (reason:)`
  on hosts that cannot build a boundary (measured on CI runners,
  2026-10-02 — `docs/build-notes.md`).

## 8. Fix path (why Phase 2 exists)

Each limitation above is a symptom of the same root cause: **the enforcement
lives inside the process it is trying to constrain.**

| limitation | Phase-2 mechanism that removes it |
|---|---|
| §1 DNS | nftables redirects `:53` to Tor `DNSPort` inside the netns — resolution has no other path |
| §2 IPv6 | netns policy: default-deny, only permitted IPv4 exists |
| §3 UDP (both classes) | no interposer, no `dup2`; kernel routes or drops by policy, socktype irrelevant |
| §4 static binaries | netns/cgroup enforcement does not care what loader the binary has |
| §5 raw syscalls | the syscall reaches the same cgroup/nft rules regardless of who issued it |

`THREAT_MODEL.md` §7 holds the rest of the argument; §6 lists what Phase 2
*still* cannot fix (timing correlation, user deanonymization, a hostile Tor).
