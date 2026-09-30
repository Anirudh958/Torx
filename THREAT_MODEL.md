# TORX Threat Model

**Thesis:** Traffic routing is not a userspace cooperation problem. Every
`LD_PRELOAD` Tor shim — `torsocks`, `proxychains-ng`, `torify`, and TORX
v0.1.0-legacy — asks the application to cooperate, and applications (hostile,
static, seccomp'd, or merely clever) do not. Enforcement belongs in the
kernel: netns + cgroup-v2 BPF + nftables, fail-closed.

This document is the contract for that claim. It defines *who* we defend
against, *what* we promise, and — explicitly — what we do not. It is versioned
with the tool: a claim in this file that stops being true is a breaking change.

**Status of the code in this repository.** The current `torx.c` is the
LD_PRELOAD shim. It is the *control group* — the "before" of the argument, kept
as `legacy/` once Phase 2 lands. Measured today against this model, it fails
adversaries A1, A2, A4, A6 and A7. That is not a defect report; it is the
experiment.

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| Origin IP address | The single fact the whole system exists to hide |
| DNS query log | Reveals intent even when TCP is proxied |
| Traffic correlation (timing, size, destination) | Links origin to destination across the Tor network |
| Circuit identity | Reuse across invocations links otherwise separate activities |
| Local process/ptrace surface | A compromised app can exfiltrate around any shim |

## 2. Trust boundaries

```
        ┌─────────────────────────────────────────────┐
        │  UNTRUSTED: wrapped process                 │
        │  may be hostile, static, seccomp'd, setuid  │
        └──────────────────┬──────────────────────────┘
                           │ syscalls only
        ┌──────────────────▼──────────────────────────┐
        │  TRUSTED-ENOUGH: kernel enforcement layer   │  ← Phase 2 guarantee
        │  netns / cgroup BPF / nftables (fail-closed)│
        └──────────────────┬──────────────────────────┘
                           │
        ┌──────────────────▼──────────────────────────┐
        │  TRUSTED: torx launcher, Tor daemon         │
        │  our code, our config, our audit log        │
        └──────────────────┬──────────────────────────┘
                           │
        ┌──────────────────▼──────────────────────────┐
        │  UNTRUSTED: Tor network, destination, LAN   │
        └─────────────────────────────────────────────┘
```

The wrapped process is on the **untrusted** side of the boundary. It is not an
actor we persuade; it is an actor we constrain. This is the inversion the
project is built on: an adversary fails-silent and evades, we fail-closed and
log.

## 3. Adversaries

### A1 — Passive network observer
**Capability:** sees all traffic leaving the origin host (ISP, local network,
upstream). Cannot modify it.
**Goal:** learn what the user is doing, or that they use Tor at all.
**In scope:** origin IP must never appear in cleartext alongside destination
traffic. DNS must not leave in cleartext (§4.2).
**Out of scope:** traffic-analysis correlation of packet timing/size across
the Tor network; Tor's own cover-traffic is the mitigation, not ours.
**v0.1.0-legacy verdict:** TCP passes. **DNS leaks** — `getaddrinfo` is
*resolved* by the shim but never *exported*, so name resolution goes to the
system resolver directly.

### A2 — Local unprivileged attacker (same host, different uid)
**Capability:** arbitrary unprivileged code, can read `/proc`, open sockets,
observe network with AF_PACKET if permitted.
**Goal:** de-anonymize the wrapped process or hijack its traffic.
**In scope:** the wrapped process must not be reachable on the loopback
control plane; its traffic must not bypass the enforcement layer.
**Out of scope:** kernel 0-days; the attacker is assumed to stay unprivileged.
**v0.1.0-legacy verdict:** **fails.** No netns separation, no namespace
distinction — attacker shares the network stack with the wrapped process.

### A3 — Malicious destination / hostile service
**Capability:** controls the server the user connects to; sees source IP if
routing fails, can attempt reverse connections.
**Goal:** identify the origin, or push traffic back into the origin's network.
**In scope:** no inbound path to the wrapped process; no origin IP exposure.
**Out of scope:** attacks on the user *after* the user has voluntarily
deanonymized themselves in-band (typing an identifier into a form).
**v0.1.0-legacy verdict:** partial. Outbound is proxied, but nothing prevents
the wrapped process from opening its own unproxied socket.

### A4 — The wrapped application itself (hostile)
**Capability:** arbitrary code execution inside the process — it may be
malware, or a legitimate tool with an exfil channel. Uses raw syscalls,
`syscall(__NR_connect, ...)`, static linking, Go runtime, io_uring.
**Goal:** reach the real network without going through Tor.
**In scope (Phase 2):** enforcement must hold under raw syscalls, static
binaries, and musl — because the kernel, not libc, is the enforcement point.
**Out of scope:** the app escaping the *host* (container/kVM breakout);
capabilities are dropped but host isolation is assumed, not enforced.
**v0.1.0-legacy verdict:** **fails, by construction.** Any direct syscall to
the kernel bypasses a libc interposer. This is the adversary that motivates
the entire project.

### A5 — Local root on the origin host
**Capability:** everything.
**Goal:** anything.
**Out of scope, entirely.** Root on the origin host defeats every design in
this space, including Tails and Whonix. Documenting otherwise would be dishonest.

### A6 — Tor-network adversary (malicious guard/middle/exit)
**Capability:** operates Tor relays; may observe both ends of a circuit
segment.
**Goal:** correlate origin and destination, or see plaintext at the exit.
**In scope:** per-invocation circuit isolation; `IsolateSOCKSAuth` tokens
unique per process so two runs never share a circuit (testable, §5).
**Out of scope:** end-to-end correlation attacks against Tor itself; use TLS.
**v0.1.0-legacy verdict:** **partially fails.** `make_userid()` generates a
per-process SOCKS4 userid (good — isolation *mechanism* exists), but the
userid is generated once per request from `getrandom()` with a `pid ^ time()`
fallback, and there is no test asserting two invocations get different
circuits.

### A7 — Local attacker with ptrace / core-dump access
**Capability:** `ptrace` the wrapped process, or read its core dump.
**Goal:** extract secrets, destination list, or credentials in memory.
**In scope (Phase 2):** `PR_SET_DUMPABLE 0`, `PR_SET_NO_NEW_PRIVS`, capability
drop, seccomp filter denying `ptrace`/`process_vm_readv`/`kcmp`/`userfaultfd`.
**Out of scope:** same-uid attacker on a kernel without those primitives.
**v0.1.0-legacy verdict:** **fails.** None of these are applied.

## 4. Guarantees (Phase 2 target)

### 4.1 Fail-closed
If nftables rules fail to apply, or cgroup BPF fails to attach, or Tor's
SocksPort is unreachable at launch — **the launcher aborts before `exec`**.
There is no degraded mode in which traffic flows unproxied. A tool that fails
open converts a proxy outage into a deanonymization event.

### 4.2 No cleartext DNS from inside the enforcement layer
DNS exits only via Tor's `DNSPort`. Name resolution never reaches the system
resolver.

### 4.3 Isolation
Every `torx run` invocation receives a distinct isolation token. Two
invocations must not share a circuit. This is asserted, not assumed.

### 4.4 Auditability
Every run writes JSONL: target, circuit fingerprints, bytes, timing, and
leak-suite results. The evidence a reviewer uses to trust the tool. (Adversaries
delete logs; we publish them.)

## 5. How claims are tested

Every row below is a record in `tests/leak/results.jsonl`
(`tests/leak/run.sh`; schema and gate semantics in `tests/leak/README.md`,
interpretation in `LIMITATIONS.md`).

| Claim | Test |
|---|---|
| TCP routed through Tor | `tor.e2e` — 3× `check.torproject.org` under `LD_PRELOAD` |
| Intercept positive control | `tcp.interception` — public IPv4 connect under `TORX_PORT=1` |
| DNS not leaked | `dns.export.getaddrinfo` — `nm -D`, asserted again by `make check` |
| IPv6 not leaked | `ipv6.passthrough` — `curl -6` must be proxied or blocked |
| Loopback/LAN not routed | `tcp.passthrough_loopback`, `tcp.passthrough_private` |
| Raw-syscall bypass blocked | `bypass.raw_syscall` — `syscall(__NR_connect)` probe |
| Static-binary bypass blocked | `bypass.static_binary` — `-static` probe |
| UDP payload never routes | `udp.export.sendto` — no `sendto`/`sendmsg` export (class `udp`) |
| UDP not corrupted | `udp.connect_hijack`, `udp.fd_swap`, `udp.silent_misdelivery` (class `udp-correctness`) |
| Fail-closed on Tor outage | implied by `tcp.interception` (dead SOCKS port ⇒ connect fails) |
| Circuit isolation | *planned* `tests/isolation/` — `GETINFO circuit-status` differs (UNTESTED) |

Empirical status of v0.1.0-legacy, measured by the harness on the build
host (GCC 14.2, Tor on 127.0.0.1:9050, full run 2026-09-30):

```
exported symbols ........... connect                (only)
TCP egress via Tor ......... PASS   IsTor:true 3/3, shim_routed=true
interception control ....... PASS
loopback passthrough ....... PASS   (not routed, ECONNREFUSED from real stack)
private passthrough ........ PASS   (RFC1918 bypasses by design)
DNS resolution ............. LEAK   getaddrinfo never exported
IPv6 egress ................ LEAK   direct:2405:201:: (address masked)
static-binary bypass ........ LEAK   -static ignores LD_PRELOAD entirely
raw-syscall bypass ......... LEAK   syscall(__NR_connect) unobserved
UDP payload ................. LEAK   no sendto/sendmsg export, payload goes direct
UDP connect/fd swap ......... LEAK   routed as TCP; live Tor swaps fd -> SOCK_STREAM
circuit isolation .......... UNTESTED (needs Stem/GETINFO circuit-status)
```

Full verdict table with evidence: `LIMITATIONS.md` and `tests/leak/results.md`.

## 6. Non-guarantees

Stated plainly, because a threat model that only lists wins is marketing:

- **No protection against timing/size correlation by a global observer.**
- **No protection if the user deanonymizes themselves in-band** (login forms,
  unique documents, cookies).
- **No protection against root on the origin host** (A5).
- **No protection if Tor itself is compromised.**
- **No anonymity for UDP, ICMP, or raw sockets** — only TCP is routed. The
  harness keeps UDP's two failure classes apart: no `sendto`/`sendmsg` hook
  means UDP payload never enters Tor at all (`udp.export.sendto`, class
  `udp`), and a `SOCK_DGRAM` `connect()` is additionally converted into a
  TCP connection instead of being refused (`udp.connect_hijack`,
  `udp.fd_swap`, class `udp-correctness`) — both documented in
  `LIMITATIONS.md` §3 (`#udp`).
- **v0.1.0-legacy is not a security tool.** It is a measurement baseline.

## 7. Relationship to the research contribution

1. **Why `LD_PRELOAD` was always wrong** — theory, plus the leak taxonomy.
2. **TORX legacy: a best-effort shim, and where it still leaks** — this
   document's §3 verdicts, measured.
3. **The correct architecture** — netns + cgroup BPF + nftables.
4. **Evaluation** — leak rate (legacy vs. `torsocks` vs. netns), latency,
   isolation.
5. **Detection** — how a defender sees all three ([`DETECTION.md`](DETECTION.md)).

The rigor of a sophisticated adversary, in service of a reproducible claim:
fail-closed where an adversary would fail-silent, auditable where an adversary
would be anti-forensic, documented where an adversary would obfuscate,
detection-friendly where an adversary would evade. The rigor transfers; the
intent inverts.
