# DETECTION.md — seeing the shim, the leak, and the bypass

**Status: experimental.** This is the defender-side companion to
`THREAT_MODEL.md` (§7, workstream 5) and `LIMITATIONS.md`. Every claim
below cites the `tests/leak/results.jsonl` row that validates it; if a
row's verdict changes, the corresponding rule's status degrades to
`experimental` until re-validated. Rule `id`s never change — statuses do.

The threat model says the artifact is unfixable; this document says it
must be *findable*. That pairing is the point: an LD_PRELOAD Tor shim
cannot be patched into correctness (see `LIMITATIONS.md` §3), so the
operational answer is detect-the-artifact → replace-with-the-netns
architecture (Phase 2).

---

## 1. How to read statuses — two axes, stated separately

| Axis | Question | Where it is answered |
|---|---|---|
| **Phenomenon** | Is the underlying behaviour real? | `tests/leak/results.jsonl` — a cited row with a stable verdict. |
| **Rule** | Has the detection *rule* been executed? | The `Executed?` column in §5. |

- **`status: stable`** — the phenomenon is validated by a committed row
  **and** the rule as written has been reviewed against that evidence.
- **`status: experimental`** — the rule depends on infrastructure that
  is absent from the build host, or its phenomenon evidence is partial.
- **`Executed?`** — whether the rule itself has ever *run*. On this
  build host there is **no auditd pipeline, no Suricata/Zeek, and no
  SIEM**: every Sigma/Suricata/auditd rule below is drafted and
  syntax-checked only (`Executed? = no`). What *is* executed here:
  `make check` (static export/ELF checks), `./tests/leak/run.sh`, and
  the in-process canary in §2.4 — those three say `yes`.

A `stable` rule that was never executed is a **validated claim with a
drafted detector**. That distinction is the whole reason §5 has two
columns; do not let a report collapse them.

---

## 2. Rules by class

### 2.1 TCP — the connection is the observable

The shim's only instrument is `connect()`: every routed IPv4 flow must
reach `127.0.0.1:9050` and be followed by a SOCKS4a handshake.
Validated by `tcp.interception` (dead-port run: `routed:true`, stderr
`[TORX] routing connect() through Torconnect: Connection refused`),
`tor.e2e` (`shim_routed:true`, `is_tor:true`, 3/3), and the negative
controls `tcp.passthrough_loopback` / `tcp.passthrough_private`
(`routed:false` — the hook itself does not dial 9050 for loopback or
RFC1918 targets).

**TORX-DET-tcp-1 (Sigma)** — hunt: non-proxy processes holding a flow
to the local Tor port.

```yaml
title: Process connecting to local Tor SOCKS port (TORX LD_PRELOAD artifact hunt)
id: a6ba1a22-2295-4030-be4d-cded7e45394f
status: stable
logsource:
  category: net_connection
  product: linux
detection:
  selection:
    dst_port: 9050
  condition: selection
falsepositives:
  - Legitimate SOCKS clients (Tor Browser, torsocks, anything configured for 127.0.0.1:9050)
  - Other proxy shims that route via a local daemon
level: low
```

`status: stable` (phenomenon validated). `Executed? = no` — no SIEM on
the build host. **Read the FP list before you alert**: dst-9050 is a
*hunting lead*, not attribution; only correlation with §2.4's in-process
signal (or the artifact's ELF signature) confirms the shim.

**TORX-DET-tcp-2 (Suricata)** — the wire shape of the shim's handshake:
a SOCKS4a `04 01 …` CONNECT as the first client payload.

```text
alert tcp any any -> any 9050 (msg:"TORX-like SOCKS4a CONNECT to local tor port"; flow:to_server,established; content:"|04 01|"; depth:2; sid:9000001; rev:1;)
```

`status: experimental` — **hole 3**: Suricata (and Zeek) are not
installed on the build host, so this rule has never been executed. The
*phenomenon* (SOCKS4a bytes on the wire, `04 01` + port + ip + NUL
terminated userid) is code-level in `torx.c` (`socks4_handshake`) with
routing confirmed by `tcp.interception` — but the rule-as-written gets
no validation beyond review until someone runs it against a capture.
FPs: every legitimate SOCKS4a client (torsocks, `curl --socks4`,
`ssh -D` over socks4).

### 2.2 DNS — the leak that happens before any hook

`getaddrinfo` is **not exported** by `libtorx.so`, so resolver traffic
from a shimmed process is direct *by construction*: there is no hook in
its path. Validated statically by `dns.export.getaddrinfo`
(`exported_T:["connect"]` — the entire dynamic surface is `connect`).

**TORX-DET-dns-1 (artifact inspection)** — this is `make check` /
`run.sh --static`, i.e. already executed in CI on every push:

```bash
nm -D --defined-only libtorx.so | grep -q ' T getaddrinfo' \
  && echo SUSPECT-libtorx-without-dns-hook \
  || echo "no getaddrinfo export -> DNS from shimmed procs is direct"
```

`status: stable`, `Executed? = yes` (every `make check` / static run).

**TORX-DET-dns-2 (correlation)** — drafted:

```text
A:  /proc/<pid>/maps contains libtorx.so        (process is shimmed)
B:  same pid emits UDP/53 to a non-local resolver
A AND B within 60s  ->  DNS was direct by construction
    (dns.export.getaddrinfo: no hook exists to have rerouted it)
```

`status: stable` (phenomenon validated by the static row; correlation
logic is trivial on purpose). `Executed? = no` — needs auditd/procfs
telemetry that this host does not collect. `dns.dynamic.egress` is
recorded `UNTESTED` in the harness (needs CAP_NET_RAW or a controlled
resolver) — the harness's own honesty marker, not a gap in this rule's
logic.

### 2.3 UDP — the export surface is the detection

`sendto`/`sendmsg` are **not exported**, so a UDP payload cannot be
routed even in principle: datagrams leave direct. Validated by
`udp.export.sendto` (`match_count:0`, `exported_T:["connect"]`,
`REFUTED`).

**TORX-DET-udp-1 (artifact inspection)** — again a static check, so
already executed everywhere the harness runs:

```bash
nm -D --defined-only libtorx.so | grep -E ' T (sendto|sendmsg)$' \
  && echo "unexpected UDP hook" || echo "no UDP export -> datagrams go direct"
```

`status: stable`, `Executed? = yes`.

**Real-world consequence (observation, not a harness row):** a QUIC
client bypasses the shim *silently and completely*, because QUIC uses
unconnected sockets — there is no `connect()` for the hook to see:

```bash
# identical output with and without TORX; no "[TORX] routing" trace either way
curl --http3-only -sS -o /dev/null -w '%{exitcode}\n' \
  'https://cloudflare-dns.com/dns-query?name=example.com&type=A'
#   under:  TORX_DEBUG=1 TORX_PORT=9050 LD_PRELOAD=./libtorx.so
```

Both runs exit `0`. The h3 session is direct end-to-end — class-1 leak,
zero errors, zero corruption (§2.4's swap never triggers because
`connect()` is never called). Mark this as an *observation with a
reproducible command*, not a row; the static row above is what grants
the rule its `stable` status.

### 2.4 In-process — the only place the corruption is visible

The corruption class (`udp-correctness`) has no wire signal at all.
What the application can observe after the swap, **measured** by the
harness (`udp.silent_misdelivery` evidence, `udp.fd_swap` evidence):

| Observation | Value | Meaning |
|---|---|---|
| `so_type` after live swap | `1` | fd became `SOCK_STREAM` — `dup2` over a TCP socket. |
| `post_swap_send_rc` / `_errno` | `1` / `0` | `send()` **succeeds** — payload rides the Tor stream. |
| `post_swap_sendto_rc` / `_errno` | `1` / `0` | different destination **silently ignored**, not `EISCONN`. |
| `misdelivery` | `true` | `sendto(B)` succeeded while the payload rides A's stream — **silent misdelivery**, the class of failure worse than a crash: a crash is detectable, this is not. |
| `peer_after_swap` | `127.0.0.1:9050` | `getpeername()` returns the **Tor SOCKS listener**, not the destination the app dialed — the second in-app tell. |
| `post_swap_reconnect_rc` / `_errno` | `0` / `0` | second `connect()` "succeeds". |
| `reroutes` (fd_swap) | `2` | the second `connect()` dialed a **fresh Tor stream** over the same fd (stream identity changes; circuit identity across streams is Tor-policy-dependent and not client-observable — see LIMITATIONS.md §3). |

**Correction to the original draft of this document:** it predicted the
post-swap write would fail with `EPROTOTYPE` (or `EOPNOTSUPP`). It does
not — measured on 2026-09-30 (this host, live Tor 0.4.9.11): **no errno
is ever raised on any of these paths.** Errno-based detection is
therefore refuted, not untested. The in-app tells are
`getsockopt(SO_TYPE)` (or reading `LD_PRELOAD` out of the environment),
and — for apps that check — `getpeername()`/`getsockname()` returning
the loopback SOCKS peer instead of the intended destination. Nothing on
the wire distinguishes this traffic from ordinary proxied TCP.

**TORX-DET-udp2-1 (in-process canary)** — run it in your own code after
your own `connect()`; this is exactly what `probe_udp` executes inside
the harness:

```c
int t = -1; socklen_t l = sizeof t;
getsockopt(fd, SOL_SOCKET, SO_TYPE, &t, &l);
if (t != SOCK_DGRAM)
        /* the fd you were handed is no longer the socket you created */;
struct sockaddr_in p; socklen_t pl = sizeof p;
if (getpeername(fd, (struct sockaddr *)&p, &pl) == 0 &&
    ntohl(p.sin_addr.s_addr) == INADDR_LOOPBACK)
        /* peer is the local SOCKS listener (127.0.0.1:9050), not the
           destination you dialed — the bytes are going elsewhere */;
```

`status: stable`, `Executed? = yes` (`run.sh` dynamic runs execute this
canary on every invocation; `udp.fd_swap` is ci_gate=false only because
it needs a live Tor).

### 2.5 IPv6 — validated, and it leaks

The shim routes **IPv4 only**; non-`AF_INET` connects pass through.
Validated by `ipv6.passthrough` — `REFUTED`, observed
`direct:2405:201::` (mask: `mask_v6()` policy — first two hextets only),
probe `curl -6 https://api64.ipify.org`, `exit:0`.

**Correction to the original draft:** this rule was marked `UNTESTED`
("no IPv6 route on the build host"). That was wrong — the harness runs
it, and it observes direct IPv6 egress today. The rule's *status*
becomes `stable`; what remains unexecuted is only the detector itself.

**TORX-DET-ipv6-1 (auditd)** — drafted:

```
# /etc/audit/rules.d/torx.rules
-a always,exit -F arch=b64 -S connect -F a1=28 -F success=1 -k torx_ipv6_connect
```

`a1=28` is `sockaddr_in6`'s length — a cheap family match; it can
false-positive on other 28-byte sockaddr families (rare; vet before
shipping). `status: stable` (phenomenon validated), `Executed? = no`
(auditd absent from the build host).

---

## 3. What defenders cannot see

The absence cases — each is a committed row, not a hedge:

- **The un-preloaded process.** `bypass.static_binary` (`REFUTED`,
  `-static libc connect()`, `routed:false`) and `bypass.raw_syscall`
  (`REFUTED`, `syscall(__NR_connect)`, `routed:false`) — statically
  linked or syscall-level traffic is *indistinguishable from direct
  traffic*. Detection must then fall back on §2.1-style flow hunting
  (or the artifact on disk), because this process emits no shim signal.
- **DNS that already left.** §2.2: no hook exists in the resolver's
  path; by the time anything is observable, the query is on the wire.
- **Unconnected UDP / QUIC.** §2.3: nothing to hook, nothing on the
  wire that marks it as a leak, exit code `0`.
- **The corruption itself.** §2.4: every syscall reports success. A
  network defender sees a normal Tor stream; only the *application*
  holding the socket could notice, and only by asking `SO_TYPE`.

## 4. Operational notes

- **Two columns, never one.** A report that says "7 rules, 6 stable"
  has already lost the distinction §1 exists to protect: six of those
  seven have never touched a telemetry pipeline. Quote `status` and
  `Executed?` together.
- **Rule ids are frozen.** `id:` fields survive status downgrades;
  degradation is a content edit (`stable` → `experimental`) plus a
  pointer to the row whose verdict moved.
- **Combination beats any single rule.** dst-9050 + IPv6 egress from
  the same pid + an ELF with `T connect` as its only dynamic export is
  the artifact; each signal alone is a lead.
- **QUIC is the quiet case.** §2.3's observation: full bypass, clean
  exit, no trace — if your only control is "did Tor get the flow?", h3
  will never trip it.

## 5. Cross-reference

| Rule | Class | Status | Executed? | Validated by | Evidence rows |
|---|---|---|---|---|---|
| `TORX-DET-tcp-1` (Sigma) | tcp | stable | no — needs SIEM | `row` | `tcp.interception`, `tor.e2e`, `tcp.passthrough_*` |
| `TORX-DET-tcp-2` (Suricata) | tcp | **experimental** | no — Suricata/Zeek absent | `draft` | phenomenon: `tcp.interception` + `torx.c` |
| `TORX-DET-dns-1` (nm check) | dns | stable | **yes** — `make check` / `--static` | `row` | `dns.export.getaddrinfo` |
| `TORX-DET-dns-2` (correlation) | dns | stable | no — auditd absent | `row` | `dns.export.getaddrinfo` |
| `TORX-DET-udp-1` (nm check) | udp | stable | **yes** — `make check` / `--static` | `row` | `udp.export.sendto` |
| `TORX-DET-udp2-1` (in-process) | udp-correctness | stable | **yes** — executed by `run.sh` | `row` | `udp.fd_swap`, `udp.silent_misdelivery`, `udp.connect_hijack` |
| `TORX-DET-ipv6-1` (auditd) | ipv6 | stable | no — auditd absent | `row` | `ipv6.passthrough` |

`Validated by` is a machine-readable enum: **`row`** = a committed
`results.jsonl` row re-checks this rule's claim on every harness run;
**`draft`** = written and source-reviewed only, nothing mechanical ties
it to the evidence (only `tcp-2`, because the SOCKS4a-on-the-wire claim
has never been captured). `none` is reserved for a rule with no
evidence trail at all — there are none. `Status` is the phenomenon,
`Executed?` is the detector: the two stay separate on purpose.

Anchors for the `limitation_ref`s cited above: `LIMITATIONS.md#1-dns`,
`#2-ipv6`, `#3-tcp`, `#static`, `#raw-syscall`, `#udp`.

## 6. Reproducing

```bash
make check                       # executes dns-1 and udp-1 (static checks)
./tests/leak/run.sh              # full run: 17 rows, live-Tor rows degrade honestly
./tests/leak/run.sh --static     # partial run: merges, never overwrites dynamic rows

# the evidence table this document cites:
grep -v '"_meta"' tests/leak/results.jsonl \
  | jq -r '[.id,.class,.verdict,(.evidence|tostring)]|@tsv'

# §2.3's QUIC observation (needs --http3-capable curl + egress):
curl --http3-only -sS -o /dev/null -w '%{exitcode}\n' \
  'https://cloudflare-dns.com/dns-query?name=example.com&type=A'
```

Results-snapshot policy (what may diff on regeneration) is in
`tests/leak/README.md`; the record contract is `tests/leak/SCHEMA.md`.
To exercise the drafted rules, load them into your pipeline — this
repository ships detections, not a telemetry stack.
