# TORX leak harness results

- generated: `2026-09-30T16:20:43Z`
- commit: `d0e094d`
- mode: `both`
- library: `libtorx.so`

| id | class | method | expected | observed | verdict | ci_gate |
|---|---|---|---|---|---|---|
| `dns.export.getaddrinfo` | dns | static | exported | **not_exported** | REFUTED | true |
| `hook.export.connect` | tcp | static | exported | **exported** | VERIFIED | true |
| `udp.export.sendto` | udp | static | exported | **not_exported** | REFUTED | true |
| `elf.textrel` | elf | static | absent | **absent** | VERIFIED | true |
| `elf.stack_protector` | elf | static | present | **present** | VERIFIED | true |
| `elf.undefined_symbols` | elf | static | none | **none** | VERIFIED | true |
| `tcp.interception` | tcp | dynamic | intercepted | **intercepted** | VERIFIED | true |
| `tcp.passthrough_loopback` | tcp | dynamic | passthrough | **passthrough** | VERIFIED | true |
| `tcp.passthrough_private` | tcp | dynamic | passthrough | **passthrough** | VERIFIED | true |
| `ipv6.passthrough` | ipv6 | dynamic | proxied_or_blocked | **direct:2405:201::** | REFUTED | true |
| `bypass.static_binary` | static | dynamic | intercepted | **bypassed** | REFUTED | true |
| `bypass.raw_syscall` | direct-syscall | dynamic | intercepted | **bypassed** | REFUTED | true |
| `udp.connect_hijack` | udp-correctness | dynamic | passthrough_or_error | **hijack_attempted** | REFUTED | true |
| `udp.fd_swap` | udp-correctness | dynamic | fd_unchanged | **fd_became_tcp** | REFUTED | false |
| `udp.silent_misdelivery` | udp-correctness | dynamic | honored_or_refused | **misdelivered** | REFUTED | false |
| `udp.quic.bypass` | udp | behavioral | intercepted_or_blocked | **bypass_direct** | REFUTED | false |
| `dns.dynamic.egress` | dns | dynamic | proxied_or_blocked | **not_run** | UNTESTED | false |
| `tor.e2e` | tcp | dynamic | IsTor=true | **IsTor:true (3/3)** | VERIFIED | false |

Verdicts: `VERIFIED` matches expectation · `REFUTED` expectation broken · `UNTESTED` could not run (see notes) · `FLAKY` inconsistent.

`UNTESTED` is a claim of absence of test, never a claim of correctness.
