# TORX

Research artifact: a Tor traffic-shim prototype, plus the empirical case for
**why `LD_PRELOAD` is the wrong layer** for forcing traffic through Tor.

The shim (`libtorx.so`) intercepts `connect(2)` and routes public IPv4 TCP
through a local SOCKS4a port. It works — and it leaks anyway. The repository
is built around proving that claim mechanically, not asserting it.

## Read this first

| document | what it is |
|---|---|
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | adversarial model (A1–A7), guarantees/non-guarantees, the v0.1.0-legacy → Phase-2 (netns/cgroup/nftables) thesis, test strategy |
| [`LIMITATIONS.md`](LIMITATIONS.md) | every known failure, each one backed by a recorded test row |
| [`DETECTION.md`](DETECTION.md) | defender-side rules per leak class, each citing the row that validates it, plus draft boundary-era rules for the Phase-2 tree (§6) |
| [`SECURITY.md`](SECURITY.md) | findings policy — what is a bug here, what is the thesis |
| [`docs/why-not-torsocks.md`](docs/why-not-torsocks.md) | why the mature shim is still the wrong primitive — the two lineages (libc interposition vs. netns/nftables), credited fairly |
| [`docs/enforcement.md`](docs/enforcement.md) | the Phase-2 enforcement primitive — netns/cgroup-BPF/nftables topology, mechanism→property→proof mapping, fail-closed launch order, coverage enumeration |
| [`docs/harness.md`](docs/harness.md) | the Phase-2 observer harness — three-party separation, evidence sources, row families (incl. inverted coverage rows), polarity birth, open questions |
| [`tests/leak/README.md`](tests/leak/README.md) | the leak-taxonomy harness: modes, schema, CI gate semantics |
| [`tests/enforce/README.md`](tests/enforce/README.md) | the Phase-2 enforcement harness — current rows, modes, gate |
| [`docs/build-notes.md`](docs/build-notes.md) | how to build it and the gotchas that produced the current Makefile |

## Quick start

```sh
make && make check                    # build + static assertions
make test                             # leak harness (degrades without egress)
TORX_DEBUG=1 ./bin/torx curl -s https://check.torproject.org/api/ip   # "IsTor": true
```

## The headline results

Deterministic, no network needed (`nm -D --defined-only libtorx.so`):

- `getaddrinfo` is **never exported** → every DNS query leaves the host in
  cleartext, before Tor is ever involved.
- A `-static` binary, or any direct `syscall(__NR_connect)`, is never seen →
  **the enforcement lives inside the process it tries to constrain.**
- IPv6 is passed through untouched, and UDP fails in two distinct ways:
  payload can never route (no `sendto`/`sendmsg` export), and a UDP
  `connect()` is actively converted to TCP (corrupting the socket).

Full verdict table with evidence: [`LIMITATIONS.md`](LIMITATIONS.md) and
[`tests/leak/results.md`](tests/leak/results.md). The verdicts are enforced
in CI: if a documented leak silently appears *or* silently disappears, the
gate fails until the docs are updated. `tests/leak/results.jsonl` is a
committed evidence snapshot with a self-describing `_meta` first line —
regeneration may diff `_meta`; a verdict diff is a finding.

## Status

`v0.1.0-legacy` — measurement baseline for the paper. Not a security tool;
`LIMITATIONS.md` is the contract. The Phase-2 architecture (network
namespace + cgroup eBPF + nftables) removes the entire class of failure by
moving enforcement out of user space — see `THREAT_MODEL.md` §7.

MIT licensed.
