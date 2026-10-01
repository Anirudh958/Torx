# netns/ — the fail-closed boundary launcher

`torx-launch` is the §5 sequence of `docs/enforcement.md` as one
synchronous, crash-safe program: unprivileged lab topology (netns, veth,
nftables, cgroup), capability drop, exec of the wrapped target, and a
JSON report of exactly what stood up before the target ran.

```
torx-launch [--mode=auto|lab|reference] [--report FILE] -- cmd [args...]
```

Exit contract: `0..125` = launch completed and the target exited N (a
target killed by signal N exits `128+N`); `70` = the launcher aborted
somewhere in §5 — fail-closed, `report.step`/`report.reason` say where;
`64` = usage. The report's `status` field is authoritative: a target
that itself exits 70 still produced a completed launch.

## Modes (docs/enforcement.md §2.1)

The mode is a measurement, not a preference: `auto` picks reference iff
the process holds `CAP_NET_ADMIN`, and a forced `--mode=reference`
without that capability aborts before touching any state.

- **reference** — claims the full §5: trusted side is the host netns,
  probes must see Tor's SocksPort, TransPort and DNSPort (their absence
  aborts — deployment prerequisite), and §5 step 6 additionally requires
  the BPF loader. Reference mode is unreachable on hosts without
  `CAP_NET_ADMIN`, by design.
- **lab** — the unprivileged default: the trusted side is a user+netns
  pair (`N1`) created by the launcher, the wrapped process runs in a
  second netns (`N2`) under the same userns, the cgroup/BPF sensor row
  records `EPERM` as the declared scope boundary
  (`kernel.unprivileged_bpf_disabled=2`, `docs/build-notes.md`), and the
  observer is declared absent (lands with `probes/`).

## Topology (lab)

```
N1 (launcher, userns root)          N2 (child netns)
  veth-torx-h  10.187.0.1/30  <->   veth-torx-c  10.187.0.2/30
  table inet torx_b (guard)           table inet torx (nat + filter)
  backstop: input, veth-scoped        output: DNAT tcp->9040, dns->5353,
  {9040,5353} accept, else drop       else drop (policy drop)
```

Both rulesets were applied and verified against this host's nft 1.1.3
in `unshare -Urn` (see `docs/build-notes.md`); verification is
`nft -j list table inet <t>` succeeding with applied rules present —
"present and active", the §5 step-5 bar.

## The report

Every launch writes `--report FILE` (omitted = no report file):

```json
{"report_schema":1,"mode":"lab","mode_reason":"...","status":"ok",
 "target_exit":0,"sensor":"...","cgroup":"...",
 "steps":[{"n":1,"name":"tor_probe","status":"ok","detail":"..."} ...]}
```

Failures instead carry `step` + `reason`. Strings are sanitized at the
two formatting sinks (quotes/backslashes/control bytes become `_`), so
the JSON is written directly without an escaping layer.

## Prerequisites

- lab: `/usr/sbin/nft` (PATH is extended automatically), `ip`, a
  delegated cgroup subtree (cgroup v2), unprivileged userns.
- reference: `CAP_NET_ADMIN`, Tor with SocksPort + TransPort + DNSPort
  listening (deployment prerequisite — `docs/enforcement.md` §5 step 1),
  and the BPF loader (lands with `probes/`).
- `resolv.conf` in `N2` still names a resolver that answers; the
  *enforcement* under test is the DNAT of port 53 to 10.187.0.1:5353,
  which the child ruleset applies regardless of resolv.conf contents.

## Build

```
make -C netns        # -Werror warning set, mirrors root Makefile
make -C netns check  # usage-contract smoke (exit 64), no state
```
