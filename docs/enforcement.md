# The enforcement primitive

`THREAT_MODEL.md` states the three properties — the wrapped application
cannot **disable** enforcement, cannot **blind** it on covered paths, and
cannot **signal** the observer — and names the row families that will test
them. This file specifies the mechanism that makes those properties hold,
and the mapping from each mechanism to its proof obligation. The *why* is
[`why-not-torsocks.md`](why-not-torsocks.md) §The correct primitive; this
is the how. The party that will prove the obligations below — from
where, with what evidence, under which polarity — is specified in
[`harness.md`](harness.md).

**Status: design contract for the unbuilt `netns/` tree — code last.**
Nothing here is measured yet. The row IDs cited below are the same targets
listed in `THREAT_MODEL.md` §3, and every one of them changes here first if
it changes at all.

## 1. The chokepoint: packets, not library calls

Every path from the wrapped process to a network — libc `connect`, raw
`syscall()`, a static binary, `io_uring` — converges on the same point: a
packet the kernel must route. Enforcement at the packet layer (netfilter)
therefore covers *by construction* every path that produces a packet;
enforcement at any layer above it covers only the paths that happen to
pass through that layer. This is the whole argument for leaving
`LD_PRELOAD` behind, and it is also why the coverage-completeness
obligation is answerable here: the set is "things that become packets,"
the classes that never do are named as non-goals (§7), and the claim is
scoped to exactly that boundary.

## 2. Topology

```
      host network namespace (trusted)
┌──────────────────────────────────────────────────────────┐
│  torx launcher            Tor daemon                     │
│  creates netns,           SocksPort 127.0.0.1:9050       │
│  installs rules,          TransPort 10.187.0.1:9040      │
│  verifies, then execs     DNSPort   10.187.0.1:5353      │
│                                                          │
│  observer ── reads BPF ringbuf (attached to child's      │
│              cgroup; fds CLOEXEC, owned here)            │
│                                                          │
│  veth-torx-h 10.187.0.1/30                               │
│  host backstop: from veth, accept only {9040, 5353};     │
│                 drop everything else                     │
└────────────────────┬─────────────────────────────────────┘
                     │ the only pipe out
┌────────────────────┴─────────────────────────────────────┐
│  child network namespace (untrusted)                     │
│  veth-torx-c 10.187.0.2/30, default route via 10.187.0.1 │
│                                                          │
│  nftables inet:  skip lo and the gateway;                │
│                  DNAT tcp      → 10.187.0.1:9040         │
│                  DNAT udp/53   → 10.187.0.1:5353         │
│                  filter: established/lo/gateway accept;  │
│                  drop the rest (udp-other, icmp, ip6)    │
│                                                          │
│  wrapped process: in the cgroup, with no CAP_NET_RAW,    │
│  no CAP_NET_ADMIN, no CAP_SYS_ADMIN, PR_SET_NO_NEW_PRIVS,│
│  PR_SET_DUMPABLE 0                                       │
└──────────────────────────────────────────────────────────┘
```

The launcher needs privilege once — to create the namespace, the veth, and
the rules — and the wrapped process gets none of it. That asymmetry is the
P1 proof obligation in physical form.

### 2.1 Two modes: reference and lab

The diagram above is **reference mode**: one privileged launch against the
real host, the child's only pipe landing on the host's own Tor. It stays
the canonical claim. But a boundary only root can build cannot be
*measured* on an unprivileged machine, and a claim that lives only where
nobody can run it is assertion, not evidence (`harness.md` §6.1). The
primitive therefore has exactly two modes, and the mode is recorded in
every evidence object the launcher produces:

| | reference mode | lab mode |
|---|---|---|
| trusted side | the host network namespace, as drawn above | a lab netns (N1) the launcher creates for itself — `unshare(CLONE_NEWUSER\|CLONE_NEWNET)`; the real host and its Tor stay outside the userns |
| privilege needed | `CAP_NET_ADMIN` in the host netns (root, once) | none — the userns grants `CAP_NET_ADMIN` over N1 and the child netns only |
| child netns · veth · child ruleset · backstop · caps drop · cgroup join | identical | identical |
| child → Tor | the path exists — the only pipe lands on TransPort/DNSPort | **no path exists** — N1 has no uplink to the host |
| claim scope | full: disable, coverage, backstop, sensor, agreement, and "traffic exits via Tor" | disable, coverage, backstop, signal — fully testable; every row whose pass condition needs either the sensor attach or real Tor egress records `UNTESTED (reason: …)` and never `VERIFIED` |

Selection is a measurement, not a preference: the launcher probes for the
capability it actually needs (`CAP_NET_ADMIN` in its own network
namespace) and takes reference mode only when that capability is held; a
forced `--mode=reference` without it aborts fail-closed, the same rule as
every other step in §5. Lab mode is the default on an unprivileged host
because it is the mode that can be run there — the child side (netns,
veth, addressing, `inet` nat+filter with DNAT and default drop, `nft
list`) is measured working unprivileged on the reference host
(`build-notes.md`, Phase-2 trial).

What lab mode does **not** do: it does not weaken child-side enforcement.
The child cannot tell N1 from the real host, because it can reach nothing
but N1 by construction; and it does not upgrade an `UNTESTED` into
anything else. Lab claims are lab claims, reference claims wait for a
privileged environment, and the seam between them is visible in evidence
rather than papered over.

## 3. Mechanisms, properties, proof obligations

| # | Mechanism | Placement | Carries | Proof obligation |
|---|---|---|---|---|
| 1 | netns + veth + default route | child | the only pipe exists — no other interface, no other route | `coverage.completeness.*` finds no alternate egress; `disable.exit_netns` — `setns` back to the host returns `EPERM` |
| 2 | nftables nat + filter (`inet`) | child | **P2** — DNAT the covered classes, drop the rest | `coverage.completeness.{tcp,dns,udp,ipv6,raw,io_uring}` — each row attempts an escape and passes only if blocked |
| 3 | backstop on the trusted side (`iif veth` accept `{9040,5353}`, else drop) | trusted side (host in reference mode, N1 in lab mode — §2.1) | an independent second stop: a child ruleset that is wrong, empty, or (hypothetically) removed still cannot become general egress | `backstop.*` — a test launch with the child ruleset deliberately empty must still end in `PACKET DROPPED`, never in success |
| 4 | cgroup-v2 BPF (connect hooks → ringbuf) | child's cgroup, owned by the trusted side; the **attach** itself needs init-ns capability (§5 step 6) | **P3** sensor: intent-level events for the observer, plus early denial | `signal.no_shared_fds`, `signal.observer_unreachable` (static rows); agreement rows — every BPF event and every netfilter verdict must be accounted for on both sides; in lab mode the agreement rows record `UNTESTED (reason:)` (§2.1), and the netfilter verdict carries the gate alone |
| 5 | capability drop + `NO_NEW_PRIVS` + `dumpable 0` | child at `exec` | **P1** — the kernel itself refuses removal attempts | `disable.nft_flush`, `disable.bpf_detach` — attempted from inside as the wrapped uid, each returns `EPERM` |
| 6 | Tor TransPort/DNSPort on the gateway address; per-invocation isolation token | trusted side (reference mode only for reachability — §2.1) | §4.2 (DNS), §4.3 (isolation) | `tests/isolation/` (planned) — two invocations never share a circuit; in lab mode every row with this pass condition records `UNTESTED (reason: lab mode: no path from N1 to the host's Tor)` |

## 4. Which layer carries the guarantee

The two enforcement layers fail differently, and the design says which one
is load-bearing:

- **cgroup BPF sees intent** — the `connect()` call, the process, the
  address before any rewrite. That makes it the sensor (the observer's
  feed) and a useful early deny. It sits on syscall paths, so its coverage
  is path-dependent: whether every path reaches its hook is a *measured*
  question (`coverage.completeness.io_uring`), never an assumed one.
- **netfilter sees the product** — the packet, after any syscall-level
  games. `io_uring`, raw syscalls, static binaries: all of them still emit
  packets through the same stack. This layer carries the guarantee.

Failure decomposition follows: a BPF attach that fails is caught before
`exec` and aborts the launch (§5 step 6, per `THREAT_MODEL.md` §4.1 —
the declared lab-mode EPERM excepted, §2.1). A BPF hook that silently stops firing
is an *observation* gap — the netfilter verdict still holds, and the
agreement rows are what notice. A netfilter verdict that holds while no
BPF event appears is likewise an observation gap, not an escape. The two
layers check each other by construction, which is exactly the separation
the opening paragraph of `THREAT_MODEL.md` claims: the observer can be
wrong without the enforcer being wrong, and vice versa — each is legible
independently.

## 5. Fail-closed launch sequence

Order matters; this list is `THREAT_MODEL.md` §4.1's fail-closed made
concrete. Any step failing means teardown and a
non-zero exit — there is no degraded mode. The mode (§2.1) is fixed and
recorded before step 1; the steps are mode-independent except step 2
(which side exists to hold the trusted position) and step 6 (which layer
the mode claims).

1. Probe Tor: SocksPort, TransPort, DNSPort answer from the host. No
   answer → abort.
2. Prepare the trusted side — reference mode: the host netns already
   exists and needs nothing; lab mode: `unshare(CLONE_NEWUSER|CLONE_NEWNET)`
   for N1. Then create the child's netns; create the veth pair; address
   both ends; install the child's default route via the gateway.
3. Install the child nftables rules (nat + filter, default drop).
4. Install the backstop on the trusted side (host netns in reference
   mode, N1 in lab mode).
5. Verify both rulesets are present and active (`nft list`, non-empty
   chains — a rule that is queued but not applied counts as absent).
6. Create the child cgroup and attach the BPF programs. In reference
   mode an attach error is an abort, not a warning. In lab mode the
   attach is *attempted* and its result recorded as evidence: this host
   measures `EPERM` for `bpf()` even as userns root
   (`kernel.unprivileged_bpf_disabled=2`, `build-notes.md`), and that
   EPERM is the mode's declared scope boundary (§2.1 — sensor rows
   `UNTESTED`, agreement rows degrade, netfilter carries the gate), not
   a failure. Any attach error *other than* the scope-declared EPERM is
   an abort in either mode.
7. `fork`; the child enters the netns, joins the cgroup, drops to the
   invoking uid, clears all capabilities, sets `PR_SET_NO_NEW_PRIVS` and
   `PR_SET_DUMPABLE 0`.
8. Start (or hand the ringbuf fd to) the host-side observer — fd is
   `CLOEXEC`, never enters the child.
9. `exec` the target.

Steps 1–8 happen without a wrapped process in existence. A failure cannot
leave a half-enforced process running, because there is not yet a process
to half-enforce.

Lab mode's one degradation is claim scope, never mechanism: steps 1–5
and 7–9 run identically and fail-closed, the child-side enforcement is
byte-for-byte the reference ruleset, and every row whose pass condition
sits outside lab mode's scope (§2.1) records `UNTESTED (reason: …)` with
the mode in its evidence — so a lab run can be green without ever being
read as a reference run.

## 6. Coverage enumeration — the P2 obligation, answered once

The harness rows in §3 are targets; this table is the design's answer to
"what is the set, and why is it complete?" each row later *measures* one
line rather than trusting it.

| Path class | What happens | Mechanism |
|---|---|---|
| TCP/IPv4 | DNAT → TransPort → Tor | nftables nat |
| TCP/IPv6 | dropped (`inet` family covers v6; blocked is a pass, per the Phase-1 `ipv6.passthrough` semantics) | nftables filter |
| DNS, UDP/53 | DNAT → DNSPort; the child's resolv.conf names the gateway, and the DNAT catches queries aimed anywhere else too | nftables nat + private resolv.conf |
| other UDP | dropped — no anonymous UDP claim is made (§6 non-guarantee) | nftables filter |
| ICMP / ICMPv6 | dropped | nftables filter |
| raw sockets / `AF_PACKET` | `EPERM` — `CAP_NET_RAW` was never granted | capabilities at `exec` |
| `io_uring` connect | the resulting packet still traverses netfilter; whether the BPF hook also fires is measured, not assumed | nftables (+ BPF agreement row) |
| static binaries | irrelevant — no libc dependency exists at the enforcement layer | design |
| `setns` to the host, new interfaces, rule changes, BPF detach | `EPERM` — `CAP_SYS_ADMIN` / `CAP_NET_ADMIN` / `CAP_BPF` absent | capabilities at `exec` |
| loopback and gateway traffic in the child netns | allowed — the child's own `lo` is not an egress, and its gateway address only reaches the two Tor ports | nftables skip rules + backstop |

Two classes of question this table deliberately leaves to measurement
rather than assertion: whether *every* syscall path reaches the BPF hook
(covered by the agreement rows), and how abstract `AF_UNIX` sockets are
scoped inside a netns (the harness measures it; path-based `AF_UNIX` is a
filesystem surface and is a named non-goal, §7).

## 7. What this primitive does not give us

The residue is stated here, not discovered later — `THREAT_MODEL.md` §6
holds the full list (traffic analysis, in-band deanonymization, root on
the host, a compromised Tor). Two entries belong specifically to this
design's boundary:

- **Path-based `AF_UNIX` and all filesystem surfaces.** Namespaces do not
  virtualize the file tree; a wrapped process that can reach `docker.sock`
  has an egress problem no nftables rule sees. Outside the network claim,
  named so it cannot masquerade as coverage.
- **Any path the enumeration in §6 could not close at measurement time.**
  That residue is a measured quantity — the rows that fail to close it —
  and it is what [`DETECTION.md`](../DETECTION.md) exists to document: the
  defender sees what the enforcement layer's coverage leaves visible.
