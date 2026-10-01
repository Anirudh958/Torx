# The observer harness

`THREAT_MODEL.md` §3 states the properties and names the row families;
[`enforcement.md`](enforcement.md) specifies the mechanism and maps each
mechanism to its proof obligation. This file specifies the third piece:
 **who proves it, from where, with what evidence** — and under what
polarity those proofs are readable. The *why* for the harness shape is
the opening argument here; the *why* for leaving `LD_PRELOAD` behind
stays in [`why-not-torsocks.md`](why-not-torsocks.md).

**Status: design contract. Code follows this document, same as
`enforcement.md` — primitive last (§7 sequence), harness before it.**
Nothing here is measured. Row IDs that change before the harness lands
change here first.

## 1. Three parties, two domains

Every run has exactly three parties:

- **the probe** — harness-controlled code *inside* the child namespace,
  attempting one escape (this is the escaping application, played by an
  instrument we own).
- **the boundary** — the primitive from `enforcement.md`: launcher,
  nftables, backstop, cgroup BPF, the capability drop. The system under
  test.
- **the observer** — harness code on the *host*, outside the child
  namespace, collecting evidence and writing the verdict.

The verdict must live outside the boundary's namespace, for two reasons
that are the same reason:

1. **An escape is visible only as a crossing.** The one thing worth
   knowing — did something get out — is a fact about the boundary's
   edge. The only party positioned at the edge is outside.
2. **A witness inside shares the failure modes of the thing it
   watches.** If the namespace is misconfigured (the case under test),
   an in-ns observer is blind with it, and would grade its own blindness
   a pass. This is not hypothetical: it is v0.1.0-legacy's failure in
   the P3 row — the enforcer's only input was the app's own control
   flow, so the app chose what got signaled (`shim_trace_count: 0`
   read as evidence, §3 P3 row). Evidence must come from surfaces the
   wrapped application cannot write: the boundary's own counters and
   verdicts, the probe's own experience, and Tor's answers. Never from
   a channel the subject controls.

The probe sits inside because it must — it is the escaping app. Probe
and observer are both harness code; the boundary is neither. The
separation discipline (`enforcement.md` §4) carries over: enforcement
and observation must not share a privilege domain or a failure mode, so
each side can be wrong without the other being wrong, and each is
legible independently.

## 2. Evidence: what the observer reads

| Source | Answers | Origin domain | Availability |
|---|---|---|---|
| probe exit status / errno | did the app's attempt *feel* successful? | probe (instrument) | always |
| nft JSON counters — child ruleset and host backstop, read as counters not as claimed verdicts | did a packet actually cross, drop, or DNAT? | boundary | read privilege open — §6 |
| BPF ringbuf fd, handed to the observer at launch, `CLOEXEC`, never entering the child (`enforcement.md` §5 step 8) | what did the process *intend* before any rewrite? | boundary's sensor | launcher contract |
| Tor TransPort/DNSPort answering on the gateway | does legitimate traffic still tunnel at all? | Tor (a third party — not the app, not the rules) | available — Tor already runs |
| `setns`/`nft flush`/BPF-detach errnos from inside | does tampering fail with `EPERM`? | kernel, via the probe | always |

Two families of rows read this table jointly: the **agreement rows**
(`enforcement.md` §3 mechanism 4) require every intent event and every
netfilter verdict to be accounted for on both sides — a BPF event with
no matching verdict or a verdict with no matching event is an
observation gap, found by cross-reading two domains rather than trusting
either.

Degradation rule is unchanged from Phase 1 (`tests/leak/SCHEMA.md`): an
unavailable source is a `null` in `<name>_observed` plus a sibling
`<name>_reason` naming what was missing, and the row degrades to
`UNTESTED`. No source's absence ever becomes a green or a red claim.

## 3. Row families — targets, not measurements

The union of `THREAT_MODEL.md` §3's planned families and
`enforcement.md` §3's per-mechanism obligations. The harness that lands
becomes the one authority; until then this table is it.

| Family | IDs | Green means | Property |
|---|---|---|---|
| `disable.*` | `nft_flush`, `bpf_detach`, `exit_netns` | each attempt from inside, as the wrapped uid, returns `EPERM` | P1 |
| `coverage.completeness.*` | `tcp`, `dns`, `udp`, `ipv6`, `raw`, `io_uring`, `unix` | **the escape attempt was blocked** — inverted: pass = failure of the escape | P2 |
| `backstop.*` | e.g. `empty_child_ruleset` | with the child's ruleset deliberately emptied, traffic still ends `PACKET DROPPED`, never success | P2's independent second stop |
| `signal.*` | `no_shared_fds`, `observer_unreachable` + the structural statics | the structural fact holds (no smuggled fd, no path from wrapped uid to the observer) | P3 |
| `agreement.*` | intent↔verdict pairing rows | every event is accounted on both sides | P3/P2 observation integrity |
| `control.*` | one positive row per covered class where a legitimate path exists | traffic aimed *through* the boundary still reaches Tor | harness integrity — see below |

`coverage.completeness.unix` is `enforcement.md` §6's open question —
how abstract `AF_UNIX` sockets are scoped inside a netns — as a row
rather than a footnote; the measurement resolves it or records it as
residue.

**`control.*` is a new family**, not in `THREAT_MODEL.md` §3's planned
column: it back-propagates there when the harness lands. It exists
because the inverted rows have a blind spot of their own — a boundary
that drops *everything* passes every escape attempt. Each coverage row
that has a legitimate path needs its paired control showing the same
path class works when directed at Tor; green is then "blocked the
escape, carried the legitimate traffic," not merely "nothing got out."

`tests/isolation/` (`enforcement.md` §3 mechanism 6, §4.3) stays a
separate, later harness — circuit non-sharing is a different question
from egress.

## 4. Never silently green

- **The mode split is inherited.** `--static` rows assert structural
  facts (fds are `CLOEXEC`, no shared channel, capability bits as read
  from `/proc`) — no network, no namespace, gated on every CI run,
  exactly like Phase 1's static rows. `--dynamic` rows need a live
  boundary and degrade to `UNTESTED` with reasons when the environment
  cannot build one. Exit codes `0/1/2` keep their Phase-1 meanings.
- **`boundary.up` is the precondition row.** Dynamic mode starts by
  verifying the launcher completed §5's sequence (both rulesets
  present, attach verified). A launcher that aborts fail-closed leaves
  a reason, not a verdict — the run reports `UNTESTED (reason: launcher
  aborted at step N)` loudly, the way the dirty-tree note reports
  regeneration (`tests/leak/run.sh`): silence must be loud.
- **The gate protects verdicts; reasons protect honesty.** The
  expected-versus-observed, both-directions, `UNTESTED`-never-fails
  mechanics are copied unchanged from Phase 1 — they are the part that
  worked. What changes is only what `observed` *means* under
  enforcement polarity, which is why polarity is a required field
  rather than a convention.
- **Teardown is fail-closed too.** A crashed or interrupted run must
  not leave a half-enforced world (ruleset without capability drop,
  netns without rules): the harness tears down what it launched, and
  reports what it could not.

## 5. Files, schema, polarity

```
tests/enforce/
  run.sh           modes, polarity guard, observer loop, gate
  SCHEMA.md        the schema:1 row contract (links the seam below)
  probes/          the escape attempts, built into .build/
  results.jsonl    committed evidence
  results.md       rendered table
  README.md        usage, CI capability notes, environment degradation
```

The directory is named for the property it proves (`enforce`), not the
mechanism it drives (`netns`) — Phase 1 is `tests/leak`, and
`tests/isolation` follows the same convention. Row fields, gate
semantics, and the `null`+`_reason` rule carry over from
`tests/leak/SCHEMA.md`; what is new is `_meta`:

- `schema: 1` — a fresh contract, not Phase 1's schema 2 (the polarity
  field is born here, so this file starts at its own version 1).
- `_meta.polarity: "enforcement"` — **required.** The guard runs before
  the first probe and refuses a file that does not carry it:

  ```
  run.sh: tests/enforce/results.jsonl: _meta.polarity missing or unknown
          (got: <value-or-<absent>>)
          Phase-2 requires explicit polarity to interpret verdicts.
          Refusing to gate. See SCHEMA.md §polarity.
  ```

The seam definition — both polarities, both refusals — lives in
`tests/leak/SCHEMA.md` §polarity, where it was written first:
measurement files carry the field absent (schema 2 predates it, and
Phase 1's guard already refuses `"enforcement"` before its own first
probe). Neither harness can now merge, rewrite, or gate the other's
file, which is the only way verdicts stay interpretable across the
rewrite.

## 6. Open questions — measured, not asserted

Each of these is resolved by a measurement, and each resolution is
recorded where the evidence will live (a row's `evidence` object, or
`docs/build-notes.md` if it happens before the code does). None of them
may be answered by assumption in a document like this one.

1. **CI capability.** Can the runner build a boundary at all —
   unprivileged user namespaces, the `nft` binary, Tor? Measured by one
   throwaway workflow (or local `unshare` trial) before any CI wiring
   is written; until then CI wiring is deferred, not designed.
2. **Counter read privilege.** Whether the observer can read nft JSON
   counters without `CAP_NET_ADMIN` in the relevant namespace.
   Candidates, in order of preference: measure first (listing may be
   permitted where mutation is not); a launcher-produced counter
   snapshot file — acceptable as corroboration only, never as sole
   evidence, because the boundary reporting on itself is P3's original
   sin; degrade the agreement rows to `UNTESTED (reason:)` and let the
   probe-errno + Tor-control rows carry the dynamic gate.
3. **Abstract `AF_UNIX` scoping** — `enforcement.md` §6's open question,
   owned by `coverage.completeness.unix` once it can run.
4. **Unprivileged topology.** `enforcement.md` §2 draws the trusted
   side in the host network namespace (veth end, backstop, Tor all
   there), which needs `CAP_NET_ADMIN` in that namespace — root —
   while §6.1 asks whether *unprivileged* user namespaces suffice. The
   two are not compatible as written. Measured 2026-10-01 (recorded in
   `docs/build-notes.md`): the entire child side — netns, veth pair,
   addressing, default route, `inet` nat+filter with DNAT, default
   drop, `nft list` — builds inside `unshare -Urn` without privilege;
   but a veth end cannot be moved into the host netns without
   privilege there, so an unprivileged child has no path to the host's
   Tor. Resolution required before `netns/` is written: a privileged
   launch (root once, §2 exactly as drawn), a lab topology (trusted
   side = a second userns-owned netns; real-Tor rows degrade to
   `UNTESTED (reason:)` until a bridge exists), or a userspace bridge
   (slirp-style, fd-passed from the host phase). Whichever is chosen,
   §2 and §5 of `enforcement.md` change here first — not in code.

## 7. Non-goals

- **Packet capture as gate evidence.** No `CAP_NET_RAW` exists on the
  host or in CI (Phase 1 records the same absence), so pcap is ad-hoc
  debug, never a verdict input.
- **A verdict from inside the namespace, or from the wrapped
  application's own channel** — §1, and the P3 row that failed for
  exactly that reason.
- **Rows for path-based `AF_UNIX` / filesystem surfaces** — a named
  non-goal of the primitive (`enforcement.md` §7), inherited here.
- **Building the primitive.** This file, and the rows it defines, land
  before `netns/` code by sequence — harness first so the primitive is
  built to be proven, and so an ID or an evidence key has somewhere to
  be recorded the day it is first measured.
