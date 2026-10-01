# Enforcement harness (Phase 2)

Observer for the Phase-2 boundary: netns + cgroup-BPF + nftables
([`docs/enforcement.md`](../../docs/enforcement.md)), verified from the
host side with a three-party separation
([`docs/harness.md`](../../docs/harness.md)). One command, two committed
artifacts:

```sh
./tests/enforce/run.sh           # results.jsonl + results.md
```

| file | audience |
|---|---|
| `results.jsonl` | machines, reviewers, `jq`, CI diffing — one record per line |
| `results.md` | humans, slides — rendered table |

**Scaffold status (read before citing anything here).** The primitive
does not exist yet (`netns/` is unwritten), so this harness currently
records exactly one row — the `boundary.up` precondition — and it is
`UNTESTED (reason:)` on any host that cannot build a boundary. Every
other row family defined in `docs/harness.md` §3 (`disable.*`,
`coverage.*`, `backstop.*`, `signal.*`, `agreement.*`, `control.*`) lands
the day it is first measured, under the §7 sequence: harness first, so
an ID has somewhere to land — then the primitive, then the probe.
Nothing here is green by default; see §4 of the harness doc.

## Modes

```sh
./tests/enforce/run.sh --static    # signal.* structural rows: no network, no namespace
./tests/enforce/run.sh --dynamic   # needs netns + nftables + a live boundary
./tests/enforce/run.sh             # both
```

Exit codes: `0` all `ci_gate` rows match their documented verdict ·
`1` gate violation (a verdict drifted — fix the code or update
`docs/harness.md` and `expected_verdict` — **or** an `*_observed` field
holds `null` without its sibling `*_reason`, see
[`SCHEMA.md`](SCHEMA.md)) · `2` setup error (jq missing).

If the host cannot build a boundary, dynamic rows **degrade to
`UNTESTED (reason:)` and the run still exits 0** — a dead or
half-configured host is never mistaken for a working boundary
(`docs/harness.md` §2). The current capability split for this machine is
recorded in [`docs/build-notes.md`](../../docs/build-notes.md) (Phase-2
capability trial): namespaces yes, `nft` no.

## `boundary.up` — the precondition row

Dynamic mode starts here (`docs/harness.md` §4). `observed=not_run` and
`verdict=UNTESTED` with `evidence.reason` naming **every** unmet
prerequisite, each measured at run time (netns tree, user namespaces,
`nft`, …), never assumed. No other dynamic row means anything until this
one is `VERIFIED`. It flips when the launcher completes
[`docs/enforcement.md` §5](../../docs/enforcement.md) and the harness is
wired to verify it — `expected_verdict` moves in the same commit
(stale-verdict policy below).

## Polarity: enforcement

This harness's rows answer *did the boundary hold*. Under enforcement
polarity, `VERIFIED` means **the boundary held** — the inverse of
`tests/leak`, where `REFUTED` is data about the shim under test.
`run.sh` refuses to gate any file whose `_meta.polarity` is not
`"enforcement"`; the refusal text, and the seam between the two
polarities, are specified in [`SCHEMA.md §polarity`](SCHEMA.md#polarity).

## The gate

`expected_verdict` is what `docs/harness.md` currently claims. A
`ci_gate` row fails CI when observed differs — in **both** directions:
a documented `VERIFIED` becoming `REFUTED` is a **regression**; a
documented `UNTESTED`/`REFUTED` becoming `VERIFIED` means the boundary
changed and nobody wrote it down. `UNTESTED` never fails the gate. The
second, independent assertion: `null` in an `*_observed` evidence field
must carry its `*_reason` sibling (`SCHEMA.md`).

`tests/leak`'s gate is copied unchanged (`tests/leak/run.sh`) — it is
the part that worked; what changes under enforcement is only what
`observed` means.

## Committed evidence

`commit` in `_meta` is the revision the run **executed** at (a file
cannot contain the hash of the commit that contains it), so `_meta` may
legitimately diff on regeneration; a verdict diff is a **finding**.
Policy: regenerate with a full run (no args) in the same commit as any
verdict-affecting change; treat an unexplained verdict diff in review as
a finding. Partial runs (`--static` / `--dynamic`) merge by `id` so a
PR's static run can never destroy previously recorded dynamic evidence —
and dynamic degradation never overwrites static rows. Run with no
arguments before committing.

Verdicts quoted in prose (`docs/harness.md`, root `README.md`) are
**copies** of `results.jsonl`; a stale verdict in prose with no matching
fresh row is a defect in the document, not evidence.

## Adding a row

1. Add the probe under `probes/` (or the launcher-adjacent checks in
   `run.sh`) per `docs/harness.md` §5's layout — probes live beside the
   primitive, verdicts collected host-side (§1).
2. Call `record` with a stable `id`, the four verdict fields, and an
   `expected_verdict` equal to what `docs/harness.md` says **today**.
3. Set `ci_gate=true` only if the row must never drift silently.
4. Reference the doc anchor that evidences the obligation (`limitation_ref`).
5. Re-run and commit the regenerated `results.jsonl` / `results.md`
   together with the doc change.

## Requirements

`jq`. `--static` needs nothing else. `--dynamic` additionally needs the
boundary itself (`docs/enforcement.md` §5): user namespaces, `nft`, the
`netns/` launcher, Tor on `127.0.0.1:9050` — missing pieces degrade the
run to `UNTESTED`, they never fail it.

Temporary build output lives in `.build/` (not committed).

## Layout

```
tests/enforce/
├── run.sh          modes, polarity guard, observer, gate
├── SCHEMA.md       record contract (schema 1), §polarity
├── README.md       this file
├── probes/         host-side probes (land with the primitive)
├── results.jsonl   committed evidence (bootstrap: first run)
└── results.md      rendered table
```
