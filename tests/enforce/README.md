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

**Status (read before citing anything here).** The boundary primitive
(`netns/torx-launch`, [`docs/enforcement.md`](../../docs/enforcement.md)
§5) exists and builds; `boundary.up` runs it and is `VERIFIED` wherever
the host can stand the boundary up. The `signal.*` structural rows
(`--static`: source audits of `netns/torx-launch.c`) and the
`control.loopback` floor row (`--dynamic`, no boundary needed) have
landed. The remaining row families defined in `docs/harness.md` §3
(`disable.*`, `coverage.*`, `backstop.*`, `agreement.*`, paired
`control.*` positives) land the day each is first measured, under the §7
sequence: harness first, so an ID has somewhere to land — then the
primitive, then the probe. Nothing here is green by default; see §4 of
the harness doc.

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

`--static` is hermetic: it reads only committed files. If a future row
needs generated input, that input must be committed or the row must not
be `ci_gate: true`.

If the host cannot build a boundary, dynamic rows **degrade to
`UNTESTED (reason:)` and the run still exits 0** — a dead or
half-configured host is never mistaken for a working boundary
(`docs/harness.md` §2). The measured capability picture for this machine
is recorded in [`docs/build-notes.md`](../../docs/build-notes.md)
(Phase-2 capability trial): the child-side half builds unprivileged —
namespaces, veth, and nftables all work (`nft` lives at `/usr/sbin/nft`,
outside a normal user `PATH`). The topology question is resolved as two
modes, lab first ([`docs/enforcement.md`](../../docs/enforcement.md)
§2.1); lab mode's unreachable halves — sensor attach, child→Tor — are
scoped to `UNTESTED (reason:)` in their own rows when those rows land
(`docs/harness.md` §6, question 4).

## `control.loopback` — the floor row

Dynamic mode's first row (`docs/harness.md` §3/§4): a loopback TCP
connection with no boundary involved — enforcement is off by definition
there. Green is the observer recording legitimate traffic: the floor
every later "blocked" verdict is read against, so a coverage row's
"blocked" means "flowing was demonstrable," never merely "nothing got
out." Three outcomes, recorded before `boundary.up`: observed flow →
`VERIFIED`; test ran and the flow was not observed → `REFUTED`
(**gates** — a host where loopback is dead is a finding about the
observation path, not an environment to degrade away); `python3` or
`timeout` missing, or the script errored before connecting →
`UNTESTED` (evidence.reason names the missing piece; never gated).

## `signal.*` — the static structural rows

`--static` (`docs/harness.md` §4): source audits of
`netns/torx-launch.c`, no network, no namespace, no build — gated on
every CI run like Phase 1's static rows.

- `signal.no_shared_fds` — every `pipe2`/`socket`/`open` call site
  carries its CLOEXEC flag (one allowlisted stdio silencer:
  `open("/dev/null")` in `run_argv_quiet`), and the protocol channel
  carries `FD_CLOEXEC` at the exec point. Counted per call, not per
  line — line 1050 carries two `pipe2` calls, and a call that loses its
  flag must flip the row even where a neighbour still shows one.
- `signal.observer_unreachable` — zero listener/IPC surface: no `bind`,
  `listen`, `accept`, `AF_UNIX`, `mkfifo`, `shm_open`, `mmap`, or
  `socketpair`. The single `socket()` in the file is the outbound Tor
  port probe (client side, `SOCK_CLOEXEC`), recorded so a reader need
  not re-grep.

Both are P3's structural half (`THREAT_MODEL.md` §3): neither proves a
negative alone — none claims to; the design argument carries the claim,
the rows make it falsifiable. Source absent → `UNTESTED (reason:)`,
never a vacuous green.

## `boundary.up` — the precondition row

The floor row runs first; this is where the boundary-dependent rows
start (`docs/harness.md` §4). The row is the
launcher itself: `boundary_up()` builds `netns/torx-launch` if needed
(through `netns/Makefile`), runs it against `/bin/true`, and decides
from the launcher's report — `status == "ok"` is `VERIFIED`, with
`evidence` carrying the report summary (mode, target exit, all nine §5
steps) rather than a harness-side assertion about it. On any host that
cannot stand the boundary up, `observed=not_run`, `verdict=UNTESTED`,
and `evidence.reason` names **every** unmet prerequisite — or, when the
launcher itself aborts fail-closed, the abort step and reason read back
from its report — each measured at run time, never assumed. No other
boundary-dependent dynamic row means anything until this one is
`VERIFIED`.
`expected_verdict` is `VERIFIED`: on a host with prerequisites the row
must pass, and observed `UNTESTED` is skipped by the gate by
construction, so the documented expectation is never downgraded to
match an environment.

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

## `probes/` — planned shape (before the first probe)

Conventions fixed *before* the first `disable.*` probe lands, so the
rows implement the scoped claim (`docs/harness.md` §3):

- **Naming:** `probe_<name>.c` produces rows named `disable.<name>`
  (`probe_nft_flush.c` → `disable.nft_flush`).
- **Position and privilege:** the probe runs *inside* the namespace, as
  the wrapped uid, with the same capability set the wrapped process
  runs with — so a `REFUTED` means "an equivalent process could
  escape," and the recorded `capeff` / `cap_required` / `cap_gap`
  (harness §3) says exactly which capability made the difference.
- **Report path:** the probe returns its result via a file, a pipe, or
  its exit code — the mechanism is part of the child's IPC surface, the
  same surface `signal.no_shared_fds` audits: a fifth `pipe2` without
  `CLOEXEC` trips the static row, and the two rows catching each other
  is the design working.
- **Positive control:** a `disable.*` probe that only ever fails would
  pass trivially. Each probe carries a variant of the same code path
  *with* the capability that *does* succeed, so evidence shows both
  outcomes — otherwise the row is a claim about a probe that might be
  broken.
- **Polarity echo:** each row states its polarity locally (a
  `"polarity": "enforcement"` note in the evidence), not only through
  `_meta.polarity`: in these rows `VERIFIED` means *the property held*
  (the attempt was blocked) and `REFUTED` means *the escape succeeded*
  — the opposite reading from the leak tree. The disambiguation
  attaches to the verdict, the same principle as `*_reason`, so a
  reader who has only seen the leak tree is not misled.

## Requirements

`jq`. `--static` additionally needs `grep` only. `--dynamic`'s floor
row needs `python3` and `timeout` (missing → the floor records
`UNTESTED`, never a silent green); the boundary rows need the boundary
itself (`docs/enforcement.md` §5): user namespaces, `nft`, a
C compiler and `make` (to build `netns/torx-launch` if missing), Tor on
`127.0.0.1:9050` — missing pieces degrade the run to `UNTESTED`, they
never fail it.

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
