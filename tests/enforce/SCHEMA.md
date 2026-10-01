# `tests/enforce` record contract (schema 1)

The machine-readable contract for `results.jsonl` in this directory.
Rendered sibling: [`results.md`](results.md). The *design* authority —
row families, degradation rules, observer separation — is
[`docs/harness.md`](../../docs/harness.md); this file only defines what a
line in the file may contain.

The leak harness's contract is [`tests/leak/SCHEMA.md`](../leak/SCHEMA.md)
(schema 2). The two files version independently; see the mirrored rules
below.

## Top-level row fields

| field | type | meaning |
|---|---|---|
| `id` | string | stable identifier, used by the gate and cross-referencing (`_meta` reserves the first line) |
| `class` | string | `boundary` `disable` `coverage` `backstop` `signal` `agreement` `control` — the families of [`docs/harness.md`](../../docs/harness.md) §3 |
| `description` | string | the invariant under test, phrased as a must / must-not |
| `method` | string | `static` (deterministic, CI-safe) or `dynamic` (needs a live boundary) |
| `expected` / `observed` | string | what should happen vs. what did — **interpretation depends on `polarity`** (below) |
| `verdict` | string | `VERIFIED` · `REFUTED` · `UNTESTED` · `FLAKY` |
| `expected_verdict` | string | the **documented** state: what `docs/harness.md` claims today |
| `ci_gate` | bool | whether drift on this row fails the run |
| `limitation_ref` | string | doc anchor that evidences the obligation (for `boundary.*`: `docs/enforcement.md` §5), or `n/a` |
| `evidence` | object | structured JSON; row-specific measurements, opaque to this contract |
| `notes` | string | human context: why a row is `UNTESTED`, what flips it |

`UNTESTED` rows carry the reason in `evidence.reason` (or an `*_reason`
sibling — the pairing rule below).

## `_meta` (first line, never a result)

| field | required | meaning |
|---|---|---|
| `id` | yes | always `"_meta"` |
| `schema` | yes | `1` — this contract |
| `polarity` | yes | `"enforcement"` — the refusal the gate enforces (below) |
| `generated` | yes | UTC timestamp of the run |
| `commit` | yes | revision the run **executed** at (may legitimately diff on regeneration) |
| `mode` | yes | `both` · `static` · `dynamic` |
| `host` / `tor_version` | yes | environment the run measured |
| `results_schema_url` | yes | `tests/enforce/SCHEMA.md` |

Example:

```json
{"id":"_meta","schema":1,"polarity":"enforcement","generated":"…Z","commit":"…","mode":"both","host":"…","tor_version":"…","results_schema_url":"tests/enforce/SCHEMA.md"}
```

## Polarity

**This file's polarity is `enforcement`.** A row here answers *did the
boundary hold* — `observed=up, verdict=VERIFIED` means the wall was up and
every probe agreed; `VERIFIED` under this polarity is the claim
**"the boundary held"**, not "the test passed".

`tests/leak/results.jsonl` runs the opposite polarity, `measurement`:
there, `REFUTED` is a documented property of the shim being measured.
Neither polarity is valid for the other's rows, so neither harness may
gate the other's file. The seam — both polarities, both refusals, and
why they live in [`tests/leak/SCHEMA.md §polarity`](../leak/SCHEMA.md#polarity)
where they were written first — is defined there; this file states the
half that applies here.

`run.sh` enforces it: before the first row is read, `_meta.polarity` must
equal `"enforcement"`. Anything else — absent, `"measurement"`, any
unknown string — is refused with the harness's fixed message (`got:` shows
the raw value or `<absent>`) and exit 1, untouched file. The check is
first because finalize would rewrite `_meta`: gating a foreign file would
destroy the very field that identifies it.

## `*_observed` / `*_reason` pairing

Any `evidence` key ending `_observed` whose value is `null` must carry a
sibling `_reason` (same key with `_reason` suffix) explaining why the
observation is absent. `null` alone could be read as "zero" or as "not
checked" — both wrong. `run.sh` gates this independently of verdicts.

## Versioning

- `schema` bumps **only** when a top-level field is added, removed, or
  changes meaning. Keys *inside* `evidence` are row-specific
  measurements and never bump it.
- History: `1` — initial contract, born with `polarity`.
- Adding a `class` value (a new §3 family row landing) is not a schema
  bump; changing what a class *means* is.

## Corrections

A verdict diff in review is a **finding**, never incidental. When a row
is corrected, the change lands in the same commit as the doc that
re-quotes it (`docs/harness.md`, `LIMITATIONS.md`, `README.md`), with the
regenerated `results.jsonl` / `results.md` — stale verdicts in prose with
no matching fresh row are a defect in the document, not evidence.
