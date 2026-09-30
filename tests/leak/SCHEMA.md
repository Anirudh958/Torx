# SCHEMA.md — the `results.jsonl` record contract

`tests/leak/results.jsonl` is a line-delimited JSON array. Line 1 is
always the `_meta` record; every other line is one row. The current
contract version is **`schema: 2`** (`_meta.schema`). Consumers should
read `_meta.results_schema_url` to find this file.

## Records

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable row id (`_meta` for line 1). Never renamed — ids are the cross-reference currency of `LIMITATIONS.md`, `THREAT_MODEL.md`, and `DETECTION.md`. |
| `class` | string | Leak/taxonomy class. Current vocabulary: `dns`, `tcp`, `udp`, `udp-correctness`, `ipv6`, `static`, `direct-syscall`, `elf`. |
| `description` | string | The invariant under test, phrased as a must/must-not. |
| `method` | string | How it was tested: `static` (no network) or `dynamic` (ran live; may be degraded to `UNTESTED`). |
| `expected` / `observed` | string | The invariant's expectation vs. what was actually measured. |
| `verdict` | enum | `VERIFIED` / `REFUTED` / `UNTESTED` / `FLAKY`. |
| `expected_verdict` | enum | The documented verdict. The gate passes iff `verdict == expected_verdict` **for both** directions (a surprise `VERIFIED` of a documented bug is a finding, not a pass). `UNTESTED` never fails the gate. |
| `ci_gate` | bool | Whether this row is allowed to fail CI. Static rows are always gated and are **never** degraded by partial runs. |
| `limitation_ref` | string | `LIMITATIONS.md#anchor` (or `n/a`) — every row resolves to a limitation section. |
| `evidence` | object | **Row-specific, not part of the versioned contract.** |
| `notes` | string | Why this row exists; cross-references to sibling rows. |

### `_meta` (line 1)

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Always `"_meta"`. Excluded from the gate, the markdown render, and the summary. |
| `schema` | int | Contract version (see below). |
| `generated` | string | UTC timestamp of the run. |
| `commit` | string | Short hash of the revision the run **executed** at (`nogit` outside a work tree). A committed file cannot contain the hash of its own commit — regenerate after verdict-affecting changes. |
| `mode` | string | `static` / `dynamic` / `both` — what this run covered. |
| `host` | string | `uname -srm` of the runner. |
| `tor_version` | string | `tor --version` first line, or `n/a`. |
| `results_schema_url` | string | Path to this file, relative to the repo root. *(added in schema 2)* |

## Versioning rules

- `schema` is bumped on **any change to the top-level record fields or
  the `_meta` fields**: adding, renaming, removing, or changing the
  meaning of a field. Version history:
  - **1** — initial committed contract (no `results_schema_url`).
  - **2** — adds `_meta.results_schema_url`.
- Keys **inside `evidence`** are row-specific measurements (e.g.
  `post_swap_send_rc`, `so_type`, `routed`). Adding or renaming them
  does **not** bump `schema`: parsers must treat `evidence` as opaque.
  Removing a row-specific evidence key also does not bump, but it does
  invalidate any prose that cites the key — search before you delete.
- Consumers must ignore unknown fields within their schema version, and
  must branch on `schema` before parsing any field whose meaning they
  could not witness.
- A row's `verdict` changing is **never** a schema event. It is a
  finding: see the regeneration policy in `tests/leak/README.md`
  (verdict diffs are reviewed; `_meta` may diff freely).

## Reading a file

```bash
head -1 results.jsonl | jq            # provenance + schema version
grep -v '"_meta"' results.jsonl \
  | jq -r '[.id,.class,.verdict,.limitation_ref]|@tsv'   # the table
```
