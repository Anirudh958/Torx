# TORX enforcement harness results

- generated: `2026-10-01T05:09:25Z`
- commit: `aebdf53`
- mode: `static`
- polarity: `enforcement`

| id | class | method | expected | observed | verdict | ci_gate |
|---|---|---|---|---|---|---|
| `boundary.up` | boundary | dynamic | up | **not_run** | UNTESTED | true |

Verdicts: `VERIFIED` matches expectation · `REFUTED` expectation broken · `UNTESTED` could not run (see notes) · `FLAKY` inconsistent.

`UNTESTED` is a claim of absence of test, never a claim of correctness.
Under enforcement polarity, `VERIFIED` means the boundary held.
