# TORX enforcement harness results

- generated: `2026-10-01T09:54:24Z`
- commit: `5ddb54a`
- mode: `both`
- polarity: `enforcement`

| id | class | method | expected | observed | verdict | ci_gate |
|---|---|---|---|---|---|---|
| `boundary.up` | boundary | dynamic | up | **up** | VERIFIED | true |

Verdicts: `VERIFIED` matches expectation · `REFUTED` expectation broken · `UNTESTED` could not run (see notes) · `FLAKY` inconsistent.

`UNTESTED` is a claim of absence of test, never a claim of correctness.
Under enforcement polarity, `VERIFIED` means the boundary held.
