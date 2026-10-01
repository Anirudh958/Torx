# TORX enforcement harness results

- generated: `2026-10-01T19:57:32Z`
- commit: `216dbd5`
- mode: `both`
- polarity: `enforcement`

| id | class | method | expected | observed | verdict | ci_gate |
|---|---|---|---|---|---|---|
| `signal.no_shared_fds` | signal | static | all_cloexec | **all_cloexec** | VERIFIED | true |
| `signal.observer_unreachable` | signal | static | no_endpoint | **no_endpoint** | VERIFIED | true |
| `control.loopback` | control | dynamic | flows | **flows** | VERIFIED | true |
| `boundary.up` | boundary | dynamic | up | **up** | VERIFIED | true |

Verdicts: `VERIFIED` matches expectation · `REFUTED` expectation broken · `UNTESTED` could not run (see notes) · `FLAKY` inconsistent.

`UNTESTED` is a claim of absence of test, never a claim of correctness.
Under enforcement polarity, `VERIFIED` means the boundary held.
