# Leak taxonomy harness

Empirical backing for the claims in `THREAT_MODEL.md` and `LIMITATIONS.md`.
One command, two committed artifacts:

```sh
make && ./tests/leak/run.sh     # results.jsonl + results.md
```

| file | audience |
|---|---|
| `results.jsonl` | machines, reviewers, `jq`, CI diffing — one record per line |
| `results.md` | humans, `LIMITATIONS.md`, slides — rendered table |

## Modes

```sh
./tests/leak/run.sh --static    # nm/readelf/ldd only: no network, no Tor
./tests/leak/run.sh --dynamic   # needs outbound IPv4 egress; Tor optional
./tests/leak/run.sh             # both
```

Exit codes: `0` all `ci_gate` rows match their documented verdict ·
`1` gate violation (a verdict drifted — fix the code or update
`LIMITATIONS.md` and `expected_verdict`) · `2` setup error (library or
probe build missing).

If the host has no egress, dynamic rows **degrade to `UNTESTED` and the run
still exits 0** — a dead CI runner is never mistaken for a real leak.

## The `TORX_PORT=1` trick

Every dynamic probe points the shim at a deliberately closed port, so the
outcome is observable without packet capture and without a working Tor:

- **intercepted** → the shim dials `127.0.0.1:1`, fails, and prints its
  `TORX_DEBUG` trace (`[TORX] routing connect()`)
- **bypassed** → the syscall never reached the shim, so the connection
  behaves normally and no trace appears

`routed:true|false` is therefore read from the shim's own mouth, not
inferred from an exit code.

## Schema

| field | meaning |
|---|---|
| `id` | stable identifier, used by the gate and for cross-referencing (`_meta` reserves the first line) |
| `class` | `tcp` `dns` `ipv6` `unix` `udp` `udp-correctness` `raw` `setuid` `static` `direct-syscall` `elf` |
| `method` | `static` (deterministic, CI-safe) or `dynamic` (needs egress) |
| `expected` / `observed` | what should happen vs. what did |
| `verdict` | `VERIFIED` · `REFUTED` · `UNTESTED (reason)` · `FLAKY` |
| `expected_verdict` | the **documented** state (see `LIMITATIONS.md`) |
| `ci_gate` | whether drift on this row fails the run |
| `limitation_ref` | pointer into `LIMITATIONS.md`, or `n/a` |
| `evidence` | structured JSON: tool, exit codes, trace flag, stderr excerpt |
| `notes` | human context, e.g. why a dynamic gate is impossible today |

Verdict meanings: `VERIFIED` observation matches expectation · `REFUTED`
expectation broken (the documented leak) · `UNTESTED` the test could not
run · `FLAKY` inconsistent across attempts.

**`UNTESTED` is a claim of absence of test, never a claim of correctness.**

### Class vocabulary

`udp` vs `udp-correctness` is a deliberate split: **anonymity** (payload can
never be routed — `udp.export.sendto`) vs **correctness** (the socket is
corrupted — `udp.connect_hijack`, `udp.fd_swap`). Different failures,
different remediation; a socktype check fixes only the second. Same rule
applies to every class: name what went wrong, not just where.

### `_meta` and the committed snapshot

The first line of `results.jsonl` is `_meta`, never a result:

```json
{"id":"_meta","schema":2,"generated":"…Z","commit":"…","mode":"both|static|dynamic","host":"…","tor_version":"…","results_schema_url":"tests/leak/SCHEMA.md"}
```

The full record contract — top-level fields, the `_meta` fields, and the
versioning rules for `schema` — lives in [`SCHEMA.md`](SCHEMA.md).
`schema` bumps only when that top-level contract changes; keys *inside*
`evidence` are row-specific measurements and never bump it.

`commit` is the revision the run **executed** at (a file cannot contain the
hash of the commit that contains it) — so `_meta` may legitimately diff on
regeneration; verdict diffs are never incidental. Policy: `results.jsonl` /
`results.md` are committed evidence; regenerate with a full run (no args)
in the same commit as any verdict-affecting change, and treat an unexplained
verdict diff in review as a finding. `_meta` is excluded from the markdown
render, the gate, and partial-run merge (merge matches other rows by `id`).

## The gate

`expected_verdict` is what `LIMITATIONS.md` currently claims. A `ci_gate`
row fails CI when observed differs — in **both** directions:

- a documented `VERIFIED` turning into `REFUTED` is a **regression**
- a documented `REFUTED` turning into `VERIFIED` means a leak was fixed
  and nobody wrote it down — the fix is not real until the doc moves

`UNTESTED` never fails the gate.

## Partial runs merge

`--static` or `--dynamic` alone merge their rows into `results.jsonl` by
`id`, so a PR's static run can never destroy previously recorded dynamic
evidence — and dynamic degradation never overwrites static rows. A full run
replaces everything (except a freshly rewritten `_meta`). Run with no
arguments before committing.

## Adding a row

1. Put the probe in `probes/` (or reuse the nm/readelf style from
   `run_static`) and build it in `build_probes`.
2. Call `record` with a stable `id`, the four verdict fields, and an
   `expected_verdict` equal to what `LIMITATIONS.md` says **today**.
3. Set `ci_gate=true` only if the row must never drift silently.
4. Reference a `LIMITATIONS.md` anchor.
5. Re-run and commit the regenerated `results.jsonl` / `results.md`
   together with the doc change.

## Requirements

`jq`, `cc`, `nm`/`readelf`/`ldd` (binutils), `ip`, `timeout`. No `strace`,
`nft`, `tcpdump`, or running Tor is required — dynamic DNS egress
observation is the one class that still needs `CAP_NET_RAW`, documented as
`UNTESTED` in `results.jsonl`.

Temporary build output lives in `.build/` (not committed).
