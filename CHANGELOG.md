# Changelog

All notable changes to TORX, newest first. Tags are annotated and their
messages carry the verification behind every "no verdict changes" claim.

## v0.1.1 — 2026-09-30

Four commits after `v0.1.0-legacy`; no verdict changes, no row additions
(verified: 18 rows both sides; `id`/`verdict`/`expected_verdict` triples
byte-identical, sha256 prefix `8b0f0147e57473da`).

- `d0ca760` — a null `*_observed` requires a sibling `*_reason`
  (SCHEMA rule + gate assertion in `run.sh` finalize, tested both
  directions; runs in CI via the push job's `--static` step). QUIC
  capture field renamed; its absence is stated as data.
- `944907a` — `docs/why-not-torsocks.md` academic section scoped to the
  wrapper class, not the LD_PRELOAD primitive.
- `332851c` — attribution rewrite (see "Repository history" below).
- `26407dc` — `CITATION.cff` gains `repository-code`.

## v0.1.0-legacy — 2026-09-30

The frozen LD_PRELOAD-thesis release: 18-row leak taxonomy (schema 2),
committed evidence harness, detection rules mapped to rows, MIT license,
CITATION, and the two-lineage comparison against torsocks. The shim is
legacy and intentionally unpatched; `THREAT_MODEL.md` holds the netns
Phase-2 thesis. See the tag message for the full inventory.

## Repository history — attribution rewrite (2026-09-30)

**What was wrong.** Every commit (and `CITATION.cff`) carried the email
`anirudh@users.noreply.github.com`, which belongs to a *different*
GitHub account (`anirudh`, display name "Anirudh C", id 10732).
GitHub attributes commits by email, so the contributors graph credited
all 19 commits to that stranger.

**What was done.** Author and committer email on every commit was
rewritten to `179838340+Anirudh958@users.noreply.github.com` (the
id-based noreply for `Anirudh958`). Trees were preserved verbatim —
only the commit envelopes changed — so every content hash comparison
below is exact. The rewrite commit is `332851c`.

**Old → new commit map.** Pre-rewrite hashes are dead; any external
reference to them should be translated through this table:

| pre-rewrite | post-rewrite |
|---|---|
| `f0299ce` | `1ef3a71` |
| `4dbf372` | `a5f0aee` |
| `07974ae` | `4f95d49` |
| `44212a7` | `ccff980` |
| `cd28286` | `a13a0ba` |
| `edafe0e` | `a93390a` |
| `d7d1b6f` | `2173b24` |
| `e0955a1` | `0b80af5` |
| `91da491` | `f4d03ea` |
| `c667572` | `fd31e8b` |
| `98e3932` | `c3378d7` |
| `9943efc` | `174d08b` |
| `cae0e7d` | `d0e094d` |
| `5697517` | `03c57ac` |
| `5f98196` | `25ac20b` |
| `5829dc4` | `184dbf5` |
| `96ad05e` | `6b5e344` |
| `4f3b01e` | `d0ca760` |
| `58d7342` | `944907a` |

In-repo references were remapped in the same commit: `results.jsonl`
`_meta.commit` and `results.md` point at `d0e094d` (the identical-tree
successor of `cae0e7d`, the commit the harness ran against). The
`v0.1.0-legacy` tag was recreated on `6b5e344` with its original
message and original tagger date.

**Why the graph can disagree with the commits.** GitHub's contributors
graph and `/stats/contributors` are lazily recomputed caches; they can
lag the pushed truth for hours. Ground truth is the commit metadata
(`GET /repos/.../commits` shows every commit linked to `Anirudh958`),
not the cached graph.

## Policy: recording a history rewrite

Any future history rewrite must, in the same change:

1. explain the *why* in the rewrite commit message;
2. publish the old→new hash map here (table above is the precedent);
3. re-verify affected claims against the diff (row counts, verdict
   triples) and say *how* they were verified, in the tag message;
4. retarget in-repo hash references (`_meta.commit`, prose citations)
   and state which pointers were remapped;
5. never force-update a tag that has been pushed — recreate forward.

The pattern this project exists to demonstrate, applied to itself: a
value that looks plausible but belongs to someone else (a noreply
address, an unexamined `_meta` field) is exactly where silent bugs
hide — so the check is *whose* value it is, not whether the format
parses.
