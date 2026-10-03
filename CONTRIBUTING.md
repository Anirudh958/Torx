# Contributing

## Required before every commit

1. **Run the checks that cover what you changed.** `make check` and
   `make -C netns check` for anything under `src/` or `netns/`;
   `./tests/leak/run.sh --static` and `./tests/enforce/run.sh --static`
   for harness changes; the full battery for row or mode changes (see
   each harness's README). A docs-only change still re-runs the
   static harness — hermeticity claims are tested by exercising them,
   and "docs-only, it can't affect the harness" is the shortcut that
   hides exactly the case no gate checks: a doc that no longer
   matches the rows it claims to summarize. No harness scans docs
   against results; this habit is the defense.
2. **Read the diff, not the file.** The file is the intended state; the
   diff is the change. Bugs live in the delta between them — a forced
   line break, an eaten blank line, a table row that an edit dropped.
   This step is required, not a habit; it has caught real defects that
   the edit itself did not intend.
3. **Fix by adding a commit, never amending.** Corrections are logged,
   not rewritten: a wrong landing gets a follow-up commit whose message
   names what it corrects. The reason is the artifact's thesis, not
   style — the corrections *are* the record of what was wrong and when,
   and `git commit --amend` plus a force-push deletes the append-only
   evidence trail the method rests on.

## Commit messages

- Prefix by surface: `build:`, `feat(torx):`, `test(enforce):`,
  `docs:`, `chore:`.
- Verb-first subject, why-body. The body says what the change claims
  and what it does not.

## Push and verify

- Push over SSH: `git push git@github.com:Anirudh958/Torx.git main`
  (https push does not authenticate).
- After a push, `git fetch` before trusting any ahead/behind
  indicator: the tracking ref updates on fetch, not on push, so a
  stale "ahead" can hide a real sync state. Verify the state, don't
  infer it.
- Verify CI against the **full** sha, never the abbreviation — an
  ambiguous reference is exactly the failure this check exists to
  prevent, and it recurs.
- Row or evidence changes: commit regenerated `results.jsonl` /
  `results.md` together with the doc or code change that produced them
  (see `tests/enforce/README.md`, "Adding a row").
