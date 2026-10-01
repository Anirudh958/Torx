# Probes

Host-side probes for the enforcement harness — the verdicts are
collected here, on the host, never inside the network namespace
([`docs/harness.md`](../../docs/harness.md) §1, three-party separation).

Layout requirement from §5: probes live beside the primitive
(`netns/`-adjacent), verdicts observed from outside it.

Empty by design: the first probes land with the launcher, in the §7
sequence (harness first — the IDs and evidence keys already have
somewhere to land in `run.sh` / `SCHEMA.md`).
