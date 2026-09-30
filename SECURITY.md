# SECURITY.md

This repository is a research artifact: **the documented leaks in
`LIMITATIONS.md` are the thesis, not bugs** — reporting "LD_PRELOAD
shim leaks DNS / hijacks UDP / bypasses on IPv6" restates what
`tests/leak/results.jsonl` already records, and is closed as such;
the intended remediation is not a patch to this tree but the Phase-2
netns/cgroup/nftables architecture described in `THREAT_MODEL.md` §7.
In-scope findings are therefore the things the evidence does *not*
already cover: a harness row whose verdict silently stops matching
reality, a build/CI integrity problem, a false-negative/false-positive
in the detection rules of `DETECTION.md`, or anything that makes the
artifact *more* dangerous than it claims to be (fail-open behaviour,
unreported bypasses, supply-chain tampering with the committed
evidence). Report those via a GitHub security advisory on this
repository; expect the finding to be triaged against a recorded row
first — if a row exists, the answer is a row update, not a patch.
