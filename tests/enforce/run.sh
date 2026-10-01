#!/usr/bin/env bash
# tests/enforce/run.sh — TORX boundary enforcement harness (Phase 2)
#
# Emits two artifacts, both committed:
#   tests/enforce/results.jsonl   machine-readable, grep/diff-able by reviewers
#   tests/enforce/results.md      rendered table, for docs + slides
#
# Polarity: ENFORCEMENT. Rows assert that the boundary held — green means
# every escape attempt was blocked. That is the inverse of tests/leak
# (measurement polarity, where REFUTED is data about the shim under test).
# The guard below refuses any file whose _meta does not carry
# polarity:"enforcement" BEFORE the first row is read: finalize rewrites
# _meta and merges by id, so gating a foreign file would not just misread
# its verdicts, it would destroy the field that identifies them. Both
# polarities, both refusals — the seam — live in tests/leak/SCHEMA.md
# §polarity, where they were written first.
#
# Modes:
#   --static    structural rows about the launcher (signal.* family): source
#               audits of netns/torx-launch.c — no network, no namespace, no
#               build — gated on every CI run, exactly like Phase 1's static
#               rows.
#   --dynamic   starts with the control.loopback floor row (no boundary
#               needed: enforcement is off, so a loopback connection must be
#               observable as succeeding), then the boundary.up precondition
#               row — the launcher itself, run against /bin/true and
#               verified from its report — and degrades to UNTESTED
#               (reason:) when the environment cannot build one.
#   (none)      both.
#
# Exit codes:
#   0  every ci_gate row matches its expected_verdict
#   1  gate violation: a documented verdict changed (fix or regression)
#   2  setup error (jq missing, probe failed to build)
#
# The gate is copied unchanged from tests/leak/run.sh — expected versus
# observed in BOTH directions, UNTESTED never fails — because it is the
# part that worked (docs/harness.md §4). What changes under enforcement is
# only what `observed` means, which is why polarity is required rather
# than conventional.
set -uo pipefail

MODE=both
for arg in "$@"; do
    case "$arg" in
        --static)  MODE=static ;;
        --dynamic) MODE=dynamic ;;
        -h|--help) printf 'usage: %s [--static|--dynamic]\n' "$0"; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
BUILD="$HERE/.build"
JSONL="$HERE/results.jsonl"
MARKDOWN="$HERE/results.md"

command -v jq >/dev/null 2>&1 || { printf 'setup: jq missing\n' >&2; exit 2; }

# ---------------------------------------------------------------------------
# Polarity guard (SCHEMA.md §polarity)
# ---------------------------------------------------------------------------
# Enforcement polarity: a file that does not carry polarity:"enforcement"
# is either another harness's file (measurement) or malformed — in both
# cases a verdict in it is unreadable here. Refuse before the first row,
# before finalize can rewrite _meta away. Absent, "measurement", and any
# unknown value are all refused with the same message: the got: line says
# which case, the refusal does not negotiate.
if [ -f "$JSONL" ]; then
    polarity=$(jq -r 'select(.id == "_meta") | .polarity // empty' "$JSONL" 2>/dev/null | head -n1)
    if [ "$polarity" != "enforcement" ]; then
        printf 'run.sh: %s: _meta.polarity missing or unknown\n' "${JSONL#"$ROOT"/}" >&2
        printf '        (got: %s)\n' "${polarity:-<absent>}" >&2
        printf '        Phase-2 requires explicit polarity to interpret verdicts.\n' >&2
        printf '        Refusing to gate. See SCHEMA.md §polarity.\n' >&2
        exit 1
    fi
fi

mkdir -p "$BUILD"
RECORDS=()

# ---------------------------------------------------------------------------
# record <id> <class> <description> <method> <expected> <observed> <verdict>
#        <evidence_json> <ci_gate> <limitation_ref> <notes> [expected_verdict]
# ---------------------------------------------------------------------------
record() {
    local id="$1" class="$2" desc="$3" method="$4" expected="$5"
    local observed="$6" verdict="$7" evd="$8" cigate="$9" lref="${10}" notes="${11}"
    local expected_verdict="${12:-$verdict}"

    RECORDS+=("$(jq -cn \
        --arg id "$id" --arg class "$class" --arg description "$desc" \
        --arg method "$method" --arg expected "$expected" \
        --arg observed "$observed" --arg verdict "$verdict" \
        --arg expected_verdict "$expected_verdict" \
        --argjson ci_gate "$cigate" --arg limitation_ref "$lref" \
        --argjson evidence "$evd" --arg notes "$notes" \
        '{id:$id, class:$class, description:$description, method:$method,
          expected:$expected, observed:$observed, verdict:$verdict,
          expected_verdict:$expected_verdict, ci_gate:$ci_gate,
          limitation_ref:$limitation_ref, evidence:$evidence, notes:$notes}')")
}

verdict_for() { [ "$1" = "$2" ] && printf 'VERIFIED' || printf 'REFUTED'; }

# ---------------------------------------------------------------------------
# Static mode: structural facts about the launcher — no network, no
# namespace, no build, gated on every CI run (docs/harness.md §4, the
# signal.* family). They read the source the boundary is made of, so they
# hold wherever the repo is checked out: a runner that cannot build a
# boundary (docs/harness.md §6 Q1, measured 2026-10-02) still gates them.
# ---------------------------------------------------------------------------
# count_re <regex> <file> — call-site counts, not line counts: line 1050
# carries two pipe2 calls, and a call that loses its CLOEXEC flag must
# flip the row even when its line still shows a neighbour's flag. The
# (^|[^[:alnum:]_]) prefix excludes fopen( when counting open(; the
# [^)]* flag match assumes one call per line — true today, and a refactor
# that splits one flips the row, forcing the count to be re-read with it.
count_re() { grep -oE "$1" "$2" 2>/dev/null | wc -l | tr -d ' '; }

run_static() {
    local src="$ROOT/netns/torx-launch.c"
    local desc_fds="every fd the launcher creates must be CLOEXEC (one documented stdio silencer excepted), and the protocol channel must carry FD_CLOEXEC at the exec point — nothing but stdio is inherited by the target"
    local desc_obs="the launcher must open no listening socket, AF_UNIX endpoint, FIFO, or shared mapping — no channel a wrapped-uid process could reach an observer through"
    local notes_fds="P3 structural row (THREAT_MODEL.md §3): source audit, no build or boundary needed, so a CI runner that cannot build one still gates it (docs/harness.md §6 Q1). fopen_total is context, not a pass condition — three sites are parent-side (report, cgroup reads) and the child's uid_map fopen is fclosed on every path before execvp (uid_ok); the pass condition is the fd-creation sites plus the exec-point fcntl. A new fd-creating site without CLOEXEC flips observed, which is the falsifier."
    local notes_obs="P3 structural row (THREAT_MODEL.md §3), launcher side only: docs/harness.md §3 — none of the signal rows proves a negative alone, the design argument carries the claim. Measured is the absence of listener/IPC surface in the launcher itself; the observer side lands with probes/. socket_client_calls is the outbound Tor port probe (SOCK_CLOEXEC, client side), recorded so a reader need not re-grep. Any new endpoint site flips observed, which is the falsifier."
    if [ ! -f "$src" ]; then
        record "signal.no_shared_fds" "signal" "$desc_fds" \
            "static" "all_cloexec" "not_run" "UNTESTED" \
            "$(jq -cn --arg r "netns/torx-launch.c absent" '{reason:$r}')" \
            "true" "THREAT_MODEL.md#3-adversaries" \
            "$notes_fds" "VERIFIED"
        record "signal.observer_unreachable" "signal" "$desc_obs" \
            "static" "no_endpoint" "not_run" "UNTESTED" \
            "$(jq -cn --arg r "netns/torx-launch.c absent" '{reason:$r}')" \
            "true" "THREAT_MODEL.md#3-adversaries" \
            "$notes_obs" "VERIFIED"
        return
    fi
    # no_shared_fds: every pipe2/socket/open call carries its CLOEXEC flag,
    # except the run_argv_quiet /dev/null silencer (dup2 onto stdio, fd
    # closed before exec), plus the explicit FD_CLOEXEC on the protocol
    # channel at child_main's exec point.
    local p2 p2x sk skx op opx dn ec fo bad obs_fds
    p2=$(count_re '(^|[^[:alnum:]_])pipe2\(' "$src")
    p2x=$(count_re 'pipe2\([^)]*O_CLOEXEC' "$src")
    sk=$(count_re '(^|[^[:alnum:]_])socket\(' "$src")
    skx=$(count_re '(^|[^[:alnum:]_])socket\([^)]*SOCK_CLOEXEC' "$src")
    op=$(count_re '(^|[^[:alnum:]_])open\(' "$src")
    opx=$(count_re '(^|[^[:alnum:]_])open\([^)]*O_CLOEXEC' "$src")
    dn=$(count_re '(^|[^[:alnum:]_])open\("/dev/null"' "$src")
    ec=$(count_re 'fcntl\([^)]*F_SETFD, FD_CLOEXEC\)' "$src")
    fo=$(count_re '(^|[^[:alnum:]_])fopen\(' "$src")
    bad=$(( (p2 - p2x) + (sk - skx) + (op - opx - dn) ))
    obs_fds="all_cloexec"
    [ "$bad" -gt 0 ] && obs_fds="site_without_cloexec"
    record "signal.no_shared_fds" "signal" "$desc_fds" \
        "static" "all_cloexec" "$obs_fds" "$(verdict_for all_cloexec "$obs_fds")" \
        "$(jq -cn \
            --arg tool "per-call grep of netns/torx-launch.c" \
            --arg allowlist 'open("/dev/null") in run_argv_quiet: dup2 onto stdio, fd closed before exec' \
            --argjson pipe2_total "$p2" --argjson pipe2_cloexec "$p2x" \
            --argjson socket_total "$sk" --argjson socket_cloexec "$skx" \
            --argjson open_total "$op" --argjson open_cloexec "$opx" \
            --argjson allowlisted_matches "$dn" \
            --argjson exec_point_fcntl_fd_cloexec "$ec" \
            --argjson fopen_total "$fo" \
            '{tool:$tool, pipe2_total:$pipe2_total, pipe2_cloexec:$pipe2_cloexec,
              socket_total:$socket_total, socket_cloexec:$socket_cloexec,
              open_total:$open_total, open_cloexec:$open_cloexec,
              allowlist:$allowlist, allowlisted_matches:$allowlisted_matches,
              exec_point_fcntl_fd_cloexec:$exec_point_fcntl_fd_cloexec,
              fopen_total:$fopen_total}')" \
        "true" "THREAT_MODEL.md#3-adversaries" \
        "$notes_fds" "VERIFIED"
    # observer_unreachable: zero listener/IPC surface — bind, listen,
    # accept, AF_UNIX, FIFO, shared memory, socketpair — in the launcher.
    local bind listen acc afunix fifo shm mmap_ pair cli ep
    bind=$(count_re '(^|[^[:alnum:]_])bind\(' "$src")
    listen=$(count_re '(^|[^[:alnum:]_])listen\(' "$src")
    acc=$(count_re 'accept4?\(' "$src")
    afunix=$(count_re 'AF_UNIX|AF_LOCAL' "$src")
    fifo=$(count_re 'mkfifo' "$src")
    shm=$(count_re 'shm_open' "$src")
    mmap_=$(count_re '(^|[^[:alnum:]_])mmap\(' "$src")
    pair=$(count_re 'socketpair\(' "$src")
    cli=$(count_re '(^|[^[:alnum:]_])socket\(' "$src")
    ep=$(( bind + listen + acc + afunix + fifo + shm + mmap_ + pair ))
    local obs_ep="no_endpoint"
    [ "$ep" -gt 0 ] && obs_ep="endpoint_present"
    record "signal.observer_unreachable" "signal" "$desc_obs" \
        "static" "no_endpoint" "$obs_ep" "$(verdict_for no_endpoint "$obs_ep")" \
        "$(jq -cn \
            --arg tool "grep of netns/torx-launch.c for listener/IPC surface" \
            --arg socket_client_note "the socket() is the outbound Tor port probe (SOCK_CLOEXEC, client side)" \
            --argjson bind_calls "$bind" --argjson listen_calls "$listen" \
            --argjson accept_calls "$acc" --argjson af_unix_refs "$afunix" \
            --argjson mkfifo_calls "$fifo" --argjson shm_open_calls "$shm" \
            --argjson mmap_calls "$mmap_" --argjson socketpair_calls "$pair" \
            --argjson socket_client_calls "$cli" \
            '{tool:$tool, bind_calls:$bind_calls, listen_calls:$listen_calls,
              accept_calls:$accept_calls, af_unix_refs:$af_unix_refs,
              mkfifo_calls:$mkfifo_calls, shm_open_calls:$shm_open_calls,
              mmap_calls:$mmap_calls, socketpair_calls:$socketpair_calls,
              socket_client_calls:$socket_client_calls,
              socket_client_note:$socket_client_note}')" \
        "true" "THREAT_MODEL.md#3-adversaries" \
        "$notes_obs" "VERIFIED"
}

# ---------------------------------------------------------------------------
# Dynamic mode
# ---------------------------------------------------------------------------
# boundary_up — the precondition row (docs/harness.md §4). Returns 0 only
# once the launcher has completed docs/enforcement.md §5's sequence (both
# rulesets present, attach verified). Otherwise BOUNDARY_REASON names
# every unmet prerequisite, each one *measured at run time* — the reason
# is evidence, not prose. A launcher that aborts fail-closed reports
# UNTESTED (reason: launcher aborted at step N), never green.

# nft lives outside a normal user PATH on Debian-derivatives
# (/usr/sbin) — a `command -v nft` alone once misreported this host as
# lacking nftables. Search both, because "not in PATH" is not "absent".
have_nft() {
    command -v nft >/dev/null 2>&1 && return 0
    local p
    for p in /usr/sbin /sbin; do
        [ -x "$p/nft" ] && return 0
    done
    return 1
}

# BOUNDARY_EVIDENCE: on success, the launcher report's summary, used
# verbatim as the row's evidence (mode, target exit, the nine §5 steps);
# on failure it stays empty and BOUNDARY_REASON names the abort step —
# read from the report when the launcher wrote one, because a
# fail-closed abort is evidence, not prose.
BOUNDARY_REASON=""
BOUNDARY_EVIDENCE=""
boundary_up() {
    local missing=() rc=0
    [ -d "$ROOT/netns" ] || missing+=("netns/ tree absent (docs/enforcement.md §5 unimplemented)")
    if ! command -v unshare >/dev/null 2>&1; then
        missing+=("unshare binary not found in PATH")
    elif ! unshare -Urn true 2>/dev/null; then
        missing+=("unprivileged user namespaces unavailable (kernel.unprivileged_userns_clone?)")
    fi
    have_nft || missing+=("nft binary not found (PATH, /usr/sbin, /sbin)")
    if [ "${#missing[@]}" -gt 0 ]; then
        BOUNDARY_REASON=$(printf '%s; ' "${missing[@]}")
        BOUNDARY_REASON=${BOUNDARY_REASON%; }
        return 1
    fi
    # Build the launcher through netns/Makefile (the canonical build —
    # -Werror warning set, README.md); reuse an existing binary, like
    # tests/leak's probes, so a rebuild only happens when needed.
    if [ ! -x "$ROOT/netns/torx-launch" ]; then
        if ! command -v make >/dev/null 2>&1; then
            BOUNDARY_REASON="make not found (cannot build netns/torx-launch)"
            return 1
        fi
        if ! make -C "$ROOT/netns" >"$BUILD/launcher.build.log" 2>&1; then
            BOUNDARY_REASON="netns/torx-launch build failed (see tests/enforce/.build/launcher.build.log)"
            return 1
        fi
    fi
    # Launch docs/enforcement.md §5 with the harness's own target. The
    # exit code alone is not the verdict — a target that itself exits
    # non-zero completed §5 — so the report's status field decides.
    timeout 30 "$ROOT/netns/torx-launch" \
        --report "$BUILD/boundary-report.json" -- /bin/true \
        >"$BUILD/launcher.out" 2>"$BUILD/launcher.err" || rc=$?
    if [ "$rc" -eq 0 ] && [ -s "$BUILD/boundary-report.json" ] &&
        jq -e '.status == "ok"' "$BUILD/boundary-report.json" >/dev/null 2>&1; then
        BOUNDARY_EVIDENCE=$(jq -c \
            '{launch:"completed",mode,mode_reason,target_exit,sensor,cgroup,steps}' \
            "$BUILD/boundary-report.json")
        return 0
    fi
    if [ -s "$BUILD/boundary-report.json" ] &&
        jq -e . "$BUILD/boundary-report.json" >/dev/null 2>&1; then
        BOUNDARY_REASON=$(jq -r \
            '"launcher aborted at step \(.step // "unknown"): \(.reason // "no reason recorded")"' \
            "$BUILD/boundary-report.json")
    else
        BOUNDARY_REASON="launcher exited rc=$rc without a report (see tests/enforce/.build/launcher.err)"
    fi
    return 1
}

# control_loopback — the floor row (docs/harness.md §3/§4). A loopback
# TCP connection with no boundary involved: if the observer cannot record
# "traffic flowed" before enforcement is engaged, a later "blocked" from
# any inverted row is indistinguishable from a dead observer. Returns 0
# when the flow was observed. Otherwise CONTROL_UNTESTED is set (the test
# could not run at all — UNTESTED, never gated) or CONTROL_FAIL is set
# (the test ran and the floor did not hold — REFUTED, gated: a host where
# loopback is dead is a finding, not an absence of test).
CONTROL_UNTESTED=""
CONTROL_FAIL=""
control_loopback() {
    CONTROL_UNTESTED=""
    CONTROL_FAIL=""
    if ! command -v python3 >/dev/null 2>&1; then
        CONTROL_UNTESTED="python3 not found (loopback listener)"
        return 1
    fi
    if ! command -v timeout >/dev/null 2>&1; then
        CONTROL_UNTESTED="timeout not found (loopback listener)"
        return 1
    fi
    if timeout 10 python3 - >"$BUILD/loopback.out" 2>&1 <<'PY'
import socket, sys
srv = socket.socket()
try:
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.socket()
    cli.settimeout(5)
    try:
        cli.connect(("127.0.0.1", srv.getsockname()[1]))
        conn, _ = srv.accept()
        conn.close()
    finally:
        cli.close()
except OSError as e:
    print(repr(e))
    sys.exit(1)
finally:
    srv.close()
PY
    then
        return 0
    fi
    CONTROL_FAIL=$(tail -n1 "$BUILD/loopback.out" 2>/dev/null)
    [ -n "$CONTROL_FAIL" ] || \
        CONTROL_FAIL="loopback connect failed (see tests/enforce/.build/loopback.out)"
    return 1
}

run_dynamic() {
    # Floor row first (docs/harness.md §3/§4): it needs no boundary, so it
    # runs before the precondition row rather than after it — enforcement
    # is off by definition here, and green is "the observer records
    # legitimate traffic".
    local desc_loop="with enforcement not yet engaged, a loopback TCP connection must be observable as succeeding — the floor every later 'blocked' verdict is read against"
    local notes_floor="Floor row (docs/harness.md §3/§4): runs before boundary.up because it needs no boundary. Green here is the observation path, not the boundary — a coverage.* 'blocked' claim means 'flowing was demonstrable' only once this row is VERIFIED, never merely 'nothing got out'."
    if control_loopback; then
        record "control.loopback" "control" "$desc_loop" \
            "dynamic" "flows" "flows" "VERIFIED" \
            '{"tool":"python3 bind/listen/connect/accept on 127.0.0.1","rc":0}' \
            "true" "docs/harness.md#3-row-families--targets-not-measurements" \
            "$notes_floor" "VERIFIED"
    elif [ -n "$CONTROL_UNTESTED" ]; then
        record "control.loopback" "control" "$desc_loop" \
            "dynamic" "flows" "not_run" "UNTESTED" \
            "$(jq -cn --arg r "$CONTROL_UNTESTED" '{reason:$r}')" \
            "true" "docs/harness.md#3-row-families--targets-not-measurements" \
            "$notes_floor The test could not run at all — evidence.reason names the missing piece. UNTESTED is a claim of absence of test, never a claim of correctness; the gate skips it by construction." \
            "VERIFIED"
    else
        record "control.loopback" "control" "$desc_loop" \
            "dynamic" "flows" "not_flowing" "REFUTED" \
            "$(jq -cn --arg r "$CONTROL_FAIL" '{reason:$r}')" \
            "true" "docs/harness.md#3-row-families--targets-not-measurements" \
            "$notes_floor Tested and the floor did not hold — this gates, by design: a host where loopback traffic cannot be observed is a finding about the observation path, not an environment to degrade away." \
            "VERIFIED"
    fi
    if boundary_up; then
        record "boundary.up" "boundary" \
            "the launcher must complete docs/enforcement.md §5's fail-closed sequence before any boundary-dependent dynamic row runs" \
            "dynamic" "up" "up" "VERIFIED" \
            "$BOUNDARY_EVIDENCE" \
            "true" "docs/enforcement.md#5-fail-closed-launch-sequence" \
            "Precondition row (docs/harness.md §4): the floor row (control.loopback) runs first because it needs no boundary; the boundary-dependent rows start here. Evidence is the launcher's own report — mode, target exit, all nine §5 steps — not a harness-side assertion about it." \
            "VERIFIED"
    else
        record "boundary.up" "boundary" \
            "the launcher must complete docs/enforcement.md §5's fail-closed sequence before any boundary-dependent dynamic row runs" \
            "dynamic" "up" "not_run" "UNTESTED" \
            "$(jq -cn --arg r "$BOUNDARY_REASON" '{reason:$r}')" \
            "true" "docs/enforcement.md#5-fail-closed-launch-sequence" \
            "Precondition row (docs/harness.md §4): the floor row runs first, and no other boundary-dependent dynamic row means anything until this one is VERIFIED. UNTESTED when the environment cannot stand the boundary up — every unmet prerequisite or abort step is named in evidence.reason, measured at run time, never assumed. expected_verdict is VERIFIED: on a host with prerequisites this row must pass. Observed UNTESTED is skipped by the gate by construction — absence of test is never correctness — so the documented expectation is never downgraded to match an environment." \
            "VERIFIED"
    fi
    # The other families (disable.*, coverage.completeness.*, backstop.*,
    # signal.* observer-side rows, agreement.*, control.* paired rows) are
    # defined in docs/harness.md §3 and are recorded here the day each is
    # first measured — docs/harness.md §7: harness first so an ID or an
    # evidence key has somewhere to land. The observer loop itself (§1:
    # verdicts collected host-side) arrives with probes/.
}

# ---------------------------------------------------------------------------
# Render + gate
# ---------------------------------------------------------------------------
finalize() {
    local ts rev torv meta
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    rev=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo nogit)
    torv=$(timeout 3 tor --version 2>/dev/null | sed -n '1p')
    [ -n "$torv" ] || torv="n/a"
    # _meta: makes a committed results.jsonl self-describing. `polarity` is
    # REQUIRED and stamped here — the guard above is what keeps a foreign
    # file from ever reaching this rewrite. `schema` is 1: this contract is
    # born with polarity (SCHEMA.md), it is not Phase 1's schema 2.
    # `commit` is the revision this run EXECUTED at (a file cannot contain
    # the hash of the commit that contains it — regenerate after
    # verdict-affecting changes).
    meta=$(jq -cn --arg generated "$ts" --arg commit "$rev" --arg mode "$MODE" \
        --arg host "$(uname -srm)" --arg tor_version "$torv" \
        --arg schema_url "tests/enforce/SCHEMA.md" \
        '{id:"_meta",schema:1,polarity:"enforcement",generated:$generated,
          commit:$commit,mode:$mode,host:$host,tor_version:$tor_version,
          results_schema_url:$schema_url}')

    # Partial runs (--static / --dynamic) merge into the committed file by id
    # so a PR's static run can never destroy previously recorded dynamic
    # evidence. A full run replaces everything. _meta is always rewritten fresh.
    local tmp="$BUILD/records.jsonl"
    if [ "${#RECORDS[@]}" -gt 0 ]; then
        printf '%s\n' "${RECORDS[@]}" > "$tmp"
    else
        : > "$tmp"
    fi
    if [ "$MODE" != both ] && [ -f "$JSONL" ]; then
        # NOTE: write elsewhere first — redirecting onto the file jq is
        # reading would truncate it to empty before jq opens it.
        jq -cn --slurpfile old "$JSONL" --slurpfile new "$tmp" \
            '($new | map(.id)) as $ids
             | ([$old[] | select(.id != "_meta"
                 and (. as $r | ($ids | index($r.id)) == null))] + $new)[]' \
            > "$BUILD/merged.jsonl"
        { printf '%s\n' "$meta"; cat "$BUILD/merged.jsonl"; } > "$JSONL"
    else
        { printf '%s\n' "$meta"; cat "$tmp"; } > "$JSONL"
    fi

    {
        printf '# TORX enforcement harness results\n\n'
        printf -- '- generated: `%s`\n- commit: `%s`\n- mode: `%s`\n- polarity: `enforcement`\n\n' \
            "$ts" "$rev" "$MODE"
        printf '| id | class | method | expected | observed | verdict | ci_gate |\n'
        printf '|---|---|---|---|---|---|---|\n'
        jq -r 'select(.id != "_meta")
               | [.id,.class,.method,.expected,.observed,.verdict,(.ci_gate|tostring)]|join("~")' "$JSONL" \
            | awk -F'~' '{printf "| `%s` | %s | %s | %s | **%s** | %s | %s |\n",$1,$2,$3,$4,$5,$6,$7}'
        printf '\nVerdicts: `VERIFIED` matches expectation · `REFUTED` expectation broken · '
        printf '`UNTESTED` could not run (see notes) · `FLAKY` inconsistent.\n\n'
        printf '`UNTESTED` is a claim of absence of test, never a claim of correctness.\n'
        printf 'Under enforcement polarity, `VERIFIED` means the boundary held.\n'
    } > "$MARKDOWN"

    # Gate: ci_gate rows must still match their documented verdict.
    local fails=0 id v ev
    while IFS=$'\t' read -r id v ev; do
        [ "$v" = "UNTESTED" ] && continue
        if [ "$v" != "$ev" ]; then
            printf 'GATE VIOLATION: %s documented %s, observed %s\n' "$id" "$ev" "$v" >&2
            printf '  -> update docs/harness.md + expected_verdict if intentional\n' >&2
            fails=1
        fi
    done < <(jq -r 'select(.ci_gate) | [.id,.verdict,.expected_verdict]|join("\t")' "$JSONL")

    # Gate: a null in an `*_observed` evidence field must carry a sibling
    # `*_reason` (SCHEMA.md). `null` must never be readable as "zero" or
    # as "we didn't check" — the reason field is what disambiguates, and
    # this check is what makes the distinction machine-checkable.
    local miss
    miss=$(jq -r 'select(.id != "_meta")
        | .id as $id | (.evidence // {}) as $e
        | [$e | to_entries[]
           | select((.key | endswith("_observed")) and .value == null)
           | (.key | sub("_observed$"; "_reason"))
           | select($e[.] == null)]
        | select(length > 0)
        | "\($id): \(join(", "))"' "$JSONL")
    if [ -n "$miss" ]; then
        printf 'GATE VIOLATION: null *_observed without sibling *_reason:\n' >&2
        printf '  %s\n' "$miss" >&2
        printf '  -> SCHEMA.md: null never means "zero" or "not checked" alone\n' >&2
        fails=1
    fi

    printf '\n'
    jq -r 'select(.id != "_meta") | "  \(.verdict)  \(.id)"' "$JSONL"
    printf '\n%d rows -> %s, %s\n' "${#RECORDS[@]}" \
        "${JSONL#"$ROOT"/}" "${MARKDOWN#"$ROOT"/}"

    # A regenerated snapshot dirtying a clean tree is the design working, not
    # a bug — but a reviewer watching `git status` cannot tell which case they
    # are in. Say which, at the moment the diff is created. Same rule as a
    # null *_observed: silence must be loud.
    if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 \
        && ! git -C "$ROOT" diff --quiet -- "${JSONL#"$ROOT"/}" 2>/dev/null; then
        printf '\nSnapshot at %s may now differ from HEAD.\n' "${JSONL#"$ROOT"/}"
        printf '  _meta / evidence-only diff: regeneration, safe to revert or refresh.\n'
        printf '  verdict / expected_verdict diff: a finding. See tests/enforce/README.md.\n'
    fi

    [ "$fails" -eq 0 ] || exit 1
}

case "$MODE" in
    static)  run_static ;;
    dynamic) run_dynamic ;;
    both)    run_static; run_dynamic ;;
esac
finalize
