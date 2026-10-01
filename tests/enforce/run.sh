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
#   --static    structural rows about the launcher (signal.* family): no
#               network, no namespace, gated on every CI run — exactly like
#               Phase 1's static rows. [scaffold: rows land with netns/]
#   --dynamic   needs a live boundary (netns + nftables + Tor). Starts with
#               the boundary.up precondition row; degrades to UNTESTED
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
# namespace, gated on every CI run (docs/harness.md §4, the signal.*
# family: fds are CLOEXEC, no shared channel, capability bits as read
# from /proc).
# ---------------------------------------------------------------------------
# Scaffold state: the launcher does not exist yet, so there is no
# structure to assert. Record nothing — and say so loudly. An empty
# green would be the exact failure docs/harness.md §4 forbids; the rows
# land the day their subject does, and this banner is what a --static run
# prints until then.
run_static() {
    printf 'note: no signal.* structural rows yet — they assert facts about\n'
    printf '      the netns/launcher (fds CLOEXEC, no shared channel, capability\n'
    printf '      bits from /proc) and land with it. Recording nothing.\n'
    printf '      See docs/harness.md §3 (signal.*) and §4.\n'
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

BOUNDARY_REASON=""
boundary_up() {
    local missing=()
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
    # All prerequisites present — but the harness is not yet wired to
    # launch the boundary (scaffold). 6b replaces this with the actual
    # launch + §5 verification, and BOUNDARY_REASON="launcher aborted at
    # step N" on a fail-closed abort.
    BOUNDARY_REASON="prerequisites present, but the harness cannot yet launch the boundary (scaffold)"
    return 1
}

run_dynamic() {
    if boundary_up; then
        record "boundary.up" "boundary" \
            "the launcher must complete docs/enforcement.md §5's fail-closed sequence before any other dynamic row runs" \
            "dynamic" "up" "up" "VERIFIED" \
            '{"launch":"completed"}' \
            "true" "docs/enforcement.md#5-fail-closed-launch-sequence" \
            "Precondition row (docs/harness.md §4): dynamic mode starts here." \
            "VERIFIED"
    else
        record "boundary.up" "boundary" \
            "the launcher must complete docs/enforcement.md §5's fail-closed sequence before any other dynamic row runs" \
            "dynamic" "up" "not_run" "UNTESTED" \
            "$(jq -cn --arg r "$BOUNDARY_REASON" '{reason:$r}')" \
            "true" "docs/enforcement.md#5-fail-closed-launch-sequence" \
            "Precondition row (docs/harness.md §4): dynamic mode starts here, and no other dynamic row means anything until this one is VERIFIED. UNTESTED while the boundary is unbuilt — every unmet prerequisite is named in evidence.reason, measured at run time, never assumed. Flips to VERIFIED when the launcher lands; expected_verdict updates in the same change (stale-verdict policy, README.md)." \
            "UNTESTED"
    fi
    # The other families (disable.*, coverage.completeness.*, backstop.*,
    # signal.* dynamics, agreement.*, control.*) are defined in
    # docs/harness.md §3 and are recorded here the day each is first
    # measured — docs/harness.md §7: harness first so an ID or an evidence
    # key has somewhere to land. The observer loop itself (§1: verdicts
    # collected host-side) arrives with probes/.
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
