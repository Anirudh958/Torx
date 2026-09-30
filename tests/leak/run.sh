#!/usr/bin/env bash
# tests/leak/run.sh — TORX leak taxonomy harness
#
# Emits two artifacts, both committed:
#   tests/leak/results.jsonl   machine-readable, grep/diff-able by reviewers
#   tests/leak/results.md      rendered table, for LIMITATIONS.md + slides
#
# Modes:
#   --static    nm/readelf/ldd only. No network, no Tor. Runs on every PR.
#   --dynamic   needs outbound network. Tor optional (see "TORX_PORT=1").
#   (none)      both. If egress is unavailable, dynamic rows degrade to
#               UNTESTED instead of failing — a dead CI runner is never
#               mistaken for a real leak.
#
# Exit codes:
#   0  every ci_gate row matches its expected_verdict
#   1  gate violation: a documented verdict changed (fix or regression)
#   2  setup error (missing library, probe failed to build)
#
# ---------------------------------------------------------------------------
# The TORX_PORT=1 trick
# ---------------------------------------------------------------------------
# Making a leak *observable* without packet capture or a running Tor: point
# the shim at a closed port. Then interception is observable as FAILURE (the
# shim dials 127.0.0.1:1 and gets ECONNREFUSED) and bypass is observable as
# SUCCESS (the syscall never reached the shim). Each probe additionally emits
# the shim's own TORX_DEBUG trace, so `routed:true|false` is read from the
# shim's mouth rather than inferred from an exit code.
#
# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
# `expected_verdict` is the documented current state (LIMITATIONS.md). A
# ci_gate row fails CI when observed != documented — in BOTH directions:
# a leak that silently appears is a regression, and a leak that silently
# disappears is an undocumented behaviour change that must be written down.
# UNTESTED never fails the gate: it is a claim of absence of test, never a
# claim of correctness.
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
LIB="$ROOT/libtorx.so"
BUILD="$HERE/.build"
JSONL="$HERE/results.jsonl"
MARKDOWN="$HERE/results.md"
# The shim's own trace marker (torx.c, dbg()).
TRACE='[TORX] routing connect()'

[ -f "$LIB" ] || { printf 'setup: %s missing — run `make` first\n' "$LIB" >&2; exit 2; }

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

# mask_v6 <address> — keep only the first two hextets so results.jsonl can be
# committed without disclosing the operator's own addresses (or an egress
# node's) to reviewers.
mask_v6() {
    [ -n "$1" ] || return 0
    awk -F: '{printf "%s:%s::\n",$1,$2}' <<<"$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Static mode: deterministic, network-free, CI-safe
# ---------------------------------------------------------------------------
run_static() {
    local names resolved udpexp textrel canary undef njson observed verdict
    names=$(nm -D --defined-only "$LIB" | awk '$2=="T"{print $3}')
    njson=$(printf '%s\n' $names | jq -R -s 'split("\n")|map(select(length>0))')
    resolved=$(printf '%s\n' "$names" | grep -cx getaddrinfo)
    textrel=$(readelf -d "$LIB" | grep -c TEXTREL || true)
    canary=$(readelf -sW "$LIB" | grep -c __stack_chk_fail || true)
    undef=$(ldd -r "$LIB" 2>&1 | grep -c 'undefined symbol' || true)

    # --- the headline: provable with one command, no network, no Tor ------
    observed=$([ "$resolved" -gt 0 ] && echo exported || echo not_exported)
    record "dns.export.getaddrinfo" "dns" \
        "getaddrinfo must be exported for name resolution to be proxied" \
        "static" "exported" "$observed" "$(verdict_for exported "$observed")" \
        '{"tool":"nm -D --defined-only libtorx.so | grep \" T getaddrinfo\"","exported_T":'"$njson"'}' \
        "true" "LIMITATIONS.md#1-dns" \
        "Deterministic: needs neither network nor Tor. If this flips to VERIFIED the leak is fixed — update LIMITATIONS.md §1 and the make check assertion." \
        "REFUTED"

    observed=$(printf '%s\n' "$names" | grep -qx connect && echo exported || echo missing)
    record "hook.export.connect" "tcp" \
        "the connect() interposer must be exported or nothing is routed" \
        "static" "exported" "$observed" "$(verdict_for exported "$observed")" \
        '{"tool":"nm -D --defined-only","exported_T":'"$njson"'}' \
        "true" "LIMITATIONS.md#3-tcp" \
        "Baseline: without this the shim is inert and every row below is meaningless." "VERIFIED"

    # --- UDP anonymity class: payload can never be routed ------------------
    # Only `connect` is exported: there is no sendto/sendmsg hook, so no UDP
    # payload (DNS-over-UDP, QUIC, ...) can ever be steered through Tor.
    # Distinct from the udp-correctness rows below: those corrupt the socket,
    # this one silently leaks the payload.
    udpexp=$(printf '%s\n' "$names" | grep -cx -e sendto -e sendmsg)
    observed=$([ "$udpexp" -gt 0 ] && echo exported || echo not_exported)
    record "udp.export.sendto" "udp" \
        "UDP payload must be routable (sendto/sendmsg exported), else UDP leaks" \
        "static" "exported" "$observed" "$(verdict_for exported "$observed")" \
        '{"tool":"nm -D --defined-only | T {sendto,sendmsg}","match_count":'"$udpexp"',"exported_T":'"$njson"'}' \
        "true" "LIMITATIONS.md#udp" \
        "Anonymity class: without a sendmsg/sendto hook UDP bytes go direct, never through Tor. The separate correctness class (udp-correctness) is socket corruption on connect()." \
        "REFUTED"

    observed=$([ "$textrel" -gt 0 ] && echo present || echo absent)
    record "elf.textrel" "elf" "no text relocations (required for full RELRO)" \
        "static" "absent" "$observed" "$(verdict_for absent "$observed")" \
        "$(jq -cn --argjson n "$textrel" '{tool:"readelf -d",textrel_count:$n}')" \
        "true" "n/a" "" "VERIFIED"

    observed=$([ "$canary" -gt 0 ] && echo present || echo absent)
    record "elf.stack_protector" "elf" "__stack_chk_fail referenced (canary present)" \
        "static" "present" "$observed" "$(verdict_for present "$observed")" \
        "$(jq -cn --argjson n "$canary" '{tool:"readelf -s",match_count:$n}')" \
        "true" "n/a" "Guards -fstack-protector-strong in CFLAGS." "VERIFIED"

    observed=$([ "$undef" -gt 0 ] && echo present || echo none)
    record "elf.undefined_symbols" "elf" "no unresolved symbols at load time" \
        "static" "none" "$observed" "$(verdict_for none "$observed")" \
        "$(jq -cn --argjson n "$undef" '{tool:"ldd -r",undefined_count:$n}')" \
        "true" "n/a" "A library that fails to load routes nothing." "VERIFIED"
}

# ---------------------------------------------------------------------------
# Dynamic mode
# ---------------------------------------------------------------------------
have_egress() { timeout 4 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; }
have_v6()     { timeout 6 curl -6 -s --max-time 4 -o /dev/null https://www.cloudflare.com 2>/dev/null; }
have_tor()    { timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9050' 2>/dev/null; }

PROBE_EXIT=0
PROBE_ROUTED=false

# run_probe <binary> [target_ip]  → sets PROBE_EXIT / PROBE_ROUTED, stderr
#                                  is captured to "$BUILD/last.err"
run_probe() {
    local bin="$1" ip="${2:-1.1.1.1}"
    PROBE_EXIT=0
    TORX_DEBUG=1 TORX_PORT=1 LD_PRELOAD="$LIB" timeout 8 \
        "$bin" "$ip" 443 2>"$BUILD/last.err" || PROBE_EXIT=$?
    if grep -qF "$TRACE" "$BUILD/last.err" 2>/dev/null; then
        PROBE_ROUTED=true
    else
        PROBE_ROUTED=false
    fi
}

# evidence <probe-name>
evidence() {
    jq -cn --arg probe "$1" --argjson exit "$PROBE_EXIT" \
           --argjson routed "$PROBE_ROUTED" \
           --arg stderr "$(head -c 160 "$BUILD/last.err" 2>/dev/null | tr -d '\n')" \
           '{probe:$probe, exit:$exit, routed:$routed, stderr:$stderr}'
}

# degrade <id> <class> <description> <limitation_ref> <notes>
degrade() {
    record "$1" "$2" "$3" "dynamic" "see LIMITATIONS.md" "not_run" "UNTESTED" \
        "$(jq -cn --arg r "$EGRESS_REASON" '{reason:$r}')" \
        "false" "$4" "$5" "UNTESTED"
}

skip_all_dynamic() {
    EGRESS_REASON="$1"
    degrade "tcp.interception" "tcp" "public IPv4 connect must be intercepted" \
        "n/a" "Positive control."
    degrade "tcp.passthrough_loopback" "tcp" "loopback must bypass Tor" \
        "n/a" ""
    degrade "tcp.passthrough_private" "tcp" "RFC1918 must bypass Tor" \
        "n/a" ""
    degrade "ipv6.passthrough" "ipv6" "AF_INET6 must be proxied or blocked" \
        "LIMITATIONS.md#2-ipv6" "UNTESTED is a claim of absence of test, not of correctness."
    degrade "bypass.static_binary" "static" "LD_PRELOAD must not be silently ignored" \
        "LIMITATIONS.md#static" ""
    degrade "bypass.raw_syscall" "direct-syscall" "raw syscall(__NR_connect) must be intercepted" \
        "LIMITATIONS.md#raw-syscall" ""
    # NOTE: udp.export.sendto is static (nm) — it is never degraded; a
    # dynamic-only run must not overwrite its REFUTED evidence with UNTESTED.
    degrade "udp.connect_hijack" "udp-correctness" "SOCK_DGRAM connect() must not become Tor TCP" \
        "LIMITATIONS.md#udp" "Correctness class: socket corruption, not payload disclosure."
    degrade "udp.fd_swap" "udp-correctness" "the UDP fd must not be swapped for a TCP socket" \
        "LIMITATIONS.md#udp" "Needs a live Tor."
    degrade "dns.dynamic.egress" "dns" "DNS must not egress outside Tor" \
        "LIMITATIONS.md#1-dns" "Static nm assertion is the CI gate for this class."
    degrade "tor.e2e" "tcp" "end-to-end egress via a real Tor circuit" \
        "n/a" "Needs a running Tor; never a CI gate."
}

build_probes() {
    cc -O1 -o "$BUILD/probe_connect"    "$HERE/probes/probe_connect.c"    || return 1
    cc -O1 -o "$BUILD/probe_rawsyscall" "$HERE/probes/probe_rawsyscall.c" || return 1
    cc -O1 -o "$BUILD/probe_udp"        "$HERE/probes/probe_udp.c"        || return 1
    cc -O1 -static -o "$BUILD/probe_connect_static" \
        "$HERE/probes/probe_connect.c" 2>"$BUILD/static_cc.log" || return 1
}

run_dynamic() {
    if ! have_egress; then
        skip_all_dynamic "no outbound IPv4 egress from this host"
        return
    fi
    build_probes || { printf 'setup: probe build failed (see %s)\n' "$BUILD/static_cc.log" >&2; exit 2; }

    local observed verdict

    # --- positive control: a public IPv4 connect MUST be intercepted ------
    run_probe "$BUILD/probe_connect"
    observed=$([ "$PROBE_ROUTED" = true ] && echo intercepted || echo bypassed)
    verdict=$(verdict_for intercepted "$observed")
    record "tcp.interception" "tcp" \
        "public IPv4 connect must be intercepted by the shim" \
        "dynamic" "intercepted" "$observed" "$verdict" \
        "$(evidence 'libc connect()')" \
        "true" "n/a" \
        "If this ever shows bypassed the shim is inert and no other dynamic row means anything." \
        "VERIFIED"

    # --- loopback must NOT be routed --------------------------------------
    run_probe "$BUILD/probe_connect" 127.0.0.1
    observed=$([ "$PROBE_ROUTED" = true ] && echo routed || echo passthrough)
    verdict=$(verdict_for passthrough "$observed")
    record "tcp.passthrough_loopback" "tcp" \
        "loopback connections must never go through Tor" \
        "dynamic" "passthrough" "$observed" "$verdict" \
        "$(evidence 'libc connect() to 127.0.0.1:1')" \
        "true" "n/a" "Routing loopback would deadlock local services and Tor itself." "VERIFIED"

    # --- private LAN must NOT be routed -----------------------------------
    local lan_ip
    lan_ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    if [ -n "$lan_ip" ]; then
        run_probe "$BUILD/probe_connect" "$lan_ip"
        observed=$([ "$PROBE_ROUTED" = true ] && echo routed || echo passthrough)
        verdict=$(verdict_for passthrough "$observed")
        record "tcp.passthrough_private" "tcp" \
            "RFC1918 targets must bypass Tor (Tor cannot reach them)" \
            "dynamic" "passthrough" "$observed" "$verdict" \
            "$(evidence "libc connect() to $lan_ip:1")" \
            "true" "n/a" "" "VERIFIED"
    fi

    # --- IPv6 -------------------------------------------------------------
    if have_v6; then
        local v6ip="" v6rc=0
        v6ip=$(TORX_DEBUG=1 TORX_PORT=1 LD_PRELOAD="$LIB" timeout 15 \
                   curl -6 -s --max-time 10 https://api64.ipify.org 2>"$BUILD/last.err") || v6rc=$?
        if grep -qF "$TRACE" "$BUILD/last.err" 2>/dev/null; then
            observed=proxied_or_blocked
        elif [ -n "$v6ip" ]; then
            observed="direct:$(mask_v6 "$v6ip")"
        else
            observed="failed"
        fi
        verdict=$(verdict_for proxied_or_blocked "$observed")
        record "ipv6.passthrough" "ipv6" \
            "AF_INET6 connect must be proxied or blocked, never passed through" \
            "dynamic" "proxied_or_blocked" "$observed" "$verdict" \
            "$(jq -cn --arg ip "$(mask_v6 "$v6ip")" --argjson rc "$v6rc" \
                '{probe:"curl -6 https://api64.ipify.org", source_ip_masked:$ip, exit:$rc}')" \
            "true" "LIMITATIONS.md#2-ipv6" \
            "connect() passes sa_family != AF_INET straight to the real libc, so IPv6 egress exposes the origin address." \
            "REFUTED"
    else
        record "ipv6.passthrough" "ipv6" \
            "AF_INET6 connect must be proxied or blocked, never passed through" \
            "dynamic" "proxied_or_blocked" "not_run" "UNTESTED" \
            '{"reason":"host has no usable IPv6 route"}' \
            "false" "LIMITATIONS.md#2-ipv6" \
            "UNTESTED is a claim of absence of test, NOT a claim of correctness." "UNTESTED"
    fi

    # --- static binary bypass --------------------------------------------
    run_probe "$BUILD/probe_connect_static"
    # exit 0 with no shim trace == the shim was never even loaded
    observed=$([ "$PROBE_ROUTED" = false ] && [ "$PROBE_EXIT" -eq 0 ] \
                   && echo bypassed || echo intercepted)
    verdict=$(verdict_for intercepted "$observed")
    record "bypass.static_binary" "static" \
        "a -static binary must not silently lose interception" \
        "dynamic" "intercepted" "$observed" "$verdict" \
        "$(evidence '-static libc connect()')" \
        "true" "LIMITATIONS.md#static" \
        "Static binaries have no dynamic loader, so LD_PRELOAD is ignored entirely." "REFUTED"

    # --- raw syscall bypass ----------------------------------------------
    run_probe "$BUILD/probe_rawsyscall"
    observed=$([ "$PROBE_ROUTED" = true ] && echo intercepted || echo bypassed)
    verdict=$(verdict_for intercepted "$observed")
    record "bypass.raw_syscall" "direct-syscall" \
        "syscall(__NR_connect) must not bypass the interposer" \
        "dynamic" "intercepted" "$observed" "$verdict" \
        "$(evidence 'syscall(__NR_connect)')" \
        "true" "LIMITATIONS.md#raw-syscall" \
        "LD_PRELOAD interposes libc symbols, not syscalls. This is the adversary that motivates the netns architecture." \
        "REFUTED"

    # --- UDP connect() hijack --------------------------------------------
    # The hook never checks socktype, so a SOCK_DGRAM connect() is routed
    # as TCP. Deterministic under TORX_PORT=1: the trace alone proves the
    # hijack attempt, no Tor needed.
    #
    # post_stats: probe_udp prints machine-parseable post-conditions
    # ("what: rc=N errno=N") after a successful connect — send(), sendto()
    # to a different destination, and a second connect(). These are the
    # only signals an application has after the corruption; see SCHEMA.md
    # for how they ride in evidence.
    post_stats() { # $1 = probe stderr file
        local f="$1"
        POST_SEND_RC=$(sed -n 's/^send: rc=\(-\?[0-9]\+\) errno=\([0-9]\+\).*/\1/p' "$f" | head -1)
        POST_SEND_ERRNO=$(sed -n 's/^send: rc=\(-\?[0-9]\+\) errno=\([0-9]\+\).*/\2/p' "$f" | head -1)
        POST_SENDTO_RC=$(sed -n 's/^sendto: rc=\(-\?[0-9]\+\) errno=\([0-9]\+\).*/\1/p' "$f" | head -1)
        POST_SENDTO_ERRNO=$(sed -n 's/^sendto: rc=\(-\?[0-9]\+\) errno=\([0-9]\+\).*/\2/p' "$f" | head -1)
        POST_RECONN_RC=$(sed -n 's/^reconnect: rc=\(-\?[0-9]\+\) errno=\([0-9]\+\).*/\1/p' "$f" | head -1)
        POST_RECONN_ERRNO=$(sed -n 's/^reconnect: rc=\(-\?[0-9]\+\) errno=\([0-9]\+\).*/\2/p' "$f" | head -1)
        POST_SO_TYPE_AFTER=$(sed -n 's/.*so_type_after=\([0-9]*\).*/\1/p' "$f" | head -1)
        POST_REROUTES=$(grep -cF "$TRACE" "$f" 2>/dev/null)
        [ -n "$POST_REROUTES" ] || POST_REROUTES=0
    }
    PROBE_EXIT=0
    TORX_DEBUG=1 TORX_PORT=1 LD_PRELOAD="$LIB" timeout 8 \
        "$BUILD/probe_udp" 1.1.1.1 53 2>"$BUILD/last.err" || PROBE_EXIT=$?
    if grep -qF "$TRACE" "$BUILD/last.err" 2>/dev/null; then PROBE_ROUTED=true
    else PROBE_ROUTED=false; fi
    local so_type reroutes
    so_type=$(sed -n 's/.*so_type=\([0-9]*\).*/\1/p' "$BUILD/last.err" | head -1)
    post_stats "$BUILD/last.err"
    reroutes=$POST_REROUTES
    observed=$([ "$PROBE_ROUTED" = true ] && echo hijack_attempted || echo passthrough)
    verdict=$(verdict_for passthrough_or_error "$observed")
    record "udp.connect_hijack" "udp-correctness" \
        "a SOCK_DGRAM connect() must not be converted into a Tor TCP connection" \
        "dynamic" "passthrough_or_error" "$observed" "$verdict" \
        "$(jq -cn --argjson exit "$PROBE_EXIT" --arg so_type "${so_type:-unknown}" \
            --argjson reroutes "$reroutes" \
            '{probe:"SOCK_DGRAM connect() to 1.1.1.1:53", exit:$exit, routed:('"$PROBE_ROUTED"'), so_type:$so_type, reroutes:$reroutes, so_type_note:"1=SOCK_STREAM 2=SOCK_DGRAM", reroutes_note:"times the shim printed the routing trace: 1 = initial connect only (post-ops skipped because the dead-port dial failed)"}')" \
        "true" "LIMITATIONS.md#udp" \
        "Correctness class (socket corruption), not the anonymity class — that is udp.export.sendto. No SO_TYPE check exists anywhere in torx.c, so SOCKS4 (TCP-only) is attempted on a datagram socket; so_type here is still 2 only because the dead-port dial fails first — see udp.fd_swap for the live swap." \
        "REFUTED"

    # --- UDP fd swap against a live Tor (needs 127.0.0.1:9050) -----------
    if have_tor; then
        PROBE_EXIT=0
        TORX_DEBUG=1 TORX_PORT=9050 LD_PRELOAD="$LIB" timeout 20 \
            "$BUILD/probe_udp" 1.1.1.1 53 2>"$BUILD/last.err" || PROBE_EXIT=$?
        so_type=$(sed -n 's/.*so_type=\([0-9]*\).*/\1/p' "$BUILD/last.err" | head -1)
        post_stats "$BUILD/last.err"
        observed=$([ "$so_type" = "1" ] && echo fd_became_tcp || echo fd_unchanged)
        verdict=$(verdict_for fd_unchanged "$observed")
        record "udp.fd_swap" "udp-correctness" \
            "the application's UDP fd must not become a TCP socket (dup2 swap)" \
            "dynamic" "fd_unchanged" "$observed" "$verdict" \
            "$(jq -cn --argjson exit "$PROBE_EXIT" --arg so_type "${so_type:-unknown}" \
                --arg so_type_after "${POST_SO_TYPE_AFTER:-unknown}" \
                --argjson send_rc "${POST_SEND_RC:-null}" \
                --argjson send_errno "${POST_SEND_ERRNO:-null}" \
                --argjson sendto_rc "${POST_SENDTO_RC:-null}" \
                --argjson sendto_errno "${POST_SENDTO_ERRNO:-null}" \
                --argjson reconn_rc "${POST_RECONN_RC:-null}" \
                --argjson reconn_errno "${POST_RECONN_ERRNO:-null}" \
                --argjson reroutes "${POST_REROUTES:-0}" \
                '{probe:"SOCK_DGRAM connect() via live Tor", exit:$exit, so_type:$so_type, so_type_after:$so_type_after,
                  post_swap_send_rc:$send_rc, post_swap_send_errno:$send_errno,
                  post_swap_sendto_rc:$sendto_rc, post_swap_sendto_errno:$sendto_errno,
                  post_swap_reconnect_rc:$reconn_rc, post_swap_reconnect_errno:$reconn_errno,
                  reroutes:$reroutes,
                  no_errno_note:"send/sendto/reconnect all returned success after the swap — no errno is raised, so SO_TYPE is the only in-app tell"}')" \
            "false" "LIMITATIONS.md#udp" \
            "The corruption in its final form: connect() returned success while the fd became SOCK_STREAM — the app's datagram payload now rides a TCP stream, send()/sendto() still report success (address silently ignored), and a second connect() routes a fresh Tor stream over the same fd (reroutes=2). Correctness class, distinct from the udp leak class. Needs a live Tor, hence not a gate." \
            "REFUTED"
    else
        record "udp.fd_swap" "udp-correctness" \
            "the application's UDP fd must not become a TCP socket (dup2 swap)" \
            "dynamic" "fd_unchanged" "not_run" "UNTESTED" \
            '{"reason":"nothing listening on 127.0.0.1:9050"}' \
            "false" "LIMITATIONS.md#udp" "" "UNTESTED"
    fi

    # --- DNS dynamic ------------------------------------------------------
    record "dns.dynamic.egress" "dns" \
        "DNS queries must not egress outside Tor" \
        "dynamic" "proxied_or_blocked" "not_run" "UNTESTED" \
        '{"reason":"observing DNS egress needs CAP_NET_RAW (tcpdump) or a controlled resolver"}' \
        "false" "LIMITATIONS.md#1-dns" \
        "dns.export.getaddrinfo (static) is the CI gate for this class; this row documents why a dynamic gate is not yet possible." \
        "UNTESTED"

    # --- Tor end-to-end ---------------------------------------------------
    # NOTE: this must load the shim (LD_PRELOAD) and dial the real Tor port.
    # Only the boolean is recorded — never the response body, which contains
    # either the operator's own address or a Tor exit's.
    if have_tor; then
        local ok=0 i resp="" routed=false
        for i in 1 2 3; do
            resp=$(TORX_DEBUG=1 TORX_PORT=9050 LD_PRELOAD="$LIB" timeout 40 \
                       curl -s --max-time 30 https://check.torproject.org/api/ip \
                       2>"$BUILD/last.err") || true
            if grep -qF "$TRACE" "$BUILD/last.err" 2>/dev/null; then routed=true; fi
            if printf '%s' "$resp" | grep -q '"IsTor":true'; then
                ok=$((ok+1))
            else
                break
            fi
        done
        if   [ "$ok" -eq 3 ]; then verdict=VERIFIED; observed="IsTor:true (3/3)"
        elif [ "$ok" -gt 0 ]; then verdict=FLAKY;    observed="IsTor:true ($ok/3)"
        elif [ -n "$resp" ];  then verdict=REFUTED;   observed="not_tor"
        else                        verdict=UNTESTED; observed="no_response"; fi
        record "tor.e2e" "tcp" "end-to-end egress via a real Tor circuit" \
            "dynamic" "IsTor=true" "$observed" "$verdict" \
            "$(jq -cn --argjson ok "$ok" --argjson routed "$routed" \
                '{attempts:3, ok:$ok, shim_routed:$routed, is_tor:($ok > 0)}')" \
            "false" "n/a" "Run against a live Tor; excluded from CI gates (timing-dependent)." "$verdict"
    else
        record "tor.e2e" "tcp" "end-to-end egress via a real Tor circuit" \
            "dynamic" "IsTor=true" "not_run" "UNTESTED" \
            '{"reason":"nothing listening on 127.0.0.1:9050"}' \
            "false" "n/a" "" "UNTESTED"
    fi
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
    # _meta: makes a committed results.jsonl self-describing. `commit` is the
    # revision this run EXECUTED at (a file cannot contain the hash of the
    # commit that contains it — regenerate after verdict-affecting changes).
    # `schema` bumps only when the top-level record contract changes
    # (additive evidence keys do not — see SCHEMA.md).
    meta=$(jq -cn --arg generated "$ts" --arg commit "$rev" --arg mode "$MODE" \
        --arg host "$(uname -srm)" --arg tor_version "$torv" \
        --arg schema_url "tests/leak/SCHEMA.md" \
        '{id:"_meta",schema:2,generated:$generated,commit:$commit,mode:$mode,
          host:$host,tor_version:$tor_version,results_schema_url:$schema_url}')

    # Partial runs (--static / --dynamic) merge into the committed file by id
    # so a PR's static run can never destroy previously recorded dynamic
    # evidence. A full run replaces everything. _meta is always rewritten fresh.
    local tmp="$BUILD/records.jsonl"
    printf '%s\n' "${RECORDS[@]}" > "$tmp"
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
        printf '# TORX leak harness results\n\n'
        printf -- '- generated: `%s`\n- commit: `%s`\n- mode: `%s`\n- library: `%s`\n\n' \
            "$ts" "$rev" "$MODE" "$(basename "$LIB")"
        printf '| id | class | method | expected | observed | verdict | ci_gate |\n'
        printf '|---|---|---|---|---|---|---|\n'
        jq -r 'select(.id != "_meta")
               | [.id,.class,.method,.expected,.observed,.verdict,(.ci_gate|tostring)]|join("~")' "$JSONL" \
            | awk -F'~' '{printf "| `%s` | %s | %s | %s | **%s** | %s | %s |\n",$1,$2,$3,$4,$5,$6,$7}'
        printf '\nVerdicts: `VERIFIED` matches expectation · `REFUTED` expectation broken · '
        printf '`UNTESTED` could not run (see notes) · `FLAKY` inconsistent.\n\n'
        printf '`UNTESTED` is a claim of absence of test, never a claim of correctness.\n'
    } > "$MARKDOWN"

    # Gate: ci_gate rows must still match their documented verdict.
    local fails=0 id v ev
    while IFS=$'\t' read -r id v ev; do
        [ "$v" = "UNTESTED" ] && continue
        if [ "$v" != "$ev" ]; then
            printf 'GATE VIOLATION: %s documented %s, observed %s\n' "$id" "$ev" "$v" >&2
            printf '  -> update LIMITATIONS.md + expected_verdict if intentional\n' >&2
            fails=1
        fi
    done < <(jq -r 'select(.ci_gate) | [.id,.verdict,.expected_verdict]|join("\t")' "$JSONL")

    printf '\n'
    jq -r 'select(.id != "_meta") | "  \(.verdict|lpad(8;." "))  \(.id)"' "$JSONL" 2>/dev/null \
        || jq -r 'select(.id != "_meta") | "  \(.verdict)  \(.id)"' "$JSONL"
    printf '\n%d rows -> %s, %s\n' "${#RECORDS[@]}" \
        "${JSONL#"$ROOT"/}" "${MARKDOWN#"$ROOT"/}"

    [ "$fails" -eq 0 ] || exit 1
}

case "$MODE" in
    static)  run_static ;;
    dynamic) run_dynamic ;;
    both)    run_static; run_dynamic ;;
esac
finalize
