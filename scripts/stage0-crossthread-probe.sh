#!/usr/bin/env bash
#
# Stage 0 cross-thread correlation measurement harness.
#
# Empirically validates the assumptions in
# docs/design-cross-thread-correlation.md BEFORE any bridge implementation
# ships. It attaches READ-ONLY bpftrace uprobes to a live MicroCeph radosgw
# and measures, against the design's Stage 0 gates:
#
#   (a) Coverage ceiling  - fraction of Objecter::_send_op calls whose TID was
#                           seeded by a rgw_process_authenticated entry on the
#                           same TID within the last 1s.
#   (b) Key match         - whether the req_state* seen at rgw_process_authenticated
#                           equals a req_state* seen at RGWREST::get_handler
#                           (pointer equality, per request, within 1s).
#   (c) [A1]              - whether _send_op runs on the same thread that ran
#                           rgw_process_authenticated (count unseeded = tid-hop
#                           or background).
#   (d) [A3]              - whether the req_state* parameter is register-located
#                           and holds a plausible heap pointer at function entry
#                           (see the documented limitation below and in the runbook).
#   (e) Residual risk     - fraction of _send_op whose TID's most recent seed is
#                           stale (> STALE_MS ago), bucketed by age; old seeds
#                           indicate lingering-context mis-correlation risk.
#
# SAFETY: this harness only *reads* registers and userspace memory via uprobes.
# It never writes to the traced process, uses no kernel-version-fragile probes,
# and periodically clears its bpftrace maps to keep them bounded.
#
# This script creates and runs a bpftrace program; it does not modify rgwtrace,
# the RGW process, or any repository file.
#
# ---------------------------------------------------------------------------
# Environment overrides (all optional):
#
#   RGW_PID                 radosgw PID to scope uprobes to (auto-discovered).
#                           Set RGW_PID=0 to attach process-wide (not scoped).
#   RADOSGW_PATH            path to the radosgw executable (auto-discovered).
#   LIBCEPH_COMMON_PATH     path to libceph-common.so.* (auto-discovered).
#
#   STAGE0_DURATION         run duration in seconds (default 60; Ctrl-C also stops).
#   STAGE0_STALE_MS         "stale seed" threshold in ms for metric (e) (default 50).
#   STAGE0_OUTDIR           where to write the generated program + log
#                           (default: a fresh private mktemp -d directory).
#                           A supplied directory must be owned by the current
#                           user and not group/other writable (it is created
#                           with mode 0700 if it does not exist yet).
#
#   RGW_GET_HANDLER_SYM     override the mangled symbol for RGWREST::get_handler.
#   RGW_PROC_AUTH_SYM       override the mangled symbol for rgw_process_authenticated.
#   RGW_SEND_OP_SYM         override the mangled symbol for Objecter::_send_op.
#
#   RGW_GET_HANDLER_ARG     override the bpftrace arg index for get_handler's
#                           req_state* (default: auto-derived, expected 2).
#   RGW_PROC_AUTH_ARG       override the bpftrace arg index for
#                           rgw_process_authenticated's req_state* (default:
#                           auto-derived, expected 3 = "4th parameter").
#
#   STAGE0_COVERAGE_GATE    coverage PASS threshold % (default 90 single-stream).
#   STAGE0_KEYMATCH_GATE    key-match PASS threshold % (default 99, "~100%").
#   STAGE0_A3_GATE          [A3] plausible-pointer PASS threshold % (default 99).
#
#   STAGE0_DRY_RUN=1        resolve symbols and generate the program, but do not
#                           run bpftrace (useful without a live RGW).
# ---------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=scripts/lib/private-dir.sh
. "${SCRIPT_DIR}/lib/private-dir.sh"

PATH="/snap/bin:${PATH}"

# The generated program is executed by a privileged bpftrace; nothing this
# script writes may be readable or plantable by other local users.
umask 077

# --- configuration ---------------------------------------------------------
STAGE0_DURATION="${STAGE0_DURATION:-60}"
STAGE0_STALE_MS="${STAGE0_STALE_MS:-50}"
STAGE0_OUTDIR="${STAGE0_OUTDIR:-$(rgwtrace_private_tmpdir rgwtrace-stage0)}"
STAGE0_COVERAGE_GATE="${STAGE0_COVERAGE_GATE:-90}"
STAGE0_KEYMATCH_GATE="${STAGE0_KEYMATCH_GATE:-99}"
STAGE0_A3_GATE="${STAGE0_A3_GATE:-99}"
STAGE0_DRY_RUN="${STAGE0_DRY_RUN:-0}"

# Plausible userspace heap/mmap pointer window on x86-64 (128TiB user split).
PTR_MIN="0x10000"
PTR_MAX="0x800000000000"

# Design-derived expectations. get_handler is a NON-STATIC MEMBER of RGWREST,
# so bpftrace arg0 == `this` and the source parameters shift by 1.
# rgw_process_authenticated is a FREE function, so no `this` shift.
GH_DEMANGLED_NAME="RGWREST::get_handler"
GH_IDENT="get_handler"
GH_THIS_OFFSET=1
GH_EXPECTED_ARG=2

PA_DEMANGLED_NAME="rgw_process_authenticated"
PA_IDENT="rgw_process_authenticated"
PA_THIS_OFFSET=0
PA_EXPECTED_ARG=3

SEND_DEMANGLED_NAME="Objecter::_send_op"
SEND_IDENT="_send_op"

info()  { printf '[stage0] %s\n'  "$*"; }
warn()  { printf '[stage0][WARN] %s\n' "$*" >&2; }
err()   { printf '[stage0][ERROR] %s\n' "$*" >&2; }
die()   { err "$*"; exit 1; }

require_root() {
    if [[ "${EUID}" -ne 0 && "${STAGE0_DRY_RUN}" != "1" ]]; then
        die "must run as root (uprobes require CAP_BPF/CAP_PERFMON); re-run with sudo, or set STAGE0_DRY_RUN=1"
    fi
}

require_tools() {
    local missing=()
    for t in nm objdump c++filt; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if (( ${#missing[@]} )); then
        die "missing required tools: ${missing[*]} (install binutils)"
    fi
    if ! command -v bpftrace >/dev/null 2>&1; then
        if [[ "${STAGE0_DRY_RUN}" == "1" ]]; then
            warn "bpftrace not found; STAGE0_DRY_RUN=1 so continuing (program will be generated but not run)"
        else
            die "bpftrace not found; install bpftrace (>= 0.14 recommended) or set STAGE0_DRY_RUN=1"
        fi
    fi
}

# --- target discovery ------------------------------------------------------

discover_pid() {
    if [[ -n "${RGW_PID:-}" ]]; then
        return 0
    fi
    local pid exe
    for pid in $(pgrep -f radosgw 2>/dev/null || true); do
        [[ -r "/proc/${pid}/maps" ]] || continue
        exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
        [[ "${exe}" == *radosgw* || "${exe}" == *ceph-radosgw* ]] || continue
        if grep -q 'librados.so.2' "/proc/${pid}/maps" 2>/dev/null; then
            RGW_PID="${pid}"
            return 0
        fi
    done
    RGW_PID=""
    return 0
}

discover_radosgw_path() {
    if [[ -n "${RADOSGW_PATH:-}" ]]; then
        [[ -r "${RADOSGW_PATH}" ]] || die "RADOSGW_PATH=${RADOSGW_PATH} is not readable"
        return 0
    fi
    if [[ -n "${RGW_PID:-}" && "${RGW_PID}" != "0" ]]; then
        local exe
        exe="$(readlink "/proc/${RGW_PID}/exe" 2>/dev/null || true)"
        if [[ -n "${exe}" ]]; then
            # Resolve through the target's mount namespace root so we read the
            # same inode the process sees (mirrors rgwtrace --pid behaviour).
            if [[ -r "/proc/${RGW_PID}/root${exe}" ]]; then
                RADOSGW_PATH="/proc/${RGW_PID}/root${exe}"
            elif [[ -r "${exe}" ]]; then
                RADOSGW_PATH="${exe}"
            fi
        fi
    fi
    if [[ -z "${RADOSGW_PATH:-}" ]]; then
        local cand
        for cand in \
            /snap/microceph/current/usr/bin/radosgw \
            /usr/bin/radosgw \
            /usr/local/bin/radosgw; do
            [[ -r "${cand}" ]] && { RADOSGW_PATH="${cand}"; break; }
        done
    fi
    [[ -n "${RADOSGW_PATH:-}" && -r "${RADOSGW_PATH}" ]] || \
        die "could not locate the radosgw executable; set RADOSGW_PATH explicitly"
}

discover_libceph_common() {
    if [[ -n "${LIBCEPH_COMMON_PATH:-}" ]]; then
        [[ -r "${LIBCEPH_COMMON_PATH}" ]] || die "LIBCEPH_COMMON_PATH=${LIBCEPH_COMMON_PATH} is not readable"
        return 0
    fi
    if [[ -n "${RGW_PID:-}" && "${RGW_PID}" != "0" ]]; then
        local mapped
        mapped="$(grep -oE '/[^ ]*libceph-common\.so[^ ]*' "/proc/${RGW_PID}/maps" 2>/dev/null | sort -u | head -n1 || true)"
        if [[ -n "${mapped}" ]]; then
            if [[ -r "/proc/${RGW_PID}/root${mapped}" ]]; then
                LIBCEPH_COMMON_PATH="/proc/${RGW_PID}/root${mapped}"
            elif [[ -r "${mapped}" ]]; then
                LIBCEPH_COMMON_PATH="${mapped}"
            fi
        fi
    fi
    if [[ -z "${LIBCEPH_COMMON_PATH:-}" ]]; then
        local cand
        for cand in \
            /snap/microceph/current/usr/lib/*/ceph/libceph-common.so.* \
            /usr/lib/*/ceph/libceph-common.so.* \
            /usr/lib/ceph/libceph-common.so.*; do
            [[ -r "${cand}" ]] && { LIBCEPH_COMMON_PATH="${cand}"; break; }
        done
    fi
    [[ -n "${LIBCEPH_COMMON_PATH:-}" && -r "${LIBCEPH_COMMON_PATH}" ]] || \
        die "could not locate libceph-common.so; set LIBCEPH_COMMON_PATH explicitly"
}

# --- symbol resolution -----------------------------------------------------
#
# Mangled C++ names embed the identifier text literally (length-prefixed), so a
# cheap fixed-string grep finds candidates without demangling every symbol in a
# large binary. We then demangle only the candidates and filter to the exact
# function. Clones (.part/.constprop/[clone ...]) are skipped.

# Emit candidate mangled symbols containing $ident from $bin, trying .symtab,
# then .dynsym, then objdump -T.
list_candidate_symbols() {
    local bin="$1" ident="$2" raw=""
    raw="$(nm --defined-only "${bin}" 2>/dev/null | awk '{print $NF}' | grep -F -- "${ident}" | sort -u || true)"
    if [[ -z "${raw}" ]]; then
        raw="$(nm -D --defined-only "${bin}" 2>/dev/null | awk '{print $NF}' | grep -F -- "${ident}" | sort -u || true)"
    fi
    if [[ -z "${raw}" ]]; then
        raw="$(objdump -T "${bin}" 2>/dev/null | awk '{print $NF}' | grep -F -- "${ident}" | sort -u || true)"
    fi
    printf '%s\n' "${raw}"
}

# Resolve one function. Prints the chosen mangled symbol on stdout and the
# demangled signature on fd 3 (captured by the caller). Diagnostics go to
# stderr. Exits non-zero on no match.
#
# args: bin ident demangled_prefix
RESOLVED_SYM=""
RESOLVED_SIG=""
resolve_function() {
    local bin="$1" ident="$2" prefix="$3" override="${4:-}"
    RESOLVED_SYM=""
    RESOLVED_SIG=""

    if [[ -n "${override}" ]]; then
        RESOLVED_SYM="${override}"
        RESOLVED_SIG="$(printf '%s' "${override}" | c++filt || true)"
        info "using override symbol for ${prefix}: ${override}"
        info "  demangled: ${RESOLVED_SIG}"
        return 0
    fi

    local mangled demangled
    local -a matches=()
    local -a match_sigs=()
    while IFS= read -r mangled; do
        [[ -n "${mangled}" ]] || continue
        demangled="$(printf '%s' "${mangled}" | c++filt || true)"
        # Require the exact qualified name immediately followed by '(' and
        # exclude compiler clones.
        if [[ "${demangled}" == *"${prefix}("* && "${demangled}" != *"[clone "* ]]; then
            matches+=("${mangled}")
            match_sigs+=("${demangled}")
        fi
    done < <(list_candidate_symbols "${bin}" "${ident}")

    if (( ${#matches[@]} == 0 )); then
        err "no defined symbol for '${prefix}' found in ${bin}"
        err "  (binary may be stripped of .symtab/.dynsym; install matching debug symbols,"
        err "   or set the override env var for this function)"
        return 1
    fi

    if (( ${#matches[@]} > 1 )); then
        warn "${prefix}: ${#matches[@]} matching symbols (overloads/variants):"
        local i
        for i in "${!matches[@]}"; do
            warn "  [$i] ${match_sigs[$i]}"
        done
        warn "  -> picking [0]; set the override env var to choose a different one"
    fi

    RESOLVED_SYM="${matches[0]}"
    RESOLVED_SIG="${match_sigs[0]}"
    info "resolved ${prefix}:"
    info "  mangled  : ${RESOLVED_SYM}"
    info "  demangled: ${RESOLVED_SIG}"
    return 0
}

# --- el9 / embedded-Objecter pre-warning -----------------------------------
#
# When _send_op resolves in libceph-common, a HIDDEN private copy of Objecter
# embedded in librados.so may be the one that actually executes, so the uprobe
# would attach to dead code and report 0 _send_op calls with no hint why. If a
# librados.so mapped into the same process embeds Objecter (its source path
# 'osdc/Objecter.cc' shows up in the string table), warn at resolution time so
# the operator is not surprised by a silent zero. Best-effort and never fatal.
warn_if_embedded_objecter() {
    local send_bin="$1"
    # Only relevant when we attached to libceph-common's copy.
    [[ "${send_bin}" == "${LIBCEPH_COMMON_PATH}" ]] || return 0
    command -v strings >/dev/null 2>&1 || return 0

    local librados=""
    if [[ -n "${RGW_PID:-}" && "${RGW_PID}" != "0" ]]; then
        local mapped
        mapped="$(grep -oE '/[^ ]*librados\.so[^ ]*' "/proc/${RGW_PID}/maps" 2>/dev/null | sort -u | head -n1 || true)"
        if [[ -n "${mapped}" ]]; then
            if [[ -r "/proc/${RGW_PID}/root${mapped}" ]]; then
                librados="/proc/${RGW_PID}/root${mapped}"
            elif [[ -r "${mapped}" ]]; then
                librados="${mapped}"
            fi
        fi
    fi
    if [[ -z "${librados}" ]]; then
        local cand
        for cand in \
            "$(dirname "${LIBCEPH_COMMON_PATH}")"/librados.so.* \
            /usr/lib64/librados.so.* \
            /usr/lib/*/librados.so.*; do
            [[ -r "${cand}" ]] && { librados="${cand}"; break; }
        done
    fi
    [[ -n "${librados}" && -r "${librados}" ]] || return 0

    if strings -- "${librados}" 2>/dev/null | grep -qm1 'osdc/Objecter.cc'; then
        warn "resolved Objecter::_send_op in libceph-common, but ${librados} appears to embed a PRIVATE copy of Objecter (found 'osdc/Objecter.cc' in its strings)."
        warn "  On el9 Ceph builds that hidden Objecter is the one that actually executes; the libceph-common export can be dead code, so this uprobe may report 0 _send_op calls."
        warn "  If the summary shows 0 _send_op with nonzero process_authenticated, re-run with the executing copy:"
        warn "    LIBCEPH_COMMON_PATH=/proc/<pid>/root/usr/lib64/librados.so.2.0.0 (unstripped/debuginfo symtab; merge one with eu-unstrip if needed)."
    fi
}

# --- argument-index derivation ---------------------------------------------
#
# Parse a demangled signature, find which source parameter's type contains
# 'req_state', and print that 0-based source index. Balanced-<>()[] aware.
# Prints -1 if not found. python3 is already a hard dependency of the e2e rig.
reqstate_source_index() {
    local sig="$1"
    SIG_INPUT="${sig}" python3 - <<'PY'
import os, sys

sig = os.environ["SIG_INPUT"]

# Find the '(' that opens the parameter list: first '(' at angle-bracket depth 0.
depth_ang = 0
start = -1
for i, ch in enumerate(sig):
    if ch == '<':
        depth_ang += 1
    elif ch == '>':
        if depth_ang > 0:
            depth_ang -= 1
    elif ch == '(' and depth_ang == 0:
        start = i
        break
if start < 0:
    print(-1); sys.exit(0)

# Match the closing ')'.
depth = 0
end = -1
for i in range(start, len(sig)):
    ch = sig[i]
    if ch == '(':
        depth += 1
    elif ch == ')':
        depth -= 1
        if depth == 0:
            end = i
            break
if end < 0:
    print(-1); sys.exit(0)

inner = sig[start + 1:end].strip()
if not inner or inner == "void":
    print(-1); sys.exit(0)

# Split at top-level commas.
params = []
buf = []
d_ang = d_par = d_brk = 0
for ch in inner:
    if ch == '<': d_ang += 1
    elif ch == '>' and d_ang > 0: d_ang -= 1
    elif ch == '(': d_par += 1
    elif ch == ')' and d_par > 0: d_par -= 1
    elif ch == '[': d_brk += 1
    elif ch == ']' and d_brk > 0: d_brk -= 1
    if ch == ',' and d_ang == d_par == d_brk == 0:
        params.append(''.join(buf)); buf = []
    else:
        buf.append(ch)
if buf:
    params.append(''.join(buf))

for idx, p in enumerate(params):
    if 'req_state' in p:
        print(idx); sys.exit(0)

print(-1)
PY
}

# Derive & validate a bpftrace arg index. Sets DERIVED_ARG.
DERIVED_ARG=""
derive_arg() {
    local label="$1" sig="$2" this_offset="$3" expected="$4" override="$5"
    DERIVED_ARG=""

    local src_idx
    src_idx="$(reqstate_source_index "${sig}")"

    if [[ "${src_idx}" == "-1" ]]; then
        warn "${label}: could not locate a 'req_state' parameter in the demangled signature."
        warn "  falling back to the design-assumed arg index ${expected}. VERIFY MANUALLY."
        DERIVED_ARG="${expected}"
    else
        DERIVED_ARG=$(( src_idx + this_offset ))
        info "${label}: req_state is source parameter #${src_idx} (0-based); this-offset=${this_offset} => bpftrace arg${DERIVED_ARG}"
        if [[ "${DERIVED_ARG}" != "${expected}" ]]; then
            warn "${label}: derived arg${DERIVED_ARG} != design-assumed arg${expected}. The signature differs from the design's assumption -- eyeball it above."
        fi
    fi

    if [[ -n "${override}" ]]; then
        if [[ "${override}" != "${DERIVED_ARG}" ]]; then
            warn "${label}: env override arg${override} differs from derived arg${DERIVED_ARG}; using the override."
        fi
        DERIVED_ARG="${override}"
    fi
    info "${label}: using bpftrace arg${DERIVED_ARG} for req_state*"
}

# --- bpftrace program generation & run -------------------------------------

BT_PROGRAM=""

generate_program() {
    local gh_target="$1" pa_target="$2" send_target="$3"
    local gh_arg="$4" pa_arg="$5"
    local stale_ns=$(( STAGE0_STALE_MS * 1000000 ))

    # bpftrace runs this file as root: refuse an output directory another
    # user could have pre-created or planted symlinks in.
    rgwtrace_require_private_dir "${STAGE0_OUTDIR}" "STAGE0_OUTDIR" \
        || die "STAGE0_OUTDIR=${STAGE0_OUTDIR} is not a private directory; unset it to use a fresh mktemp -d directory"
    BT_PROGRAM="${STAGE0_OUTDIR}/stage0.bt"

    # NOTE: this bpftrace program deliberately uses NO bpftrace scratch ($)
    # variables, so it is safe to emit from an unquoted heredoc where the shell
    # substitutes ${...} target/arg/threshold values. It uses only portable
    # features (uprobe, argN, tid, nsecs, interval, clear, delete) to avoid
    # kernel-version fragility.
    cat > "${BT_PROGRAM}" <<EOF
/*
 * Stage 0 cross-thread correlation probe (generated by
 * scripts/stage0-crossthread-probe.sh -- do not edit by hand).
 * READ-ONLY: reads registers and userspace memory only; never writes to RGW.
 */

BEGIN
{
    printf("[stage0] probe attached; running for ${STAGE0_DURATION}s (Ctrl-C to stop early)\n");
    printf("[stage0] stale-seed threshold = ${STAGE0_STALE_MS}ms\n");
    @gh_calls   = 0;
    @pa_calls   = 0;
    @pa_keymatch = 0;
    @pa_keymiss  = 0;
    @pa_rsp_ok   = 0;
    @pa_rsp_bad  = 0;
    @send_total  = 0;
    @send_unseeded = 0;
    @send_fresh    = 0;
    @send_aging    = 0;
    @send_old      = 0;
    @elapsed = 0;
}

/* RGWREST::get_handler -- record the req_state* observed on the frontend thread. */
${gh_target}
{
    @gh_calls++;
    if (${gh_arg} >= ${PTR_MIN} && ${gh_arg} < ${PTR_MAX}) {
        @gh_seen[${gh_arg}] = nsecs;
    }
}

/* rgw_process_authenticated -- seed the submit thread, check key-match + [A3]. */
${pa_target}
{
    @pa_calls++;
    if (${pa_arg} >= ${PTR_MIN} && ${pa_arg} < ${PTR_MAX}) {
        @pa_rsp_ok++;
        if (@gh_seen[${pa_arg}] != 0 && (nsecs - @gh_seen[${pa_arg}]) < 1000000000) {
            @pa_keymatch++;
            delete(@gh_seen[${pa_arg}]);
        } else {
            @pa_keymiss++;
        }
        @seed[tid] = nsecs;
    } else {
        @pa_rsp_bad++;
    }
}

/* Objecter::_send_op -- classify each op by the freshness of its TID's seed. */
${send_target}
{
    @send_total++;
    if (@seed[tid] == 0) {
        @send_unseeded++;
    } else {
        if ((nsecs - @seed[tid]) <= ${stale_ns}) {
            @send_fresh++;
        } else {
            if ((nsecs - @seed[tid]) <= 1000000000) {
                @send_aging++;
            } else {
                @send_old++;
            }
        }
    }
}

interval:s:1
{
    @elapsed++;
    if (@elapsed >= ${STAGE0_DURATION}) {
        exit();
    }
}

/* Bound the get_handler pointer map: gh->process_authenticated gap is sub-second. */
interval:s:5
{
    clear(@gh_seen);
}

END
{
    clear(@gh_seen);
    clear(@seed);

    printf("\n");
    printf("======== STAGE 0 SUMMARY ========\n");
    printf("get_handler calls              : %d\n", @gh_calls);
    printf("process_authenticated calls    : %d\n", @pa_calls);
    printf("_send_op calls                 : %d\n", @send_total);
    printf("\n");

    /*
     * Dead-probe hazard: 0 _send_op while process_authenticated fired means the
     * _send_op uprobe is very likely attached to a NON-EXECUTING copy of
     * Objecter. On el9 Ceph builds librados.so embeds a HIDDEN private Objecter
     * (the one that actually runs) while libceph-common.so ALSO exports
     * Objecter::_send_op as dead code -- resolving there attaches successfully
     * yet observes nothing. Say so explicitly instead of reporting a silent 0.
     */
    if (@send_total == 0 && @pa_calls > 0) {
        printf("[stage0][WARNING] 0 _send_op but %d process_authenticated calls.\n", @pa_calls);
        printf("    The _send_op uprobe may be attached to a NON-EXECUTING copy of Objecter\n");
        printf("    (multiple DSOs can define Objecter::_send_op). On el9, librados.so embeds a\n");
        printf("    hidden private Objecter that actually runs, while libceph-common.so exports\n");
        printf("    _send_op as dead code.\n");
        printf("    Diagnose : strings <librados.so> | grep -m1 'osdc/Objecter.cc'\n");
        printf("               (a hit means librados carries its own Objecter).\n");
        printf("    Override : LIBCEPH_COMMON_PATH=/proc/<pid>/root/usr/lib64/librados.so.2.0.0\n");
        printf("               (needs an unstripped/debuginfo symtab; merge one with eu-unstrip).\n");
        printf("    See the 'el9 / embedded-Objecter' caveat in docs/stage0-runbook.md.\n");
        printf("\n");
    }

    /* (a) coverage ceiling: _send_op on a TID seeded within 1s. */
    if (@send_total > 0) {
        printf("(a) coverage ceiling      : %d%% seeded<=1s (%d/%d)  [gate >=${STAGE0_COVERAGE_GATE}%% single-stream, 80%% concurrent]\n",
            (100 * (@send_fresh + @send_aging)) / @send_total, @send_fresh + @send_aging, @send_total);
        if ((100 * (@send_fresh + @send_aging)) / @send_total >= ${STAGE0_COVERAGE_GATE}) {
            printf("    -> PASS\n");
        } else {
            printf("    -> FAIL (below single-stream gate; kills [A1]/[A2] coverage assumption if data-path ops dominate)\n");
        }
    } else {
        printf("(a) coverage ceiling      : INCONCLUSIVE (no _send_op observed -- run a workload)\n");
    }
    printf("\n");

    /* (b) key match: process_authenticated req_state* seen at get_handler. */
    if (@pa_calls > 0) {
        printf("(b) req_state key-match   : %d%% (%d/%d process_auth rsp seen at get_handler <1s)  [gate ~100%%]\n",
            (100 * @pa_keymatch) / @pa_calls, @pa_keymatch, @pa_calls);
        if ((100 * @pa_keymatch) / @pa_calls >= ${STAGE0_KEYMATCH_GATE}) {
            printf("    -> PASS\n");
        } else {
            printf("    -> FAIL/CHECK (misses at trace start are expected; sustained misses kill [A2] pointer identity)\n");
        }
    } else {
        printf("(b) req_state key-match   : INCONCLUSIVE (no process_authenticated calls)\n");
    }
    printf("\n");

    /* (c) [A1] thread contiguity: unseeded _send_op = tid-hop or background. */
    if (@send_total > 0) {
        printf("(c) [A1] tid contiguity   : %d%% _send_op on a seeded TID; %d unseeded (tid-hop OR background op)\n",
            (100 * (@send_total - @send_unseeded)) / @send_total, @send_unseeded);
        printf("    -> INFO: unseeded is a superset of tid-hops (includes GC/notify/startup ops).\n");
        printf("             Cross-check role via rgwtrace; a high data-path unseeded fraction would kill [A1].\n");
    } else {
        printf("(c) [A1] tid contiguity   : INCONCLUSIVE (no _send_op observed)\n");
    }
    printf("\n");

    /* (d) [A3] register-located req_state* pointer plausibility at entry. */
    if (@pa_calls > 0) {
        printf("(d) [A3] reg-located ptr  : %d%% plausible-heap req_state at entry (ok=%d bad=%d)  [gate >=${STAGE0_A3_GATE}%%]\n",
            (100 * @pa_rsp_ok) / @pa_calls, @pa_rsp_ok, @pa_rsp_bad);
        if ((100 * @pa_rsp_ok) / @pa_calls >= ${STAGE0_A3_GATE}) {
            printf("    -> PASS\n");
        } else {
            printf("    -> FAIL (null/implausible values suggest the param is not in the ABI register at entry -> kills [A3])\n");
        }
        printf("    NOTE: bpftrace argN reads the ABI arg register AT ENTRY; this checks non-null heap-plausible\n");
        printf("          values, NOT that DWARF marks the param register-located. A param already spilled to the\n");
        printf("          stack at entry would read a stack pointer (also in-range) -> confirm against rgwtrace\n");
        printf("          native DWARF extraction (see runbook metric (d)).\n");
    } else {
        printf("(d) [A3] reg-located ptr  : INCONCLUSIVE (no process_authenticated calls)\n");
    }
    printf("\n");

    /* (e) residual mis-correlation risk: seeded _send_op whose seed is stale. */
    if ((@send_fresh + @send_aging + @send_old) > 0) {
        printf("(e) residual mis-corr risk: %d%% of seeded _send_op seeded >${STAGE0_STALE_MS}ms ago (aging=%d, old>1s=%d)  [gate ~0%%]\n",
            (100 * (@send_aging + @send_old)) / (@send_fresh + @send_aging + @send_old), @send_aging, @send_old);
        if ((@send_aging + @send_old) == 0) {
            printf("    -> PASS\n");
        } else {
            printf("    -> WARN (lingering seeds = finding-#3 residual risk; must be ~0 before --correlate-cross-thread)\n");
        }
    } else {
        printf("(e) residual mis-corr risk: INCONCLUSIVE (no seeded _send_op observed)\n");
    }
    printf("=================================\n");

    clear(@gh_calls); clear(@pa_calls); clear(@pa_keymatch); clear(@pa_keymiss);
    clear(@pa_rsp_ok); clear(@pa_rsp_bad); clear(@send_total); clear(@send_unseeded);
    clear(@send_fresh); clear(@send_aging); clear(@send_old); clear(@elapsed);
}
EOF

    info "generated bpftrace program: ${BT_PROGRAM}"
}

parse_check_program() {
    command -v bpftrace >/dev/null 2>&1 || return 0
    # -d dumps the compiled program and exits without attaching (best-effort
    # parse/type check). Older/newer bpftrace differ on the -d argument form;
    # tolerate either and never fail the harness on the check alone.
    if bpftrace -d ast "${BT_PROGRAM}" >/dev/null 2>&1 \
        || bpftrace -d "${BT_PROGRAM}" >/dev/null 2>&1; then
        info "bpftrace parse-check OK"
    else
        warn "bpftrace parse-check did not confirm (version-dependent -d flag); the run below is authoritative"
    fi
}

run_program() {
    local -a bt_args=()
    if [[ -n "${RGW_PID:-}" && "${RGW_PID}" != "0" ]]; then
        bt_args+=(-p "${RGW_PID}")
        info "scoping uprobes to radosgw PID ${RGW_PID}"
    else
        warn "no PID scope (RGW_PID=0 or none discovered); attaching process-wide by binary path"
    fi

    local log="${STAGE0_OUTDIR}/stage0.log"
    info "running bpftrace (output tee'd to ${log})"
    info "-------------------------------------------------------------"
    bpftrace "${bt_args[@]}" "${BT_PROGRAM}" 2>&1 | tee "${log}"
    info "-------------------------------------------------------------"
    info "done; summary and full log are in ${log}"
}

# --- main ------------------------------------------------------------------

main() {
    require_root
    require_tools

    discover_pid
    discover_radosgw_path
    discover_libceph_common

    info "radosgw executable : ${RADOSGW_PATH}"
    info "libceph-common     : ${LIBCEPH_COMMON_PATH}"
    if [[ -n "${RGW_PID:-}" && "${RGW_PID}" != "0" ]]; then
        info "radosgw PID        : ${RGW_PID}"
    else
        warn "radosgw PID        : (none discovered; run may be process-wide)"
    fi

    # Resolve the three symbols.
    resolve_function "${RADOSGW_PATH}" "${GH_IDENT}" "${GH_DEMANGLED_NAME}" "${RGW_GET_HANDLER_SYM:-}" \
        || die "failed to resolve ${GH_DEMANGLED_NAME}"
    local gh_sym="${RESOLVED_SYM}" gh_sig="${RESOLVED_SIG}"

    resolve_function "${RADOSGW_PATH}" "${PA_IDENT}" "${PA_DEMANGLED_NAME}" "${RGW_PROC_AUTH_SYM:-}" \
        || die "failed to resolve ${PA_DEMANGLED_NAME} (required for the whole design -- if absent, [A2] is already dead)"
    local pa_sym="${RESOLVED_SYM}" pa_sig="${RESOLVED_SIG}"

    # _send_op lives in libceph-common; fall back to the radosgw binary.
    if ! resolve_function "${LIBCEPH_COMMON_PATH}" "${SEND_IDENT}" "${SEND_DEMANGLED_NAME}" "${RGW_SEND_OP_SYM:-}"; then
        warn "Objecter::_send_op not found in libceph-common; trying the radosgw binary"
        resolve_function "${RADOSGW_PATH}" "${SEND_IDENT}" "${SEND_DEMANGLED_NAME}" "${RGW_SEND_OP_SYM:-}" \
            || die "failed to resolve ${SEND_DEMANGLED_NAME}"
        SEND_BIN="${RADOSGW_PATH}"
    else
        SEND_BIN="${LIBCEPH_COMMON_PATH}"
    fi
    local send_sym="${RESOLVED_SYM}"

    # el9 dead-probe hazard: warn now if librados.so embeds its own Objecter.
    warn_if_embedded_objecter "${SEND_BIN}"

    # Derive & validate arg indices from the demangled signatures.
    derive_arg "${GH_DEMANGLED_NAME}" "${gh_sig}" "${GH_THIS_OFFSET}" "${GH_EXPECTED_ARG}" "${RGW_GET_HANDLER_ARG:-}"
    local gh_arg="arg${DERIVED_ARG}"

    derive_arg "${PA_DEMANGLED_NAME}" "${pa_sig}" "${PA_THIS_OFFSET}" "${PA_EXPECTED_ARG}" "${RGW_PROC_AUTH_ARG:-}"
    local pa_arg="arg${DERIVED_ARG}"

    # Build uprobe targets.
    local gh_target="uprobe:${RADOSGW_PATH}:${gh_sym}"
    local pa_target="uprobe:${RADOSGW_PATH}:${pa_sym}"
    local send_target="uprobe:${SEND_BIN}:${send_sym}"

    generate_program "${gh_target}" "${pa_target}" "${send_target}" "${gh_arg}" "${pa_arg}"
    parse_check_program

    if [[ "${STAGE0_DRY_RUN}" == "1" ]]; then
        info "STAGE0_DRY_RUN=1: not running bpftrace. Inspect ${BT_PROGRAM}."
        return 0
    fi

    run_program
}

main "$@"
