#!/usr/bin/env bash
#
# Macro A/B overhead benchmark for rgwtrace against a live RGW.
#
# Measures the real end-to-end cost of attaching rgwtrace to a running radosgw
# by driving a fixed S3 workload under several tracing "arms" and comparing
# client-side latency/throughput plus radosgw and rgwtrace process CPU/RSS:
#
#   A  baseline            tracing OFF
#   B  traced_default      rgwtrace attached, default flags
#   C  traced_cross_thread rgwtrace attached with --correlate-cross-thread
#   D  traced_inferred     C plus --correlate-inferred   (only with --with-inferred)
#
# Phases are interleaved A,B,A,C[,A,D] and that block is repeated R times
# (default 3) so cache warm-up and slow drift are shared across arms rather than
# biasing one. Samples are pooled per arm at the end.
#
# This script must run on the MicroCeph/RGW host (root, radosgw present). Use
# --dry-run to print the full execution plan without touching any cluster; the
# dry-run path needs neither root nor a running radosgw and is how the script is
# validated off-cluster.
#
# ---------------------------------------------------------------------------
# Metrics per phase:
#   * client latency p50/p95/p99 + throughput   (from s3-workload.py --summary)
#   * radosgw CPU-seconds delta                  (/proc/<pid>/stat utime+stime)
#   * radosgw RSS before/after + peak VmHWM      (/proc/<pid>/status)
#   * rgwtrace CPU-seconds + peak VmHWM          (traced arms only)
#   * rgwtrace diagnostics drop counters         (trace.diagnostics in JSON out)
# ---------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PATH="/snap/bin:${PATH}"

# --- defaults (all overridable via flags) ----------------------------------
REQUESTS="${REQUESTS:-200}"
CONCURRENCY="${CONCURRENCY:-4}"
OBJECT_SIZE="${OBJECT_SIZE:-4096}"
PUT_FRACTION="${PUT_FRACTION:-0.5}"
REPEATS="${REPEATS:-3}"
WARMUP_REQUESTS="${WARMUP_REQUESTS:-50}"
WITH_INFERRED=0
INFERENCE_WINDOW="${INFERENCE_WINDOW:-2}"
ATTACH_DELAY="${ATTACH_DELAY:-6}"
TRACE_SAFETY_TIMEOUT="${TRACE_SAFETY_TIMEOUT:-900}"
DRY_RUN=0
SECRET_ON_ARGV=0

ENDPOINT="${RGW_ENDPOINT:-http://127.0.0.1:8080}"
# No well-known default credentials. Read from the environment (RGW_* first
# for symmetry with the e2e test, then the standard AWS_* names); they are
# handed to s3-workload.py through AWS_* env vars, never on its argv.
ACCESS_KEY="${RGW_ACCESS_KEY:-${AWS_ACCESS_KEY_ID:-}}"
SECRET_KEY="${RGW_SECRET_KEY:-${AWS_SECRET_ACCESS_KEY:-}}"

RGWTRACE_BIN="${RGWTRACE_BIN:-${PROJECT_ROOT}/target/release/rgwtrace}"
RGWTRACE_DWARF_JSON="${RGWTRACE_DWARF_JSON:-}"
CEPH_VERSION="${CEPH_VERSION:-}"
RGW_PID="${RGW_PID:-}"

OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_ROOT}/bench-results}"
WORKLOAD_PY="${SCRIPT_DIR}/../tests/e2e/s3-workload.py"

CLK_TCK=""
RUN_STAMP=""
RAW_DIR=""
SUMMARY_JSON=""
SEQ=0
TRACE_PID=""
SCRIPT_INVALID=0

info() { printf '[bench] %s\n' "$*"; }
warn() { printf '[bench][WARN] %s\n' "$*" >&2; }
err()  { printf '[bench][ERROR] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<'USAGE'
Usage: bench-rgw-ab.sh [options]

Workload:
  --requests N         measured PUT/GET requests per phase        (default 200)
  --concurrency C      concurrent client workers                  (default 4)
  --object-size BYTES  object payload size                        (default 4096)
  --put-fraction F     fraction of requests that are PUTs (0..1)  (default 0.5)
  --warmup-requests N  unmeasured warm-up requests before phases  (default 50)

Arms / scheduling:
  --repeats R          interleaved A,B,A,C[,A,D] blocks           (default 3)
  --with-inferred      add arm D (--correlate-inferred)
  --inference-window S inference window seconds for arm D         (default 2)

Target / tracing:
  --endpoint URL       S3 endpoint            (default http://127.0.0.1:8080)
  --access-key KEY     S3 access key    (prefer env RGW_ACCESS_KEY / AWS_ACCESS_KEY_ID)
  --secret-key KEY     S3 secret key    (prefer env RGW_SECRET_KEY / AWS_SECRET_ACCESS_KEY;
                       a flag value is visible to every local user via ps)
  --rgwtrace-bin PATH  rgwtrace binary        (default target/release/rgwtrace)
  --dwarf-json PATH    use imported DWARF JSON instead of native extraction
  --ceph-version V     pass --ceph-version to rgwtrace (native mode)
  --pid PID            radosgw PID to trace   (default: auto-discover)
  --attach-delay S     seconds to wait after attach before workload (default 6)

Output:
  --output-dir DIR     raw results + summary  (default bench-results/)
  --dry-run            print the execution plan; touch no cluster, no root
  -h, --help           show this help
USAGE
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --requests)         REQUESTS="$2"; shift 2 ;;
            --concurrency)      CONCURRENCY="$2"; shift 2 ;;
            --object-size)      OBJECT_SIZE="$2"; shift 2 ;;
            --put-fraction)     PUT_FRACTION="$2"; shift 2 ;;
            --warmup-requests)  WARMUP_REQUESTS="$2"; shift 2 ;;
            --repeats)          REPEATS="$2"; shift 2 ;;
            --with-inferred)    WITH_INFERRED=1; shift ;;
            --inference-window) INFERENCE_WINDOW="$2"; shift 2 ;;
            --endpoint)         ENDPOINT="$2"; shift 2 ;;
            --access-key)       ACCESS_KEY="$2"; shift 2 ;;
            --secret-key)       SECRET_KEY="$2"; SECRET_ON_ARGV=1; shift 2 ;;
            --rgwtrace-bin)     RGWTRACE_BIN="$2"; shift 2 ;;
            --dwarf-json)       RGWTRACE_DWARF_JSON="$2"; shift 2 ;;
            --ceph-version)     CEPH_VERSION="$2"; shift 2 ;;
            --pid)              RGW_PID="$2"; shift 2 ;;
            --attach-delay)     ATTACH_DELAY="$2"; shift 2 ;;
            --output-dir)       OUTPUT_DIR="$2"; shift 2 ;;
            --dry-run)          DRY_RUN=1; shift ;;
            -h|--help)          usage; exit 0 ;;
            *) die "unknown argument: $1 (use --help)" ;;
        esac
    done
}

cleanup() {
    local rc=$?
    if [[ -n "${TRACE_PID}" ]]; then
        kill -INT "${TRACE_PID}" 2>/dev/null || true
        sleep 1
        kill "${TRACE_PID}" 2>/dev/null || true
    fi
    if [[ "${DRY_RUN}" != "1" && -n "${RGWTRACE_BIN}" ]]; then
        pkill -f "${RGWTRACE_BIN}" 2>/dev/null || true
    fi
    if [[ -n "${RAW_DIR}" && "${DRY_RUN}" != "1" ]]; then
        info "raw results preserved in ${OUTPUT_DIR}"
    fi
    exit "${rc}"
}
trap cleanup EXIT

# --- dwarf-source arg selection (mirrors tests/e2e conventions) ------------
dwarf_args() {
    if [[ -n "${RGWTRACE_DWARF_JSON}" ]]; then
        printf '%s\0%s\0%s\0' "--dwarf-source" "json" "--import-json"
        printf '%s\0' "${RGWTRACE_DWARF_JSON}"
    else
        printf '%s\0%s\0' "--dwarf-source" "native"
        if [[ -n "${CEPH_VERSION}" ]]; then
            printf '%s\0%s\0' "--ceph-version" "${CEPH_VERSION}"
        fi
    fi
}

# Read utime+stime (clock ticks) for a pid, robust against a comm with spaces.
proc_cpu_ticks() {
    local pid="$1" stat rest
    stat="$(cat "/proc/${pid}/stat" 2>/dev/null)" || return 1
    rest="${stat#*) }"
    # After stripping "PID (comm) ", field 1 is 'state'; utime=field14, stime=field15,
    # i.e. positions 12 and 13 of what remains.
    # shellcheck disable=SC2086
    set -- $rest
    printf '%s %s\n' "${12}" "${13}"
}

proc_status_kb() {
    local pid="$1" field="$2"
    awk -v f="${field}:" '$1==f {print $2; exit}' "/proc/${pid}/status" 2>/dev/null || true
}

cpu_seconds() {
    local u="$1" s="$2"
    awk -v u="${u}" -v s="${s}" -v t="${CLK_TCK}" 'BEGIN { printf "%.3f", (u + s) / t }'
}

find_rgw_pid() {
    local pid exe
    for pid in $(pgrep -f radosgw 2>/dev/null || true); do
        [[ -r "/proc/${pid}/maps" ]] || continue
        exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
        [[ "${exe}" == *radosgw* || "${exe}" == *ceph-radosgw* ]] || continue
        if grep -q 'librados.so.2' "/proc/${pid}/maps" 2>/dev/null; then
            printf '%s\n' "${pid}"
            return 0
        fi
    done
    return 1
}

arm_label() {
    case "$1" in
        baseline)            echo "A baseline (tracing off)" ;;
        traced_default)      echo "B rgwtrace default" ;;
        traced_cross_thread) echo "C rgwtrace --correlate-cross-thread" ;;
        traced_inferred)     echo "D rgwtrace --correlate-cross-thread --correlate-inferred" ;;
        *)                   echo "$1" ;;
    esac
}

# Build the rgwtrace argv for a traced arm into the global RGWTRACE_CMD array.
build_trace_cmd() {
    local arm="$1" pid="$2"
    local -a dargs=()
    local token
    while IFS= read -r -d '' token; do dargs+=("${token}"); done < <(dwarf_args)

    RGWTRACE_CMD=("${RGWTRACE_BIN}" "${dargs[@]}"
        --pid "${pid}"
        --output json
        --service-name rgwtrace-bench
        --timeout "${TRACE_SAFETY_TIMEOUT}")
    case "${arm}" in
        traced_cross_thread) RGWTRACE_CMD+=(--correlate-cross-thread) ;;
        traced_inferred)     RGWTRACE_CMD+=(--correlate-cross-thread --correlate-inferred --inference-window "${INFERENCE_WINDOW}") ;;
    esac
}

# Build the s3-workload.py argv into the global WORKLOAD_CMD array.
#   phase = all|prepare|run|cleanup
build_workload_cmd() {
    local phase="$1" requests="$2" jsonl="$3" summary="$4" state="$5"
    # Credentials reach the workload via AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
    # (exported in main), so they never appear in this argv or in --dry-run.
    WORKLOAD_CMD=(python3 "${WORKLOAD_PY}"
        --endpoint "${ENDPOINT}"
        --requests "${requests}"
        --concurrent-requests "${CONCURRENCY}"
        --object-size "${OBJECT_SIZE}"
        --put-fraction "${PUT_FRACTION}"
        --bench-phase "${phase}"
        --bench-state "${state}"
        --output "${jsonl}")
    case "${phase}" in
        run|all) WORKLOAD_CMD+=(--summary "${summary}") ;;
    esac
}

# Print an argv for --dry-run. Credential flag values are redacted so a plan
# pasted into a ticket or log never carries a key, whatever the argv holds.
print_cmd() {
    local prefix="$1"; shift
    printf '%s' "${prefix}"
    local arg redact_next=0
    for arg in "$@"; do
        if [[ "${redact_next}" -eq 1 ]]; then
            printf ' %q' "<redacted>"
            redact_next=0
            continue
        fi
        case "${arg}" in
            --secret-key|--access-key) printf ' %q' "${arg}"; redact_next=1 ;;
            --secret-key=*|--access-key=*) printf ' %q' "${arg%%=*}=<redacted>" ;;
            *) printf ' %q' "${arg}" ;;
        esac
    done
    printf '\n'
}

# Lightweight validity check of a trace JSON: file present, parseable, has a
# diagnostics block. Returns 0 (valid) / 1 (invalid).
trace_json_valid() {
    local path="$1"
    [[ -s "${path}" ]] || return 1
    python3 - "${path}" <<'PY' 2>/dev/null
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        doc = json.load(handle)
except (OSError, ValueError):
    sys.exit(1)
trace = doc.get("trace", doc)
sys.exit(0 if isinstance(trace, dict) and isinstance(trace.get("diagnostics"), dict) else 1)
PY
}

run_phase() {
    local arm="$1" repeat="$2"
    SEQ=$((SEQ + 1))
    local seq_padded
    seq_padded="$(printf '%03d' "${SEQ}")"
    local base="${RAW_DIR}/${seq_padded}-${arm}"
    local trace_json="${base}.trace.json"
    local trace_log="${base}.rgwtrace.log"
    local workload_jsonl="${base}.workload.jsonl"
    local workload_summary="${base}.workload.json"
    local workload_log="${base}.workload.log"
    local state="${base}.state.json"
    local meta="${base}.meta.json"

    local traced=0
    [[ "${arm}" != "baseline" ]] && traced=1

    [[ "${traced}" -eq 1 ]] && build_trace_cmd "${arm}" "${RGW_PID}"

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf -- '--- phase %s : %s  (repeat %s) ---\n' "${seq_padded}" "$(arm_label "${arm}")" "${repeat}"
        if [[ "${traced}" -eq 1 ]]; then
            print_cmd "  start(bg):" "${RGWTRACE_CMD[@]}"
            printf '             > %s 2> %s   (then settle %ss)\n' "${trace_json}" "${trace_log}" "${ATTACH_DELAY}"
        else
            printf '  (no tracer attached)\n'
        fi
        build_workload_cmd prepare "${REQUESTS}" "${workload_jsonl}" "${workload_summary}" "${state}"
        print_cmd "  prepare:" "${WORKLOAD_CMD[@]}"
        printf '  sample:    radosgw stat/RSS + rgwtrace stat (BEFORE measured window)\n'
        build_workload_cmd run "${REQUESTS}" "${workload_jsonl}" "${workload_summary}" "${state}"
        print_cmd "  run:     " "${WORKLOAD_CMD[@]}"
        printf '  sample:    radosgw stat/RSS/VmHWM + rgwtrace stat/VmHWM (AFTER)\n'
        printf '             -> radosgw CPU delta + collector CPU delta over measured window only\n'
        build_workload_cmd cleanup "${REQUESTS}" "${workload_jsonl}" "${workload_summary}" "${state}"
        print_cmd "  cleanup: " "${WORKLOAD_CMD[@]}"
        if [[ "${traced}" -eq 1 ]]; then
            printf '  stop:      SIGINT rgwtrace to flush JSON; check exit + validate %s\n' "${trace_json}"
            printf '  collect:   trace.diagnostics drop counters\n'
        fi
        printf '  write:     %s\n' "${meta}"
        return 0
    fi

    local valid=1 reason=""

    # --- attach tracer (settle sleep is OUTSIDE the measured CPU window) -------
    if [[ "${traced}" -eq 1 ]]; then
        "${RGWTRACE_CMD[@]}" >"${trace_json}" 2>"${trace_log}" &
        TRACE_PID=$!
        sleep "${ATTACH_DELAY}"
        if ! kill -0 "${TRACE_PID}" 2>/dev/null; then
            warn "rgwtrace exited during attach for arm ${arm}; see ${trace_log}"
            wait "${TRACE_PID}" 2>/dev/null || true
            TRACE_PID=""
            write_phase_meta "${meta}" "${arm}" "${repeat}" "${traced}" \
                0 0 0 0 null null null "${workload_summary}" "" false "attach_failed"
            SCRIPT_INVALID=1
            return 0
        fi
    fi

    # --- prepare (create + seed): unmeasured -----------------------------------
    build_workload_cmd prepare "${REQUESTS}" "${workload_jsonl}" "${workload_summary}" "${state}"
    if ! "${WORKLOAD_CMD[@]}" >"${workload_log}" 2>&1; then
        warn "prepare failed for arm ${arm}; see ${workload_log}"
        stop_tracer
        write_phase_meta "${meta}" "${arm}" "${repeat}" "${traced}" \
            0 0 0 0 null null null "${workload_summary}" "" false "prepare_failed"
        SCRIPT_INVALID=1
        return 0
    fi

    # --- sample BEFORE the measured window -------------------------------------
    local rgw_u0 rgw_s0 rgw_rss0 tr_u0=0 tr_s0=0
    read -r rgw_u0 rgw_s0 < <(proc_cpu_ticks "${RGW_PID}")
    rgw_rss0="$(proc_status_kb "${RGW_PID}" VmRSS)"
    if [[ "${traced}" -eq 1 ]]; then
        read -r tr_u0 tr_s0 < <(proc_cpu_ticks "${TRACE_PID}")
    fi

    # --- measured run ----------------------------------------------------------
    info "phase ${seq_padded} ${arm}: driving ${REQUESTS} requests"
    build_workload_cmd run "${REQUESTS}" "${workload_jsonl}" "${workload_summary}" "${state}"
    if ! "${WORKLOAD_CMD[@]}" >>"${workload_log}" 2>&1; then
        warn "measured run failed for arm ${arm}; see ${workload_log}"
        valid=0
        reason="run_failed"
    fi

    # --- sample AFTER the measured window --------------------------------------
    local rgw_u1 rgw_s1 rgw_rss1 rgw_hwm
    read -r rgw_u1 rgw_s1 < <(proc_cpu_ticks "${RGW_PID}")
    rgw_rss1="$(proc_status_kb "${RGW_PID}" VmRSS)"
    rgw_hwm="$(proc_status_kb "${RGW_PID}" VmHWM)"
    local rgw_cpu
    rgw_cpu="$(cpu_seconds "$((rgw_u1 - rgw_u0 + rgw_s1 - rgw_s0))" 0)"

    local tr_cpu=null tr_life=null tr_hwm=null
    if [[ "${traced}" -eq 1 ]]; then
        if kill -0 "${TRACE_PID}" 2>/dev/null; then
            local tr_u1 tr_s1
            read -r tr_u1 tr_s1 < <(proc_cpu_ticks "${TRACE_PID}")
            # Collector CPU over the measured window only (delta), plus lifetime
            # (includes DWARF extraction, BPF load/attach, and the settle sleep).
            tr_cpu="$(cpu_seconds "$((tr_u1 - tr_u0 + tr_s1 - tr_s0))" 0)"
            tr_life="$(cpu_seconds "$((tr_u1 + tr_s1))" 0)"
            tr_hwm="$(proc_status_kb "${TRACE_PID}" VmHWM)"
            tr_hwm="${tr_hwm:-null}"
        else
            warn "rgwtrace exited mid-run for arm ${arm}; see ${trace_log}"
            valid=0
            reason="tracer_died_mid_run"
        fi
    fi

    # --- cleanup: unmeasured ---------------------------------------------------
    build_workload_cmd cleanup "${REQUESTS}" "${workload_jsonl}" "${workload_summary}" "${state}"
    "${WORKLOAD_CMD[@]}" >>"${workload_log}" 2>&1 || warn "cleanup failed for arm ${arm}; see ${workload_log}"

    # --- stop + validate tracer capture ----------------------------------------
    local trace_field=""
    if [[ "${traced}" -eq 1 ]]; then
        trace_field="${trace_json}"
        local rc=0
        stop_tracer || rc=$?
        # SIGINT flush exits 0 or 130 (128+SIGINT); 143 covers our fallback SIGTERM.
        if [[ "${rc}" -ne 0 && "${rc}" -ne 130 && "${rc}" -ne 143 ]]; then
            warn "rgwtrace exited with status ${rc} for arm ${arm}; see ${trace_log}"
            [[ "${valid}" -eq 1 ]] && { valid=0; reason="tracer_exit_${rc}"; }
        fi
        if ! trace_json_valid "${trace_json}"; then
            warn "trace JSON missing or unparseable for arm ${arm}: ${trace_json}"
            [[ "${valid}" -eq 1 ]] && { valid=0; reason="trace_json_invalid"; }
        fi
    fi

    local valid_bool="true"
    [[ "${valid}" -eq 0 ]] && { valid_bool="false"; SCRIPT_INVALID=1; }

    write_phase_meta "${meta}" "${arm}" "${repeat}" "${traced}" \
        "${rgw_cpu}" "${rgw_rss0:-0}" "${rgw_rss1:-0}" "${rgw_hwm:-0}" \
        "${tr_cpu}" "${tr_life}" "${tr_hwm}" "${workload_summary}" "${trace_field}" \
        "${valid_bool}" "${reason}"
    return 0
}

# SIGINT the running tracer so it flushes JSON, reap it, and return its status.
stop_tracer() {
    [[ -n "${TRACE_PID}" ]] || return 0
    local pid="${TRACE_PID}" rc=0
    kill -INT "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || rc=$?
    TRACE_PID=""
    return "${rc}"
}

# Emit a per-phase metadata JSON. All numeric/controlled fields; paths are ours.
write_phase_meta() {
    local meta="$1" arm="$2" repeat="$3" traced="$4"
    local rgw_cpu="$5" rgw_rss0="$6" rgw_rss1="$7" rgw_hwm="$8"
    local tr_cpu="$9" tr_life="${10}" tr_hwm="${11}" workload_summary="${12}"
    local trace_json="${13}" valid_bool="${14}" reason="${15}"
    local traced_bool="false"
    [[ "${traced}" -eq 1 ]] && traced_bool="true"
    local trace_field="null"
    [[ -n "${trace_json}" ]] && trace_field="\"${trace_json}\""

    cat >"${meta}" <<EOF
{
  "arm": "${arm}",
  "repeat": ${repeat},
  "traced": ${traced_bool},
  "valid": ${valid_bool},
  "invalid_reason": "${reason}",
  "radosgw_cpu_seconds": ${rgw_cpu},
  "radosgw_rss_before_kb": ${rgw_rss0},
  "radosgw_rss_after_kb": ${rgw_rss1},
  "radosgw_vmhwm_kb": ${rgw_hwm},
  "rgwtrace_cpu_delta_seconds": ${tr_cpu},
  "rgwtrace_cpu_lifetime_seconds": ${tr_life},
  "rgwtrace_vmhwm_kb": ${tr_hwm},
  "workload_summary": "${workload_summary}",
  "trace_json": ${trace_field}
}
EOF
}

run_warmup() {
    [[ "${WARMUP_REQUESTS}" -gt 0 ]] || return 0
    local jsonl="${RAW_DIR}/warmup.workload.jsonl"
    local summary="${RAW_DIR}/warmup.workload.json"
    local state="${RAW_DIR}/warmup.state.json"
    local log="${RAW_DIR}/warmup.workload.log"
    # Warm-up is self-contained (phase all): create+seed+run+teardown in one shot.
    build_workload_cmd all "${WARMUP_REQUESTS}" "${jsonl}" "${summary}" "${state}"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf -- '--- warm-up (unmeasured, %s requests) ---\n' "${WARMUP_REQUESTS}"
        print_cmd "  workload:" "${WORKLOAD_CMD[@]}"
        return 0
    fi
    info "warm-up: ${WARMUP_REQUESTS} requests"
    "${WORKLOAD_CMD[@]}" >"${log}" 2>&1 || warn "warm-up workload failed; see ${log}"
}

# Counterbalanced schedule: each traced arm is bracketed by a baseline before AND
# after, and the traced-arm order is rotated per repeat so no traced arm is
# permanently biased by always following B (or always running against a warmer
# cache). Repeat 1: B,C[,D]; repeat 2: C[,D,]B; repeat 3: [D,]B,C; ...
build_schedule() {
    SCHEDULE=()
    local -a arms=("traced_default" "traced_cross_thread")
    [[ "${WITH_INFERRED}" -eq 1 ]] && arms+=("traced_inferred")
    local n="${#arms[@]}"
    local r i idx
    for ((r = 1; r <= REPEATS; r++)); do
        for ((i = 0; i < n; i++)); do
            idx=$(((i + r - 1) % n))   # rotate left by (r-1)
            SCHEDULE+=("baseline:${r}" "${arms[idx]}:${r}")
        done
        SCHEDULE+=("baseline:${r}")   # trailing bracket so the last arm has an A after it
    done
}

aggregate() {
    [[ "${DRY_RUN}" -eq 1 ]] && return 0
    info "aggregating per-arm results"
    local rc=0
    python3 "${RAW_DIR}/aggregate.py" "${RAW_DIR}" "${SUMMARY_JSON}" || rc=$?
    if [[ "${rc}" -eq 3 ]]; then
        SCRIPT_INVALID=1   # aggregator flagged invalid phases (already printed)
        return 0
    fi
    if [[ "${rc}" -ne 0 ]]; then
        err "aggregation failed (rc=${rc})"
        return "${rc}"
    fi
}

preflight_env() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        [[ -z "${RGW_PID}" ]] && RGW_PID="<RADOSGW_PID>"
        return 0
    fi

    if [[ "${EUID}" -ne 0 ]]; then
        die "must run as root (uprobes need CAP_BPF/CAP_PERFMON); re-run with sudo, or use --dry-run"
    fi
    if [[ ! -x "${RGWTRACE_BIN}" ]]; then
        die "rgwtrace binary not found at ${RGWTRACE_BIN}; run 'cargo build --release' or pass --rgwtrace-bin"
    fi
    if [[ ! -r "${WORKLOAD_PY}" ]]; then
        die "workload driver not found at ${WORKLOAD_PY}"
    fi
    if [[ -n "${RGWTRACE_DWARF_JSON}" && ! -r "${RGWTRACE_DWARF_JSON}" ]]; then
        die "DWARF JSON not readable: ${RGWTRACE_DWARF_JSON}"
    fi
    if [[ -z "${RGW_PID}" ]]; then
        RGW_PID="$(find_rgw_pid)" || die "no radosgw PID with librados.so.2 loaded; is RGW running? (or pass --pid)"
    fi
    if [[ ! -r "/proc/${RGW_PID}/stat" ]]; then
        die "radosgw PID ${RGW_PID} is not readable"
    fi
    info "tracing radosgw PID ${RGW_PID}"
}

write_aggregator() {
    # The aggregator is written under the (gitignored) results dir so it never
    # pollutes the repo. It pools per-arm latencies across repeats and recomputes
    # true percentiles, and diffs each traced arm vs the pooled baseline.
    cat >"${RAW_DIR}/aggregate.py" <<'PY'
#!/usr/bin/env python3
import glob
import json
import math
import os
import sys

# Names verified against the TraceDiagnostics struct in src/collector.rs (the
# struct serde-serialized into the JSON `trace.diagnostics` block).
DROP_KEYS = (
    "bpf_ringbuf_request_drops",
    "bpf_ringbuf_rados_drops",
    "bpf_rados_map_drops",
    "bpf_request_context_drops",
    "bpf_reqstate_map_drops",
    "bpf_probe_read_failures",
    "decode_errors",
    "otlp_queue_dropped_spans",
)
ARM_ORDER = ["baseline", "traced_default", "traced_cross_thread", "traced_inferred"]


def percentile(values, q):
    if not values:
        return None
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    pos = (len(s) - 1) * q
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def mean(values):
    return (sum(values) / len(values)) if values else None


def median(values):
    if not values:
        return None
    s = sorted(values)
    mid = len(s) // 2
    if len(s) % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


def load_diag(path):
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        return {}
    trace = doc.get("trace", doc)
    return trace.get("diagnostics", {}) if isinstance(trace, dict) else {}


def phase_latencies(meta):
    try:
        with open(meta["workload_summary"], encoding="utf-8") as handle:
            summary = json.load(handle)
    except (OSError, ValueError, KeyError):
        return [], None
    lat = summary.get("ops", {}).get("ALL", {}).get("latencies_us", [])
    return lat, summary.get("throughput_rps")


def paired_deltas(phases):
    """For each traced phase, delta vs the mean of its bracketing baselines.

    `phases` is the execution-ordered list of per-phase dicts. Each traced phase
    is compared against the baseline immediately before and immediately after it
    (whichever exist), preserving local pairing that pooling would discard.
    Returns {arm: {metric: [per-phase delta, ...]}}.
    """
    out = {}
    for i, ph in enumerate(phases):
        if not ph["traced"] or not ph["valid"]:
            continue
        before = next((phases[j] for j in range(i - 1, -1, -1)
                       if phases[j]["arm"] == "baseline" and phases[j]["valid"]), None)
        after = next((phases[j] for j in range(i + 1, len(phases))
                      if phases[j]["arm"] == "baseline" and phases[j]["valid"]), None)
        brackets = [b for b in (before, after) if b is not None]
        if not brackets:
            continue
        arm_out = out.setdefault(ph["arm"], {"p50_us": [], "p99_us": [], "throughput_rps": [], "rgw_cpu": []})
        for metric in ("p50_us", "p99_us", "throughput_rps", "rgw_cpu"):
            ref_vals = [b[metric] for b in brackets if b[metric] is not None]
            if ph[metric] is None or not ref_vals:
                continue
            arm_out[metric].append(ph[metric] - (sum(ref_vals) / len(ref_vals)))
    return out


def main():
    raw_dir, summary_path = sys.argv[1], sys.argv[2]
    phases = []
    for meta_path in sorted(glob.glob(os.path.join(raw_dir, "*.meta.json"))):
        with open(meta_path, encoding="utf-8") as handle:
            meta = json.load(handle)
        lat, throughput = phase_latencies(meta)
        phases.append({
            "arm": meta["arm"],
            "traced": bool(meta.get("traced")),
            "valid": bool(meta.get("valid", True)),
            "invalid_reason": meta.get("invalid_reason") or "",
            "lat": lat,
            "p50_us": percentile(lat, 0.50),
            "p99_us": percentile(lat, 0.99),
            "throughput_rps": throughput,
            "rgw_cpu": meta.get("radosgw_cpu_seconds"),
            "rss_delta": (meta.get("radosgw_rss_after_kb") or 0) - (meta.get("radosgw_rss_before_kb") or 0),
            "tr_cpu_delta": meta.get("rgwtrace_cpu_delta_seconds"),
            "tr_cpu_life": meta.get("rgwtrace_cpu_lifetime_seconds"),
            "tr_hwm": meta.get("rgwtrace_vmhwm_kb"),
            "diag": load_diag(meta.get("trace_json")),
        })

    invalid = [p for p in phases if not p["valid"]]

    # --- pooled per-arm aggregation (valid phases only) ------------------------
    arms = {}
    for ph in phases:
        if not ph["valid"]:
            continue
        acc = arms.setdefault(ph["arm"], {
            "phases": 0, "lat": [], "throughput": [], "rgw_cpu": [], "rss_delta": [],
            "tr_cpu_delta": [], "tr_cpu_life": [], "tr_hwm": [], "drops": {}})
        acc["phases"] += 1
        acc["lat"].extend(ph["lat"])
        if ph["throughput_rps"] is not None:
            acc["throughput"].append(ph["throughput_rps"])
        if ph["rgw_cpu"] is not None:
            acc["rgw_cpu"].append(ph["rgw_cpu"])
        acc["rss_delta"].append(ph["rss_delta"])
        if ph["traced"]:
            if isinstance(ph["tr_cpu_delta"], (int, float)):
                acc["tr_cpu_delta"].append(ph["tr_cpu_delta"])
            if isinstance(ph["tr_cpu_life"], (int, float)):
                acc["tr_cpu_life"].append(ph["tr_cpu_life"])
            if isinstance(ph["tr_hwm"], (int, float)):
                acc["tr_hwm"].append(ph["tr_hwm"])
        for key in DROP_KEYS:
            if key in ph["diag"]:
                acc["drops"][key] = acc["drops"].get(key, 0) + ph["diag"][key]

    paired = paired_deltas(phases)

    report = {"arms": {}, "invalid_phases": [
        {"arm": p["arm"], "reason": p["invalid_reason"]} for p in invalid]}
    for arm, acc in arms.items():
        lat = acc["lat"]
        pd = paired.get(arm, {})
        report["arms"][arm] = {
            "phases": acc["phases"],
            "requests_measured": len(lat),
            "pooled": {
                "p50_us": percentile(lat, 0.50),
                "p95_us": percentile(lat, 0.95),
                "p99_us": percentile(lat, 0.99),
                "mean_us": mean(lat),
                "throughput_rps": mean(acc["throughput"]),
                "radosgw_cpu_seconds": mean(acc["rgw_cpu"]),
                "radosgw_rss_delta_kb": mean(acc["rss_delta"]),
            },
            "paired_median_delta": {
                "p50_us": median(pd.get("p50_us", [])),
                "p99_us": median(pd.get("p99_us", [])),
                "throughput_rps": median(pd.get("throughput_rps", [])),
                "radosgw_cpu_seconds": median(pd.get("rgw_cpu", [])),
                "n": len(pd.get("p99_us", [])),
            },
            "rgwtrace_cpu_delta_seconds": mean(acc["tr_cpu_delta"]),
            "rgwtrace_cpu_lifetime_seconds": mean(acc["tr_cpu_life"]),
            "rgwtrace_vmhwm_kb": max(acc["tr_hwm"]) if acc["tr_hwm"] else None,
            "diagnostics_drops": acc["drops"],
        }

    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")

    arms_report = report["arms"]
    base = arms_report.get("baseline", {}).get("pooled", {})

    def fmt(value, width=10, prec=1):
        return ("{:>%d}" % width).format("n/a" if value is None else ("%.*f" % (prec, value)))

    def pct(value, ref):
        if value is None or ref in (None, 0):
            return "     n/a"
        return "%+7.1f%%" % ((value - ref) / ref * 100.0)

    def sdelta(value, prec=1):
        return "n/a" if value is None else ("%+.*f" % (prec, value))

    print()
    print("=" * 92)
    print("rgwtrace A/B overhead summary  (latencies in microseconds, pooled across repeats)")
    print("=" * 92)
    print("{:<22}{:>10}{:>10}{:>10}{:>11}{:>12}".format(
        "arm", "p50", "p95", "p99", "tput_rps", "rgw_cpu_s"))
    print("-" * 92)
    for arm in ARM_ORDER:
        if arm not in arms_report:
            continue
        row = arms_report[arm]["pooled"]
        print("{:<22}{}{}{}{:>11}{:>12}".format(
            arm, fmt(row["p50_us"]), fmt(row["p95_us"]), fmt(row["p99_us"]),
            fmt(row["throughput_rps"], 11), fmt(row["radosgw_cpu_seconds"], 12, 3)))

    if base:
        print("-" * 92)
        print("pooled deltas vs baseline (p99 latency / throughput / radosgw CPU):")
        for arm in ARM_ORDER:
            if arm == "baseline" or arm not in arms_report:
                continue
            entry = arms_report[arm]
            row = entry["pooled"]
            print("  {:<20} p99 {}   tput {}   rgw_cpu {}".format(
                arm, pct(row["p99_us"], base.get("p99_us")),
                pct(row["throughput_rps"], base.get("throughput_rps")),
                pct(row["radosgw_cpu_seconds"], base.get("radosgw_cpu_seconds"))))
            pm = entry["paired_median_delta"]
            print("  {:<20} paired median delta (n={}): p99 {} us   tput {} rps   rgw_cpu {} s".format(
                "", pm["n"], sdelta(pm["p99_us"]), sdelta(pm["throughput_rps"]),
                sdelta(pm["radosgw_cpu_seconds"], 3)))
            if entry["rgwtrace_cpu_delta_seconds"] is not None:
                print("  {:<20} collector CPU {:.3f}s/phase (measured window; lifetime {})   peak RSS {} kB".format(
                    "", entry["rgwtrace_cpu_delta_seconds"],
                    ("%.3fs" % entry["rgwtrace_cpu_lifetime_seconds"])
                    if entry["rgwtrace_cpu_lifetime_seconds"] is not None else "n/a",
                    entry["rgwtrace_vmhwm_kb"] if entry["rgwtrace_vmhwm_kb"] is not None else "n/a"))
            nonzero = {k: v for k, v in entry["diagnostics_drops"].items() if v}
            if nonzero:
                print("  {:<20} DROPS: {}".format("", nonzero))

    if invalid:
        print("-" * 92)
        print("INVALID phases (%d) -- excluded from aggregation:" % len(invalid))
        for p in invalid:
            print("  %s: %s" % (p["arm"], p["invalid_reason"] or "unknown"))

    print("=" * 92)
    print("raw per-phase metadata + JSON summary: %s" % summary_path)
    if invalid:
        sys.exit(3)


if __name__ == "__main__":
    main()
PY
}

main() {
    parse_args "$@"
    CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

    if [[ "${SECRET_ON_ARGV}" -eq 1 ]]; then
        warn "--secret-key puts the secret on this process's argv (visible in ps); prefer RGW_SECRET_KEY / AWS_SECRET_ACCESS_KEY"
    fi
    if [[ "${DRY_RUN}" -ne 1 && ( -z "${ACCESS_KEY}" || -z "${SECRET_KEY}" ) ]]; then
        die "S3 credentials missing: set RGW_ACCESS_KEY/RGW_SECRET_KEY (or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY); the e2e test prints how to read its generated keys"
    fi
    export AWS_ACCESS_KEY_ID="${ACCESS_KEY}" AWS_SECRET_ACCESS_KEY="${SECRET_KEY}"

    preflight_env

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        RUN_STAMP="dry-run"
        RAW_DIR="${OUTPUT_DIR}/${RUN_STAMP}"
        printf 'DRY RUN: no cluster contact, no root required.\n\n'
        printf 'Config: requests=%s concurrency=%s object_size=%s put_fraction=%s repeats=%s with_inferred=%s\n' \
            "${REQUESTS}" "${CONCURRENCY}" "${OBJECT_SIZE}" "${PUT_FRACTION}" "${REPEATS}" "${WITH_INFERRED}"
        printf 'Target: endpoint=%s rgwtrace=%s pid=%s\n' "${ENDPOINT}" "${RGWTRACE_BIN}" "${RGW_PID}"
        printf 'Output: %s\n\n' "${RAW_DIR}"
    else
        RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
        RAW_DIR="${OUTPUT_DIR}/${RUN_STAMP}"
        mkdir -p "${RAW_DIR}"
        SUMMARY_JSON="${RAW_DIR}/summary.json"
        write_aggregator
        info "writing raw results under ${RAW_DIR}"
    fi

    run_warmup

    build_schedule
    local entry arm repeat
    for entry in "${SCHEDULE[@]}"; do
        arm="${entry%%:*}"
        repeat="${entry##*:}"
        run_phase "${arm}" "${repeat}"
    done

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '\nDry run complete: %s phases planned (%s repeats).\n' "${SEQ}" "${REPEATS}"
        return 0
    fi

    aggregate
    if [[ "${SCRIPT_INVALID}" -ne 0 ]]; then
        err "one or more phases were invalid (capture failure); results are incomplete"
        return 1
    fi
    info "benchmark complete"
}

main "$@"
