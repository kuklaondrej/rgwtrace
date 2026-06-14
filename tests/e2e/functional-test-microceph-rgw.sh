#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PATH="/snap/bin:${PATH}"

ARTIFACT_DIR="${ARTIFACT_DIR:-/tmp/rgwtrace-e2e}"
TRACE_SECONDS="${TRACE_SECONDS:-60}"
TRACE_ATTACH_DELAY="${TRACE_ATTACH_DELAY:-6}"
MICROCEPH_OSDS="${MICROCEPH_OSDS:-3}"
MICROCEPH_OSD_SIZE="${MICROCEPH_OSD_SIZE:-3G}"
MICROCEPH_HEALTH_TIMEOUT="${MICROCEPH_HEALTH_TIMEOUT:-180}"
MICROCEPH_CHANNEL="${MICROCEPH_CHANNEL:-reef/stable}"
MICROCEPH_EXPECTED_CEPH_VERSION="${MICROCEPH_EXPECTED_CEPH_VERSION:-18.2.8-1jammy}"
MICROCEPH_ALLOW_CHANNEL_SWITCH="${MICROCEPH_ALLOW_CHANNEL_SWITCH:-0}"
RGW_PORT="${RGW_PORT:-8080}"
RGW_ENDPOINT="${RGW_ENDPOINT:-}"
RGW_USER="${RGW_USER:-rgwtrace-e2e}"
RGW_ACCESS_KEY="${RGW_ACCESS_KEY:-RGWTRACEACCESSKEY001}"
RGW_SECRET_KEY="${RGW_SECRET_KEY:-rgwtrace-secret-key-rgwtrace-secret-key}"
RGWTRACE_BIN="${RGWTRACE_BIN:-${PROJECT_ROOT}/target/release/rgwtrace}"
RGWTRACE_DWARF_JSON="${RGWTRACE_DWARF_JSON:-}"
KEEP_E2E_RESOURCES="${KEEP_E2E_RESOURCES:-0}"

PREFLIGHT_JSON="${ARTIFACT_DIR}/preflight.json"
PREFLIGHT_LOG="${ARTIFACT_DIR}/preflight.log"
TRACE_JSON="${ARTIFACT_DIR}/trace.json"
TRACE_LOG="${ARTIFACT_DIR}/rgwtrace.log"
WORKLOAD_JSONL="${ARTIFACT_DIR}/workload.jsonl"
WORKLOAD_LOG="${ARTIFACT_DIR}/workload.log"
VERIFY_LOG="${ARTIFACT_DIR}/verify.log"
RGW_USER_JSON="${ARTIFACT_DIR}/rgw-user.json"
RGW_ENABLE_LOG="${ARTIFACT_DIR}/microceph-rgw-enable.log"
MICROCEPH_VERSION_FILE="${ARTIFACT_DIR}/microceph-version.txt"
MICROCEPH_METADATA_FILE="${ARTIFACT_DIR}/microceph-metadata.yaml"
MICROCEPH_MANIFEST_FILE="${ARTIFACT_DIR}/microceph-manifest.yaml"
MICROCEPH_MANIFEST_CEPH_FILE="${ARTIFACT_DIR}/microceph-manifest-ceph.txt"
MICROCEPH_SNAP_LIST_FILE="${ARTIFACT_DIR}/microceph-snap-list.txt"

TRACE_PID=""
RGW_ADMIN=""

info() {
    printf '[INFO] %s\n' "$*"
}

err() {
    printf '[ERROR] %s\n' "$*" >&2
}

cleanup() {
    local rc=$?
    if [[ -n "${TRACE_PID}" ]]; then
        kill "${TRACE_PID}" 2>/dev/null || true
    fi
    pkill -f "${RGWTRACE_BIN}" 2>/dev/null || true

    if [[ ${rc} -eq 0 && "${KEEP_E2E_RESOURCES}" != "1" && -n "${RGW_ADMIN}" ]]; then
        "${RGW_ADMIN}" user rm --uid="${RGW_USER}" --purge-data --purge-keys >/dev/null 2>&1 || true
    fi

    info "artifacts preserved in ${ARTIFACT_DIR}"
}
trap cleanup EXIT

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "this test must be run as root or with sudo"
        exit 1
    fi
}

install_host_deps() {
    if ! command -v snap >/dev/null 2>&1; then
        info "installing snapd"
        apt-get update -q
        apt-get install -y -q snapd
    fi

    if ! command -v curl >/dev/null 2>&1; then
        info "installing curl"
        apt-get update -q
        apt-get install -y -q curl
    fi

    if ! python3 - <<'PY' >/dev/null 2>&1
import boto3
PY
    then
        info "installing python3-boto3"
        apt-get update -q
        apt-get install -y -q python3-boto3
    fi
}

capture_microceph_version_artifacts() {
    local metadata=/snap/microceph/current/share/metadata.yaml
    local manifest=/snap/microceph/current/snap/manifest.yaml
    local resolved_version=""

    snap list microceph >"${MICROCEPH_SNAP_LIST_FILE}" 2>&1 || true
    if [[ -r "${metadata}" ]]; then
        cp "${metadata}" "${MICROCEPH_METADATA_FILE}"
    fi
    if [[ -r "${manifest}" ]]; then
        cp "${manifest}" "${MICROCEPH_MANIFEST_FILE}"
        python3 - <<'PY' >"${MICROCEPH_MANIFEST_CEPH_FILE}" || true
from pathlib import Path

manifest = Path("/snap/microceph/current/snap/manifest.yaml")
needles = ("ceph", "rados", "rgw", "librbd", "librados")
if manifest.exists():
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        lowered = line.lower()
        if any(needle in lowered for needle in needles):
            print(line)
PY
    fi

    resolved_version=$(resolve_microceph_ceph_version || true)
    {
        printf 'microceph_channel=%s\n' "${MICROCEPH_CHANNEL}"
        printf 'microceph_expected_ceph_version=%s\n' "${MICROCEPH_EXPECTED_CEPH_VERSION}"
        printf 'microceph_resolved_ceph_version=%s\n' "${resolved_version}"
    } >"${MICROCEPH_VERSION_FILE}"
}

resolve_microceph_ceph_version() {
    python3 - <<'PY'
from pathlib import Path
import re
import sys

manifest = Path("/snap/microceph/current/snap/manifest.yaml")
metadata = Path("/snap/microceph/current/share/metadata.yaml")
packages = ("radosgw", "librados2", "ceph-common", "ceph-osd")

if manifest.exists():
    text = manifest.read_text(encoding="utf-8", errors="replace")
    for package in packages:
        patterns = (
            rf"(?m)^\s*{re.escape(package)}\s*[:=]\s*([^\s,]+)",
            rf"(?m)\b{re.escape(package)}=([^\s,]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                print(match.group(1).strip().strip('"\''))
                sys.exit(0)

if metadata.exists():
    for line in metadata.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^\s*ceph-version\s*:\s*(\S+)", line)
        if match:
            print(match.group(1).strip().strip('"\''))
            sys.exit(0)

sys.exit(1)
PY
}

assert_microceph_ceph_version() {
    capture_microceph_version_artifacts

    local resolved_version
    resolved_version=$(resolve_microceph_ceph_version || true)
    if [[ -z "${resolved_version}" ]]; then
        err "failed to resolve MicroCeph Ceph package version; see ${MICROCEPH_METADATA_FILE} and ${MICROCEPH_MANIFEST_FILE}"
        return 1
    fi

    info "MicroCeph Ceph package version: ${resolved_version}"
    if [[ -n "${MICROCEPH_EXPECTED_CEPH_VERSION}" && "${resolved_version}" != "${MICROCEPH_EXPECTED_CEPH_VERSION}" ]]; then
        err "MicroCeph Ceph package version ${resolved_version} does not match expected ${MICROCEPH_EXPECTED_CEPH_VERSION}"
        err "set MICROCEPH_EXPECTED_CEPH_VERSION=${resolved_version} to accept this version, or provide a matching MicroCeph channel/revision"
        return 1
    fi
}

ensure_microceph_version() {
    if assert_microceph_ceph_version; then
        return 0
    fi

    if [[ "${MICROCEPH_ALLOW_CHANNEL_SWITCH}" != "1" ]]; then
        err "refusing to switch an installed MicroCeph snap automatically; set MICROCEPH_ALLOW_CHANNEL_SWITCH=1 to run 'snap refresh microceph --channel ${MICROCEPH_CHANNEL}'"
        return 1
    fi

    info "switching MicroCeph snap to channel ${MICROCEPH_CHANNEL}"
    snap refresh --unhold microceph >/dev/null 2>&1 || true
    snap refresh microceph --channel "${MICROCEPH_CHANNEL}"
    snap refresh --hold microceph || true
    assert_microceph_ceph_version
}

microceph_setup_single_node() {
    local osd_count="$1"
    local osd_size="$2"
    local health_timeout="$3"

    if ! snap list microceph >/dev/null 2>&1; then
        local install_args=(install microceph --channel "${MICROCEPH_CHANNEL}")
        info "installing MicroCeph snap from ${MICROCEPH_CHANNEL}"
        snap "${install_args[@]}"
        snap refresh --hold microceph || true
    else
        info "MicroCeph snap already installed"
    fi

    ensure_microceph_version

    if ! microceph cluster list 2>/dev/null | grep -q "$(hostname)"; then
        info "bootstrapping MicroCeph cluster"
        microceph cluster bootstrap
    else
        info "MicroCeph cluster already bootstrapped"
    fi

    local current_osds
    current_osds=$(microceph.ceph osd stat 2>/dev/null | grep -oP '\d+(?= osds:)' || true)
    current_osds="${current_osds:-0}"
    if (( current_osds < osd_count )); then
        local missing=$((osd_count - current_osds))
        info "adding ${missing} loop-backed MicroCeph OSD(s) (${osd_size} each)"
        microceph disk add "loop,${osd_size},${missing}"
    else
        info "MicroCeph already has ${current_osds} OSD(s)"
    fi

    info "waiting for MicroCeph cluster readiness"
    local elapsed=0
    while (( elapsed < health_timeout )); do
        local status_json
        status_json=$(microceph.ceph status --format=json 2>/dev/null || true)
        if [[ -n "${status_json}" ]] && STATUS_JSON="${status_json}" WANT_OSDS="${osd_count}" python3 - <<'PY'
import json
import os
import sys

try:
    data = json.loads(os.environ["STATUS_JSON"])
except Exception:
    sys.exit(2)

health = data.get("health", {}).get("status", "")
quorum = len(data.get("quorum_names", []))
osdmap = data.get("osdmap", {})
up = osdmap.get("num_up_osds", 0)
inside = osdmap.get("num_in_osds", 0)
want = int(os.environ["WANT_OSDS"])

if health in {"HEALTH_OK", "HEALTH_WARN"} and quorum >= 1 and up >= want and inside >= want:
    sys.exit(0)
sys.exit(1)
PY
        then
            info "MicroCeph cluster ready with ${osd_count} OSD(s)"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    err "MicroCeph cluster did not become ready within ${health_timeout}s"
    microceph.ceph status || true
    return 1
}

wait_rgw_endpoint() {
    local port="$1"
    local timeout_sec="$2"
    local elapsed=0

    while (( elapsed < timeout_sec )); do
        if curl -sS --max-time 3 "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
            RGW_ENDPOINT="http://127.0.0.1:${port}"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

enable_microceph_rgw() {
    if [[ -n "${RGW_ENDPOINT}" ]]; then
        info "using caller-provided RGW endpoint ${RGW_ENDPOINT}"
        return 0
    fi

    if wait_rgw_endpoint "${RGW_PORT}" 5; then
        info "RGW already reachable at ${RGW_ENDPOINT}"
        return 0
    fi

    local enable_help
    enable_help=$(microceph enable --help 2>&1 || true)
    if [[ "${enable_help}" != *rgw* ]]; then
        info "MicroCeph help does not advertise 'enable rgw'; trying it anyway"
    fi

    info "enabling MicroCeph RGW on port ${RGW_PORT}"
    microceph enable rgw --port "${RGW_PORT}" >>"${RGW_ENABLE_LOG}" 2>&1 || true
    if wait_rgw_endpoint "${RGW_PORT}" 90; then
        info "RGW reachable at ${RGW_ENDPOINT}"
        return 0
    fi

    microceph enable rgw --port="${RGW_PORT}" >>"${RGW_ENABLE_LOG}" 2>&1 || true
    if wait_rgw_endpoint "${RGW_PORT}" 90; then
        info "RGW reachable at ${RGW_ENDPOINT}"
        return 0
    fi

    info "retrying MicroCeph RGW enable without an explicit port"
    microceph enable rgw >>"${RGW_ENABLE_LOG}" 2>&1 || true
    local port
    for port in "${RGW_PORT}" 80 8080 8000; do
        if wait_rgw_endpoint "${port}" 30; then
            info "RGW reachable at ${RGW_ENDPOINT}"
            return 0
        fi
    done

    err "MicroCeph RGW did not become reachable"
    return 1
}

find_rgw_admin() {
    if command -v microceph.radosgw-admin >/dev/null 2>&1; then
        RGW_ADMIN="microceph.radosgw-admin"
        return 0
    fi
    err "microceph.radosgw-admin was not found"
    return 1
}

create_rgw_user() {
    find_rgw_admin
    "${RGW_ADMIN}" user rm --uid="${RGW_USER}" --purge-data --purge-keys >/dev/null 2>&1 || true
    "${RGW_ADMIN}" user create \
        --uid="${RGW_USER}" \
        --display-name="${RGW_USER}" \
        --access-key="${RGW_ACCESS_KEY}" \
        --secret-key="${RGW_SECRET_KEY}" \
        --format=json >"${RGW_USER_JSON}"
}

find_rgw_pid() {
    local pid
    local exe
    for _ in $(seq 1 90); do
        for pid in $(pgrep -f radosgw 2>/dev/null || true); do
            [[ -r "/proc/${pid}/maps" ]] || continue
            exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || true)
            [[ "${exe}" == *radosgw* || "${exe}" == *ceph-radosgw* ]] || continue
            if grep -q 'librados.so.2' "/proc/${pid}/maps"; then
                printf '%s\n' "${pid}"
                return 0
            fi
        done
        sleep 1
    done
    return 1
}

run_preflight() {
    local rgw_pid="$1"
    local dwarf_args=(--dwarf-source native)
    if [[ -n "${RGWTRACE_DWARF_JSON}" ]]; then
        dwarf_args=(--dwarf-source json --import-json "${RGWTRACE_DWARF_JSON}")
    fi

    info "running rgwtrace preflight for radosgw PID ${rgw_pid}"
    if ! "${RGWTRACE_BIN}" \
        "${dwarf_args[@]}" \
        --pid "${rgw_pid}" \
        --preflight \
        --output json \
        --service-name rgwtrace-e2e \
        >"${PREFLIGHT_JSON}" 2>"${PREFLIGHT_LOG}"; then
        err "rgwtrace preflight failed; see ${PREFLIGHT_LOG} and ${PREFLIGHT_JSON}"
        return 1
    fi
}

start_trace() {
    local rgw_pid="$1"
    local dwarf_args=(--dwarf-source native)
    if [[ -n "${RGWTRACE_DWARF_JSON}" ]]; then
        dwarf_args=(--dwarf-source json --import-json "${RGWTRACE_DWARF_JSON}")
    fi

    info "starting rgwtrace capture for ${TRACE_SECONDS}s"
    timeout "$((TRACE_SECONDS + TRACE_ATTACH_DELAY + 30))" \
        "${RGWTRACE_BIN}" \
        "${dwarf_args[@]}" \
        --pid "${rgw_pid}" \
        --timeout "${TRACE_SECONDS}" \
        --output json \
        --service-name rgwtrace-e2e \
        >"${TRACE_JSON}" 2>"${TRACE_LOG}" &
    TRACE_PID=$!
}

run_workload() {
    info "running S3 workload against ${RGW_ENDPOINT}"
    python3 "${SCRIPT_DIR}/s3-workload.py" \
        --endpoint "${RGW_ENDPOINT}" \
        --access-key "${RGW_ACCESS_KEY}" \
        --secret-key "${RGW_SECRET_KEY}" \
        --output "${WORKLOAD_JSONL}" \
        >"${WORKLOAD_LOG}" 2>&1
}

verify_trace() {
    info "verifying rgwtrace JSON output"
    python3 "${SCRIPT_DIR}/verify-rgwtrace-json.py" \
        --trace "${TRACE_JSON}" \
        --workload "${WORKLOAD_JSONL}" \
        --min-request-spans 3 \
        --min-rados-spans 3 \
        --expect-role data \
        --expect-any-role bucket_index,bucket_meta \
        >"${VERIFY_LOG}" 2>&1
}

main() {
    require_root
    mkdir -p "${ARTIFACT_DIR}"
    : >"${WORKLOAD_JSONL}"

    if [[ ! -x "${RGWTRACE_BIN}" ]]; then
        err "rgwtrace binary not found at ${RGWTRACE_BIN}; run 'cargo build --release' first"
        exit 1
    fi

    install_host_deps
    microceph_setup_single_node "${MICROCEPH_OSDS}" "${MICROCEPH_OSD_SIZE}" "${MICROCEPH_HEALTH_TIMEOUT}"
    enable_microceph_rgw
    create_rgw_user

    local rgw_pid
    rgw_pid=$(find_rgw_pid) || {
        err "could not find a host radosgw PID with librados loaded"
        exit 1
    }
    info "found radosgw PID ${rgw_pid}"

    run_preflight "${rgw_pid}"
    start_trace "${rgw_pid}"
    sleep "${TRACE_ATTACH_DELAY}"
    run_workload
    wait "${TRACE_PID}"
    TRACE_PID=""
    verify_trace

    info "MicroCeph RGW e2e test passed"
}

main "$@"
