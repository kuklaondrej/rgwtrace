#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ARTIFACT_DIR="${ARTIFACT_DIR:-/tmp/rgwtrace-dwarf-artifacts}"
CEPH_VERSION="${CEPH_VERSION:-}"
DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

NATIVE_DWARF_JSON="${ARTIFACT_DIR}/native-dwarf.json"
NATIVE_DWARF_LOG="${ARTIFACT_DIR}/native-dwarf.log"
PREFLIGHT_JSON="${ARTIFACT_DIR}/preflight.json"
PREFLIGHT_LOG="${ARTIFACT_DIR}/preflight.log"
PACKAGES_TXT="${ARTIFACT_DIR}/packages.txt"
TARGET_PATHS_ENV="${ARTIFACT_DIR}/target-paths.env"
OS_RELEASE_TXT="${ARTIFACT_DIR}/os-release.txt"
REPO_RELEASE_TXT="${ARTIFACT_DIR}/repo-release.txt"
README_TXT="${ARTIFACT_DIR}/README.txt"

info() {
    printf '[INFO] %s\n' "$*"
}

err() {
    printf '[ERROR] %s\n' "$*" >&2
}

require_ceph_version() {
    if [[ ! "${CEPH_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        err "CEPH_VERSION must match X.Y.Z, got ${CEPH_VERSION:-<unset>}"
        exit 1
    fi
}

ubuntu_codename() {
    # shellcheck disable=SC1091
    . /etc/os-release
    local codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
    if [[ -z "${codename}" ]]; then
        err "could not derive Ubuntu codename from /etc/os-release"
        exit 1
    fi
    printf '%s\n' "${codename}"
}

install_base_tools() {
    info "installing base APT tools"
    apt-get update -q
    apt-get install -y -q --no-install-recommends \
        ca-certificates \
        curl \
        gnupg
}

configure_ceph_repo() {
    local codename="$1"
    local repo_url="https://download.ceph.com/debian-${CEPH_VERSION}"
    local release_url="${repo_url}/dists/${codename}/Release"

    info "checking upstream Ceph repository ${release_url}"
    if ! curl -fsSL "${release_url}" -o "${REPO_RELEASE_TXT}"; then
        printf 'missing repository release file: %s\n' "${release_url}" >"${REPO_RELEASE_TXT}"
        err "upstream Ceph repository does not publish ${codename} for Ceph ${CEPH_VERSION}: ${release_url}"
        exit 1
    fi

    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://download.ceph.com/keys/release.asc \
        | gpg --batch --yes --dearmor -o /etc/apt/keyrings/ceph.gpg
    printf 'deb [signed-by=/etc/apt/keyrings/ceph.gpg] %s %s main\n' \
        "${repo_url}" \
        "${codename}" \
        >/etc/apt/sources.list.d/ceph.list

    info "configured ${repo_url} for ${codename}"
}

install_export_dependencies() {
    info "installing rgwtrace build dependencies and Ceph packages"
    apt-get update -q
    apt-get install -y -q --no-install-recommends \
        build-essential \
        clang \
        curl \
        libelf-dev \
        linux-libc-dev \
        llvm \
        make \
        pkg-config \
        xz-utils \
        zlib1g-dev \
        ceph-common \
        ceph-common-dbg \
        librados2 \
        librados2-dbg \
        librbd1 \
        librbd1-dbg \
        radosgw \
        radosgw-dbg
}

assert_package_versions() {
    local package
    local version
    for package in \
        ceph-common \
        ceph-common-dbg \
        librados2 \
        librados2-dbg \
        librbd1 \
        librbd1-dbg \
        radosgw \
        radosgw-dbg
    do
        version="$(dpkg-query -W -f='${Version}' "${package}")"
        if [[ "${version}" != "${CEPH_VERSION}-"* ]]; then
            err "installed ${package} version ${version} does not match requested Ceph ${CEPH_VERSION}"
            exit 1
        fi
    done
}

capture_packages() {
    dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
        ceph-common \
        ceph-common-dbg \
        librados2 \
        librados2-dbg \
        librbd1 \
        librbd1-dbg \
        radosgw \
        radosgw-dbg \
        >"${PACKAGES_TXT}"
}

install_rust_toolchain() {
    if ! command -v rustup >/dev/null 2>&1; then
        info "installing rustup"
        curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain none
        # shellcheck disable=SC1091
        . "${HOME}/.cargo/env"
    else
        # shellcheck disable=SC1091
        . "${HOME}/.cargo/env" 2>/dev/null || true
    fi

    local toolchain
    toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' "${REPO_ROOT}/rust-toolchain.toml")"
    if [[ -z "${toolchain}" ]]; then
        err "failed to read Rust toolchain from ${REPO_ROOT}/rust-toolchain.toml"
        exit 1
    fi

    info "installing Rust toolchain ${toolchain}"
    rustup toolchain install --profile minimal "${toolchain}"
}

build_rgwtrace() {
    info "building rgwtrace"
    export CARGO_HOME="${CARGO_HOME:-/tmp/rgwtrace-cargo-home}"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rgwtrace-target}"

    cd "${REPO_ROOT}"
    cargo build --release --locked
}

resolve_library() {
    local soname="$1"
    local path

    for path in \
        "/usr/lib/ceph/${soname}" \
        "/usr/lib/x86_64-linux-gnu/${soname}" \
        "/usr/lib/${soname}" \
        "/lib/x86_64-linux-gnu/${soname}" \
        "/lib/${soname}"
    do
        if [[ -e "${path}" ]]; then
            readlink -f "${path}"
            return 0
        fi
    done

    ldconfig
    path="$(ldconfig -p | awk -v soname="${soname}" '$1 == soname { print $NF; exit }')"
    if [[ -n "${path}" && -e "${path}" ]]; then
        readlink -f "${path}"
        return 0
    fi

    err "failed to resolve ${soname}"
    return 1
}

resolve_targets() {
    RADOSGW_PATH="$(command -v radosgw || command -v ceph-radosgw || true)"
    if [[ -z "${RADOSGW_PATH}" ]]; then
        err "failed to resolve radosgw executable"
        exit 1
    fi
    RADOSGW_PATH="$(readlink -f "${RADOSGW_PATH}")"

    LIBRADOS_PATH="$(resolve_library librados.so.2)"
    LIBRBD_PATH="$(resolve_library librbd.so.1)"
    LIBCEPH_COMMON_PATH="$(resolve_library libceph-common.so.2)"
    export RADOSGW_PATH LIBRADOS_PATH LIBRBD_PATH LIBCEPH_COMMON_PATH

    {
        printf 'RADOSGW_PATH=%q\n' "${RADOSGW_PATH}"
        printf 'LIBRADOS_PATH=%q\n' "${LIBRADOS_PATH}"
        printf 'LIBRBD_PATH=%q\n' "${LIBRBD_PATH}"
        printf 'LIBCEPH_COMMON_PATH=%q\n' "${LIBCEPH_COMMON_PATH}"
    } >"${TARGET_PATHS_ENV}"
}

export_dwarf_json() {
    local rgwtrace_bin="${CARGO_TARGET_DIR}/release/rgwtrace"

    info "exporting native DWARF metadata"
    if ! "${rgwtrace_bin}" \
        --dwarf-source native \
        --ceph-version "${CEPH_VERSION}" \
        --librados-path "${LIBRADOS_PATH}" \
        --librbd-path "${LIBRBD_PATH}" \
        --libceph-common-path "${LIBCEPH_COMMON_PATH}" \
        --radosgw-path "${RADOSGW_PATH}" \
        --export-dwarf-json \
        >"${NATIVE_DWARF_JSON}" 2>"${NATIVE_DWARF_LOG}"; then
        err "native DWARF export failed; see ${NATIVE_DWARF_LOG}"
        exit 1
    fi
}

run_preflight() {
    local rgwtrace_bin="${CARGO_TARGET_DIR}/release/rgwtrace"

    info "validating exported DWARF metadata"
    if ! "${rgwtrace_bin}" \
        --dwarf-source json \
        --import-json "${NATIVE_DWARF_JSON}" \
        --librados-path "${LIBRADOS_PATH}" \
        --librbd-path "${LIBRBD_PATH}" \
        --libceph-common-path "${LIBCEPH_COMMON_PATH}" \
        --radosgw-path "${RADOSGW_PATH}" \
        --preflight \
        --output json \
        >"${PREFLIGHT_JSON}" 2>"${PREFLIGHT_LOG}"; then
        err "DWARF preflight failed; continuing so the exported JSON can be tested"
        if [[ ! -s "${PREFLIGHT_JSON}" ]]; then
            printf '{"ok":false,"error":"DWARF preflight failed; see preflight.log"}\n' \
                >"${PREFLIGHT_JSON}"
        fi
    fi
}

write_readme() {
    cat >"${README_TXT}" <<EOF
rgwtrace upstream Ceph DWARF artifact

Ubuntu codename: ${UBUNTU_CODENAME}
Ceph version: ${CEPH_VERSION}
Architecture: linux/amd64

Validate on a target host with matching binaries:

sudo rgwtrace \\
  --dwarf-source json \\
  --import-json /path/to/native-dwarf.json \\
  --preflight

Trace with:

sudo rgwtrace \\
  --dwarf-source json \\
  --import-json /path/to/native-dwarf.json \\
  --output json

If preflight.json reports "ok": false, the artifact was still uploaded for
manual testing. Do not use this artifact with different Ceph/RGW binaries
unless the build ID mismatch is understood.
EOF
}

main() {
    require_ceph_version
    mkdir -p "${ARTIFACT_DIR}"
    cp /etc/os-release "${OS_RELEASE_TXT}"

    UBUNTU_CODENAME="$(ubuntu_codename)"
    export UBUNTU_CODENAME

    install_base_tools
    configure_ceph_repo "${UBUNTU_CODENAME}"
    install_export_dependencies
    assert_package_versions
    capture_packages
    install_rust_toolchain
    build_rgwtrace
    resolve_targets
    export_dwarf_json
    run_preflight
    write_readme

    info "DWARF artifact written to ${ARTIFACT_DIR}"
}

main "$@"
