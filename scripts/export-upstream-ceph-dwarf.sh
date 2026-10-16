#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/lib/private-dir.sh
. "${SCRIPT_DIR}/lib/private-dir.sh"

# This script installs packages, a Rust toolchain and builds as root. Nothing
# it writes may live in a directory another local user can pre-create.
umask 077

ARTIFACT_DIR="${ARTIFACT_DIR:-$(rgwtrace_private_tmpdir rgwtrace-dwarf-artifacts)}"
# Scratch space for the rustup installer, CARGO_HOME and the cargo target dir.
# A predictable CARGO_HOME is root code execution: cargo honours
# $CARGO_HOME/config.toml (build.rustc-wrapper, [target].runner, ...).
WORK_DIR="${WORK_DIR:-$(rgwtrace_private_tmpdir rgwtrace-dwarf-work)}"
CEPH_VERSION="${CEPH_VERSION:-}"
CEPH_PACKAGE_VERSION="${CEPH_PACKAGE_VERSION:-}"
DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

# The script reconfigures APT and installs a toolchain system-wide, so it is
# only meant for a throwaway container (the dwarf-artifact workflow runs it in
# a fresh ubuntu image). Set RGWTRACE_ALLOW_HOST_EXPORT=1 to run it elsewhere
# on purpose.
RGWTRACE_ALLOW_HOST_EXPORT="${RGWTRACE_ALLOW_HOST_EXPORT:-0}"

# Ceph release signing key, "Ceph.com (release key) <security@ceph.com>".
# The long key ID E84AC2C0460F3994 is the one published in Ceph's 2015
# signing-key security notice (ceph.io blog, "Important security notice
# regarding signing key and binary downloads of Ceph"); the full fingerprint
# was taken from https://download.ceph.com/keys/release.asc on 2026-10-09 and
# its last 16 hex digits are that published key ID. Refresh only if Ceph
# rotates the key: gpg --show-keys --with-fingerprint release.asc
CEPH_RELEASE_KEY_FINGERPRINT="${CEPH_RELEASE_KEY_FINGERPRINT:-08B73419AC32B4E966C1A330E84AC2C0460F3994}"

# rustup-init is fetched as a pinned release binary and checked against the
# SHA-256 rustup publishes next to it, instead of piping sh.rustup.rs into sh.
# To refresh: VERSION=$(curl -fsSL https://static.rust-lang.org/rustup/release-stable.toml)
# then, per triple, curl -fsSL https://static.rust-lang.org/rustup/archive/<version>/<triple>/rustup-init.sha256
RUSTUP_INIT_VERSION="${RUSTUP_INIT_VERSION:-1.29.1}"
RUSTUP_INIT_SHA256_x86_64="dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71"
RUSTUP_INIT_SHA256_aarch64="15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433"

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

require_container() {
    if [[ "${RGWTRACE_ALLOW_HOST_EXPORT}" == "1" ]]; then
        info "RGWTRACE_ALLOW_HOST_EXPORT=1: running outside a container as requested"
        return 0
    fi
    if [[ -f /.dockerenv || -f /run/.containerenv || -n "${container:-}" ]]; then
        return 0
    fi
    err "refusing to run outside a container: this script rewrites APT sources and installs packages and a Rust toolchain system-wide"
    err "run it in a throwaway container (see .github/workflows/dwarf-artifact.yml) or set RGWTRACE_ALLOW_HOST_EXPORT=1"
    exit 1
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

# Print the primary-key fingerprint of an armored key file, refusing a file
# that carries more than one primary key: gpg --dearmor installs the whole
# file into the APT keyring, so a second key appended by a compromised server
# would be trusted too even though only the first one was checked.
ceph_key_single_fingerprint() {
    local key_file="$1"
    local listing pub_count
    listing="$(gpg --batch --with-colons --show-keys --with-fingerprint "${key_file}" 2>/dev/null)" || {
        err "gpg could not parse ${key_file}"
        return 1
    }
    pub_count="$(printf '%s\n' "${listing}" | awk -F: '$1 == "pub"' | wc -l | tr -d ' ')"
    if [[ "${pub_count}" != "1" ]]; then
        err "expected exactly one primary key in ${key_file}, found ${pub_count}"
        return 1
    fi
    # The first fpr record follows the (only) pub record; later ones belong to
    # its subkeys.
    printf '%s\n' "${listing}" | awk -F: '$1 == "fpr" { print $10; exit }'
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

    # Fetch the key to a private file and compare its fingerprint with the
    # pinned one before trusting it for package verification: TLS alone only
    # proves we talked to download.ceph.com, not that the key is Ceph's.
    local key_asc="${WORK_DIR}/ceph-release.asc"
    local fingerprint
    curl --proto '=https' --tlsv1.2 -fsSL https://download.ceph.com/keys/release.asc -o "${key_asc}"
    fingerprint="$(ceph_key_single_fingerprint "${key_asc}")" || exit 1
    if [[ "${fingerprint}" != "${CEPH_RELEASE_KEY_FINGERPRINT}" ]]; then
        err "Ceph release key fingerprint mismatch: got '${fingerprint:-<none>}', expected ${CEPH_RELEASE_KEY_FINGERPRINT}"
        exit 1
    fi
    info "Ceph release key fingerprint verified (${fingerprint})"

    install -d -m 0755 /etc/apt/keyrings
    gpg --batch --yes --dearmor -o /etc/apt/keyrings/ceph.gpg "${key_asc}"
    chmod 0644 /etc/apt/keyrings/ceph.gpg
    printf 'deb [signed-by=/etc/apt/keyrings/ceph.gpg] %s %s main\n' \
        "${repo_url}" \
        "${codename}" \
        >/etc/apt/sources.list.d/ceph.list

    info "configured ${repo_url} for ${codename}"
}

install_export_dependencies() {
    local package
    local packages=()
    for package in "${CEPH_PACKAGES[@]}"; do
        if [[ -n "${CEPH_PACKAGE_VERSION}" ]]; then
            packages+=("${package}=${CEPH_PACKAGE_VERSION}")
        else
            packages+=("${package}")
        fi
    done
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
        "${packages[@]}"
}

assert_package_versions() {
    local package
    local version
    for package in "${CEPH_PACKAGES[@]}"; do
        if [[ "${EXPORT_OS}" == centos-stream ]]; then
            version="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "${package}")"
        else
            version="$(dpkg-query -W -f='${Version}' "${package}")"
        fi
        if [[ -n "${CEPH_PACKAGE_VERSION}" && "${version}" != "${CEPH_PACKAGE_VERSION}" ]]; then
            err "installed ${package} version ${version} differs from pinned ${CEPH_PACKAGE_VERSION}"
            exit 1
        fi
        if [[ "${version}" != "${CEPH_VERSION}-"* ]]; then
            err "installed ${package} version ${version} does not match requested Ceph ${CEPH_VERSION}"
            exit 1
        fi
    done
}

capture_packages() {
    if [[ "${EXPORT_OS}" == centos-stream ]]; then
        rpm -q --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' \
            "${CEPH_PACKAGES[@]}" >"${PACKAGES_TXT}"
    else
        dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
            "${CEPH_PACKAGES[@]}" >"${PACKAGES_TXT}"
    fi
}

select_platform() {
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID}:${VERSION_ID}" in
        ubuntu:*)
            EXPORT_OS=ubuntu
            CEPH_PACKAGES=(ceph-common ceph-common-dbg librados2 librados2-dbg
                           librbd1 librbd1-dbg radosgw radosgw-dbg)
            ;;
        centos:9)
            EXPORT_OS=centos-stream
            CEPH_PACKAGES=(ceph-common ceph-common-debuginfo ceph-debuginfo
                           librados2 librados2-debuginfo librbd1 librbd1-debuginfo
                           ceph-radosgw ceph-radosgw-debuginfo)
            ;;
        *) err "unsupported export OS ${ID}:${VERSION_ID}"; exit 1 ;;
    esac
    EXPORT_OS_VERSION="${VERSION_ID}"
    if [[ "$(uname -m)" != x86_64 ]]; then
        err "DWARF exporter currently requires linux/amd64"
        exit 1
    fi
}

install_centos_dependencies() {
    local repo_url="https://download.ceph.com/rpm-${CEPH_VERSION}/el9"
    local package
    local packages=()
    if [[ -z "${CEPH_PACKAGE_VERSION}" ]]; then
        err "CentOS exports require an exact CEPH_PACKAGE_VERSION"
        exit 1
    fi
    dnf install -y ca-certificates curl-minimal dnf-plugins-core
    dnf config-manager --set-enabled crb
    dnf install -y epel-release
    curl -fsSL "${repo_url}/x86_64/repodata/repomd.xml" -o "${REPO_RELEASE_TXT}"
    curl -fsSL https://download.ceph.com/keys/release.asc -o /etc/pki/rpm-gpg/RPM-GPG-KEY-ceph
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-ceph
    cat >/etc/yum.repos.d/rgwtrace-ceph.repo <<EOF
[rgwtrace-ceph]
name=Ceph ${CEPH_VERSION} EL9 x86_64
baseurl=${repo_url}/x86_64
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-ceph
[rgwtrace-ceph-noarch]
name=Ceph ${CEPH_VERSION} EL9 noarch
baseurl=${repo_url}/noarch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-ceph
EOF
    for package in "${CEPH_PACKAGES[@]}"; do
        packages+=("${package}-${CEPH_PACKAGE_VERSION}.x86_64")
    done
    dnf install -y gcc gcc-c++ clang elfutils-libelf-devel kernel-headers llvm \
        make pkgconf-pkg-config xz zlib-devel "${packages[@]}"
}

install_rustup_pinned() {
    local arch triple expected actual installer
    arch="$(uname -m)"
    case "${arch}" in
        x86_64)  triple="x86_64-unknown-linux-gnu";  expected="${RUSTUP_INIT_SHA256_x86_64}" ;;
        aarch64) triple="aarch64-unknown-linux-gnu"; expected="${RUSTUP_INIT_SHA256_aarch64}" ;;
        *)
            err "no pinned rustup-init checksum for architecture ${arch}"
            exit 1
            ;;
    esac

    installer="${WORK_DIR}/rustup-init"
    info "downloading rustup-init ${RUSTUP_INIT_VERSION} for ${triple}"
    curl --proto '=https' --tlsv1.2 -fsSL \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_INIT_VERSION}/${triple}/rustup-init" \
        -o "${installer}"
    actual="$(sha256sum "${installer}" | awk '{ print $1 }')"
    if [[ "${actual}" != "${expected}" ]]; then
        err "rustup-init checksum mismatch: got ${actual}, expected ${expected}"
        exit 1
    fi
    chmod 0700 "${installer}"
    "${installer}" -y --profile minimal --default-toolchain none --no-modify-path
    rm -f "${installer}"
}

install_rust_toolchain() {
    # CARGO_HOME is fixed before rustup runs so the proxies, the registry cache
    # and any config.toml all live in our private scratch directory.
    export CARGO_HOME="${CARGO_HOME:-${WORK_DIR}/cargo-home}"
    export RUSTUP_HOME="${RUSTUP_HOME:-${WORK_DIR}/rustup-home}"
    rgwtrace_require_private_dir "${CARGO_HOME}" "CARGO_HOME" || exit 1
    # The toolchain binaries cargo runs as root live under RUSTUP_HOME, so it
    # needs the same guarantee as CARGO_HOME.
    rgwtrace_require_private_dir "${RUSTUP_HOME}" "RUSTUP_HOME" || exit 1

    if ! command -v rustup >/dev/null 2>&1 && [[ ! -x "${CARGO_HOME}/bin/rustup" ]]; then
        info "installing rustup"
        install_rustup_pinned
    fi
    PATH="${CARGO_HOME}/bin:${PATH}"
    export PATH

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
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${WORK_DIR}/target}"
    rgwtrace_require_private_dir "${CARGO_TARGET_DIR}" "CARGO_TARGET_DIR" || exit 1

    cd "${REPO_ROOT}"
    cargo build --release --locked
}

resolve_library() {
    local soname="$1"
    local path

    for path in \
        "/usr/lib64/ceph/${soname}" \
        "/usr/lib64/${soname}" \
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

Distribution: ${EXPORT_OS} ${EXPORT_OS_VERSION}
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
    require_container
    require_ceph_version
    rgwtrace_require_private_dir "${ARTIFACT_DIR}" "ARTIFACT_DIR" || exit 1
    rgwtrace_require_private_dir "${WORK_DIR}" "WORK_DIR" || exit 1
    cp /etc/os-release "${OS_RELEASE_TXT}"

    select_platform
    if [[ "${EXPORT_OS}" == centos-stream ]]; then
        install_centos_dependencies
    else
        install_base_tools
        configure_ceph_repo "$(ubuntu_codename)"
        install_export_dependencies
    fi
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
