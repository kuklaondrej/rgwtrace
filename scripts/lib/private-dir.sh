#!/usr/bin/env bash
#
# Shared helpers for scripts that write files as root into a scratch or
# artifact directory. Source this file; do not execute it.
#
# Why: these scripts run privileged on shared hosts. A predictable directory
# under /tmp (e.g. /tmp/rgwtrace-stage0) can be pre-created by any local user,
# who then controls what lands in it: a planted symlink turns `cat >` into a
# write anywhere, and a planted cargo config.toml turns `cargo build` into
# code execution as root. Every writable directory these scripts use must
# therefore be private: created by us with mktemp, or proven to be ours.

# rgwtrace_private_tmpdir PREFIX
#   Print a freshly created private (0700) directory under ${TMPDIR:-/tmp}.
rgwtrace_private_tmpdir() {
    local prefix="$1"
    mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXXXXXX"
}

# rgwtrace_dir_owner_and_mode DIR
#   Print "<uid> <octal-mode>" for DIR without following symlinks.
#   GNU stat first (Linux is the deployment target); BSD stat as a fallback so
#   the check can be exercised on macOS.
rgwtrace_dir_owner_and_mode() {
    local dir="$1"
    stat -c '%u %a' "${dir}" 2>/dev/null \
        || stat -f '%u %OLp' "${dir}" 2>/dev/null
}

# rgwtrace_require_private_dir DIR [LABEL]
#   Ensure DIR is safe to write into as the current user:
#     - if it does not exist, create it (mkdir without -p, mode 0700). mkdir
#       fails on an existing path of any kind, so a symlink planted at DIR
#       cannot be followed; the parent must already exist.
#     - otherwise it must be a real directory (not a symlink), owned by the
#       current uid, and not writable by group or others.
#   Returns 1 with a message on stderr when the directory cannot be trusted.
rgwtrace_require_private_dir() {
    local dir="$1"
    local label="${2:-directory}"

    if [[ -z "${dir}" ]]; then
        printf '[private-dir] %s path is empty\n' "${label}" >&2
        return 1
    fi

    if [[ -L "${dir}" ]]; then
        printf '[private-dir] refusing %s %s: it is a symlink\n' "${label}" "${dir}" >&2
        return 1
    fi

    if [[ ! -e "${dir}" ]]; then
        if ! mkdir -m 0700 "${dir}"; then
            printf '[private-dir] failed to create %s %s (parent missing, or the path appeared concurrently)\n' \
                "${label}" "${dir}" >&2
            return 1
        fi
        # mkdir succeeded, so the path is ours; the checks below re-verify it.
    fi

    if [[ ! -d "${dir}" ]]; then
        printf '[private-dir] refusing %s %s: not a directory\n' "${label}" "${dir}" >&2
        return 1
    fi

    local owner mode
    read -r owner mode < <(rgwtrace_dir_owner_and_mode "${dir}") || true
    if [[ -z "${owner}" || -z "${mode}" ]]; then
        printf '[private-dir] could not stat %s %s\n' "${label}" "${dir}" >&2
        return 1
    fi

    if [[ "${owner}" != "${EUID}" ]]; then
        printf '[private-dir] refusing %s %s: owned by uid %s, not the current uid %s\n' \
            "${label}" "${dir}" "${owner}" "${EUID}" >&2
        return 1
    fi

    # Group/other write bits (022) mean another user can plant files or
    # symlinks in it. The sticky bit on a world-writable dir does not help:
    # the attacker only needs to create entries, not replace ours.
    if (( (8#${mode} & 8#022) != 0 )); then
        printf '[private-dir] refusing %s %s: mode %s is group/other writable; use chmod 700\n' \
            "${label}" "${dir}" "${mode}" >&2
        return 1
    fi

    return 0
}
