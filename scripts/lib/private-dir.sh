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

# rgwtrace_require_safe_ancestors DIR [LABEL]
#   Every directory above DIR must prevent another user from swapping DIR out
#   from under us after the check (rename ours away, drop theirs in). That
#   holds when each ancestor is owned by root or by us AND is either not
#   group/other writable or sticky (a sticky /tmp only lets the owner of an
#   entry rename it). Symlink components on the logical path are checked too:
#   one owned by another user could be re-pointed.
rgwtrace_require_safe_ancestors() {
    local dir="$1"
    local label="${2:-directory}"
    local parent phys owner mode

    if [[ "${dir}" != /* ]]; then
        dir="${PWD}/${dir}"
    fi
    parent="$(dirname "${dir}")"
    while :; do
        if [[ -L "${parent}" ]]; then
            read -r owner _ < <(rgwtrace_dir_owner_and_mode "${parent}") || true
            if [[ "${owner}" != "0" && "${owner}" != "${EUID}" ]]; then
                printf '[private-dir] refusing %s %s: path component %s is a symlink owned by uid %s\n' \
                    "${label}" "$1" "${parent}" "${owner:-?}" >&2
                return 1
            fi
        fi
        phys="$(cd -P -- "${parent}" 2>/dev/null && pwd -P)" || {
            printf '[private-dir] refusing %s %s: cannot resolve parent %s\n' "${label}" "$1" "${parent}" >&2
            return 1
        }
        read -r owner mode < <(rgwtrace_dir_owner_and_mode "${phys}") || true
        if [[ -z "${owner}" || -z "${mode}" ]]; then
            printf '[private-dir] could not stat parent %s of %s %s\n' "${phys}" "${label}" "$1" >&2
            return 1
        fi
        if [[ "${owner}" != "0" && "${owner}" != "${EUID}" ]]; then
            printf '[private-dir] refusing %s %s: parent %s is owned by uid %s, who could replace it\n' \
                "${label}" "$1" "${phys}" "${owner}" >&2
            return 1
        fi
        if (( (8#${mode} & 8#022) != 0 )) && [[ ! -k "${phys}" ]]; then
            printf '[private-dir] refusing %s %s: parent %s is group/other writable and not sticky, so another user could replace the directory\n' \
                "${label}" "$1" "${phys}" >&2
            return 1
        fi
        [[ "${parent}" == "/" ]] && break
        parent="$(dirname "${parent}")"
    done
    return 0
}

# rgwtrace_require_private_dir DIR [LABEL]
#   Ensure DIR is safe to write into as the current user:
#     - every ancestor must be unable to swap DIR out (see
#       rgwtrace_require_safe_ancestors); this is checked first so nothing is
#       created under a parent we then refuse.
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

    rgwtrace_require_safe_ancestors "${dir}" "${label}" || return 1

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
