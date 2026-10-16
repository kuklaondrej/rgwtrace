#!/usr/bin/env bash
#
# Regression tests for scripts/lib/private-dir.sh. Runs unprivileged on Linux
# and macOS; everything lives under one scratch directory that is removed on
# exit. "Another user" cannot be simulated without root, so the ownership
# cases are driven by what the current user can create: mode bits, symlinks,
# and shared (group/other writable, non-sticky) parents.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/lib/private-dir.sh
. "${repo_root}/scripts/lib/private-dir.sh"

scratch="$(mktemp -d "${TMPDIR:-/tmp}/private-dir-test.XXXXXXXX")"
trap 'chmod -R u+rwx "${scratch}" 2>/dev/null; rm -rf "${scratch}"' EXIT
cd "${scratch}"

failures=0
expect_ok() {
    if rgwtrace_require_private_dir "$1" "test" 2>/dev/null; then
        printf 'ok    accept %s\n' "$2"
    else
        printf 'FAIL  expected accept: %s (%s)\n' "$2" "$1"; failures=$((failures + 1))
    fi
}
expect_refuse() {
    if rgwtrace_require_private_dir "$1" "test" 2>/dev/null; then
        printf 'FAIL  expected refuse: %s (%s)\n' "$2" "$1"; failures=$((failures + 1))
    else
        printf 'ok    refuse %s\n' "$2"
    fi
}

# --- the directory itself ----------------------------------------------------
mkdir -m 0700 own700;   expect_ok     own700   "owned 0700 directory"
mkdir -m 0755 own755;   expect_ok     own755   "owned 0755 directory (readable is fine)"
mkdir -m 0777 ww;       expect_refuse ww       "world-writable directory"
mkdir -m 0770 gw;       expect_refuse gw       "group-writable directory"
mkdir -m 1777 sticky;   expect_refuse sticky   "sticky world-writable directory (entries can still be planted)"
ln -s own700 link;      expect_refuse link     "symlink to a good directory"
touch file;             expect_refuse file     "regular file"
expect_refuse ""                                "empty path"
expect_ok     fresh                             "missing directory is created"
[[ "$(rgwtrace_dir_owner_and_mode fresh | awk '{ print $2 }')" == "700" ]] \
    || { printf 'FAIL  created directory is not 0700\n'; failures=$((failures + 1)); }
expect_refuse missing/parent                    "missing directory under a missing parent"

# --- the parent chain --------------------------------------------------------
# A parent any other user can write to and that is not sticky lets them rename
# our directory away and put their own in its place after the check.
mkdir -m 0777 shared;  mkdir -m 0700 shared/out
expect_refuse shared/out                        "0700 directory under a world-writable non-sticky parent"
mkdir -m 0770 gshared; mkdir -m 0700 gshared/out
expect_refuse gshared/out                       "0700 directory under a group-writable parent"
mkdir -m 1777 stickyp; mkdir -m 0700 stickyp/out
expect_ok     stickyp/out                       "0700 directory under a sticky world-writable parent (like /tmp)"
mkdir -m 0755 ro;      mkdir -m 0700 ro/out
expect_ok     ro/out                            "0700 directory under a 0755 parent"
mkdir -m 0777 deep;    mkdir -m 0755 deep/mid; mkdir -m 0700 deep/mid/out
expect_refuse deep/mid/out                      "writable grandparent"
mkdir -m 0777 viafresh
expect_refuse viafresh/new                      "missing directory under a world-writable non-sticky parent"
# A symlink component controlled by another user could be re-pointed; one we
# own (or root owns, like /tmp on macOS) is fine.
ln -s ro rolink
expect_ok     rolink/out                        "own symlink as a parent component"

# --- a real system path ------------------------------------------------------
d="$(rgwtrace_private_tmpdir rgwtrace-test)"
expect_ok     "${d}"                            "rgwtrace_private_tmpdir result"
rmdir "${d}"

if (( failures )); then
    printf '%s failure(s)\n' "${failures}" >&2
    exit 1
fi
printf 'private-dir tests passed\n'
