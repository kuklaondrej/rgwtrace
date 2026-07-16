#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Build and run the rgwtrace per-probe overhead microbenchmark.
#
# It attaches rgwtrace's REAL BPF programs to a synthetic, self-hosted target
# (the bench binary itself) -- no Ceph required -- and measures per-probe cost
# with full-path execution verified by ring-buffer event / diagnostic counters.
#
# Requires root (BPF load + uprobe attach). Building does not; only the run does.
#
# Output:
#   * a human-readable table on stdout
#   * a machine-readable JSON file under bench-results/ (path printed at the end;
#     schema documented in bench/README.md)
#
# Any bench argument (e.g. --iterations, --reps, --k, --flood, --cpu, --out-dir)
# is forwarded to the harness:  scripts/bench-overhead.sh --iterations 500000
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${repo_root}/bench-results"
bin="${repo_root}/target/release/rgwtrace-bench"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'bench-overhead requires Linux (eBPF uprobes)\n' >&2
  exit 1
fi

# Build first (as the invoking user, so the target dir stays owned by them),
# then re-exec the built binary under sudo if we are not already root.
printf '==> building rgwtrace-bench (release)\n' >&2
cargo build --release -p rgwtrace-bench

# Verify the synthetic uprobe targets survived in the ELF: a stripped binary
# would make every uprobe attach fail, which is a confusing way to learn the
# profile stripped symbols. Fail early and clearly instead.
# Capture nm output once instead of piping into grep -q: with pipefail, grep -q
# exiting at the first match delivers SIGPIPE to nm and fails the pipeline even
# though the symbol is present.
symtab="$(nm "${bin}" 2>/dev/null || true)"
missing=()
for sym in syn_get_handler syn_req_state_dtor syn_send_op syn_finish_op \
           syn_rados_operate syn_trap_target; do
  if ! grep -q " ${sym}$" <<<"${symtab}"; then
    missing+=("${sym}")
  fi
done
if (( ${#missing[@]} > 0 )); then
  printf 'error: synthetic uprobe target symbols missing from %s: %s\n' \
    "${bin}" "${missing[*]}" >&2
  printf 'the binary appears stripped; uprobes cannot attach by symbol offset\n' >&2
  exit 1
fi

mkdir -p "${out_dir}"

# Re-exec under root if needed. --out-dir defaults to the repo's bench-results.
run() {
  "${bin}" --out-dir "${out_dir}" "$@"
}

printf '==> running benchmark (root required)\n' >&2
if [[ "${EUID}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E "${bin}" --out-dir "${out_dir}" "$@"
  fi
  printf 'error: must run as root (BPF load + uprobe attach) and sudo is unavailable\n' >&2
  exit 1
fi
run "$@"
