#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${repo_root}"

cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
git diff --check

if [[ "${VERIFY_BPF_LOAD:-0}" == "1" ]]; then
  sudo "${repo_root}/scripts/verify-bpf-load.sh"
fi

if [[ "${VERIFY_CONTAINER_BUILD:-0}" == "1" ]]; then
  "${repo_root}/scripts/build-linux-container.sh"
fi
