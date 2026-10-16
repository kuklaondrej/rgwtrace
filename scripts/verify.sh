#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${repo_root}"

cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --locked --all-targets -- -D warnings
python3 tests/e2e/verify-rgwtrace-json.py --self-test
python3 -m unittest discover -s tests/e2e -p 'test_*.py'
python3 -m unittest discover -s tests -p 'test_release.py'
git diff --check
git diff --cached --check

if [[ "${VERIFY_AUDIT:-0}" == "1" ]]; then
  if ! command -v cargo-audit >/dev/null 2>&1; then
    cargo install cargo-audit --version 0.22.2 --locked
  fi
  cargo audit --deny yanked --deny unmaintained
fi

if [[ "${VERIFY_BPF_LOAD:-0}" == "1" ]]; then
  sudo "${repo_root}/scripts/verify-bpf-load.sh"
fi

if [[ "${VERIFY_CONTAINER_BUILD:-0}" == "1" ]]; then
  "${repo_root}/scripts/build-linux-container.sh"
fi
