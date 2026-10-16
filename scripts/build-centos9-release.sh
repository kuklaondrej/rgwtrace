#!/usr/bin/env bash
# Runs inside the CentOS builder; output is mounted at /workspace/dist.
set -euo pipefail
: "${RELEASE_TAG:?release tag is required}"
: "${TARGET:?native Rust target is required}"
: "${CARGO_TARGET_DIR:?isolated build directory is required}"
version=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "rgwtrace"))')
test "${RELEASE_TAG}" = "v${version}"
test "${TARGET}" = "$(rustc -vV | sed -n 's/^host: //p')"
git config --global --add safe.directory /workspace
scripts/verify.sh
cargo build --release --locked
scripts/package-binary.sh "${CARGO_TARGET_DIR}/release/rgwtrace" "${RELEASE_TAG}" "${TARGET}" centos9
