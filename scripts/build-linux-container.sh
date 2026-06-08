#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime="${CONTAINER_RUNTIME:-}"

if [[ -z "${runtime}" ]]; then
  if command -v docker >/dev/null 2>&1; then
    runtime=docker
  elif command -v podman >/dev/null 2>&1; then
    runtime=podman
  else
    echo "error: docker or podman is required" >&2
    exit 1
  fi
fi

image="${IMAGE_NAME:-rgwtrace-linux-builder}"
container="${image}-extract-$$"
output_dir="${OUTPUT_DIR:-${repo_root}/dist}"
output="${output_dir}/rgwtrace-linux-amd64"

mkdir -p "${output_dir}"

"${runtime}" build \
  --platform linux/amd64 \
  -f "${repo_root}/docker/Dockerfile" \
  -t "${image}" \
  "${repo_root}"

cleanup() {
  "${runtime}" rm -f "${container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${runtime}" create --name "${container}" "${image}" >/dev/null
"${runtime}" cp "${container}:/workspace/target/release/rgwtrace" "${output}"
chmod +x "${output}"

echo "built ${output}"
