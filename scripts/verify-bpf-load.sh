#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
pin_dir="/sys/fs/bpf/rgwtrace-verify-$$"

cleanup() {
  rm -rf "${tmp_dir}"
  if [[ -d "${pin_dir}" ]]; then
    rm -rf "${pin_dir}"
  fi
}
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  printf 'verify-bpf-load must run as root so bpftool can load BPF programs\n' >&2
  exit 1
fi

for tool in clang bpftool; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "${tool}" >&2
    exit 1
  fi
done

case "$(uname -m)" in
  x86_64)
    bpf_arch="-D__TARGET_ARCH_x86"
    multiarch_include="/usr/include/x86_64-linux-gnu"
    ;;
  aarch64|arm64)
    bpf_arch="-D__TARGET_ARCH_arm64"
    multiarch_include="/usr/include/aarch64-linux-gnu"
    ;;
  *)
    printf 'unsupported BPF verification architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf; then
  mount -t bpf bpf /sys/fs/bpf
fi

obj="${tmp_dir}/rgwtrace.bpf.o"
clang \
  -g \
  -O2 \
  -target bpf \
  "${bpf_arch}" \
  -I "${repo_root}/bpf" \
  -I "${multiarch_include}" \
  -c "${repo_root}/bpf/rgwtrace.bpf.c" \
  -o "${obj}"

mkdir -p "${pin_dir}"
bpftool prog loadall "${obj}" "${pin_dir}"
