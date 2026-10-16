#!/usr/bin/env bash
set -euo pipefail
binary="$1"
tag="$2"
target="$3"
variant="${4:-}"
[[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'invalid release tag' >&2; exit 1; }
case "${target}" in
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
    *) echo 'unsupported release target' >&2; exit 1 ;;
esac
case "${variant}" in
    ''|centos9) ;;
    *) echo 'unsupported release variant' >&2; exit 1 ;;
esac
name="rgwtrace-${tag}-${target}${variant:+-${variant}}"
staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT
mkdir -p "${staging}/${name}" dist
cp "${binary}" "${staging}/${name}/rgwtrace"
cp LICENSE.GPL-2.0 README.md RUNBOOK.md tests/fixtures/minimal_dwarf.json "${staging}/${name}/"
cp release/BINARY-README.txt "${staging}/${name}/INSTALL.txt"
ldd "${binary}" | tee "${staging}/${name}/shared-libraries.txt"
if grep -q 'not found' "${staging}/${name}/shared-libraries.txt"; then exit 1; fi
tar -C "${staging}" -czf "dist/${name}.tar.gz" "${name}"
