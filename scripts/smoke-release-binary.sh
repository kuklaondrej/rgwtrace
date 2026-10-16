#!/usr/bin/env bash
# Test the extracted deliverable, including its offline fixture.
set -euo pipefail
archive="$1"
name="$(basename "${archive}" .tar.gz)"
staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT
tar -C "${staging}" -xzf "${archive}"
"${staging}/${name}/rgwtrace" --version
"${staging}/${name}/rgwtrace" --import-json "${staging}/${name}/minimal_dwarf.json" \
    --dry-run --output json > "${staging}/output.json"
python3 -m json.tool "${staging}/output.json" > /dev/null
