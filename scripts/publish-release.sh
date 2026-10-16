#!/usr/bin/env bash
# Upload into a draft first; a failed upload must never expose a partial release.
set -euo pipefail
tag="$1"
assets="$2"
notes="$3"
mode="$4"
if state="$(gh release view "${tag}" --json isDraft --jq .isDraft 2>/dev/null)"; then
    if [[ "${state}" == false ]]; then
        echo "Release ${tag} already published; preserving its assets"
        exit 0
    fi
else
    if [[ "${mode}" == binary ]]; then
        gh release create "${tag}" --verify-tag --draft --title "rgwtrace ${tag}" --notes-file "${notes}"
    else
        gh release create "${tag}" --target "${GITHUB_SHA}" --draft --title "DWARF catalog ${tag#dwarf-}" --notes-file "${notes}"
    fi
fi
# Re-running a failed draft is safe; published assets are never overwritten.
gh release upload "${tag}" "${assets}"/* --clobber
if [[ "${mode}" == binary ]]; then
    gh release edit "${tag}" --draft=false --latest
else
    gh release edit "${tag}" --draft=false --latest=false
fi
