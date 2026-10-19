#!/usr/bin/env bash
# Assemble and verify a draft before publishing. Never overwrite a public
# release.
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
    echo 'Usage: publish-release.sh <tag> <tarball> <SHA256SUMS>' >&2
    exit 1
fi
tag="$1"
asset="$2"
sums="$3"
if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
    echo 'Invalid release tag' >&2
    exit 1
fi
if [[ ! -f "${asset}" || ! -f "${sums}" || "$(basename "${sums}")" != SHA256SUMS ]]; then
    echo 'Expected a tarball and SHA256SUMS file' >&2
    exit 1
fi
asset_name="$(basename "${asset}")"
if [[ "${asset_name}" != "runseal-${tag}-x86_64-unknown-linux-gnu.tar.gz" ]]; then
    echo 'Tarball name does not match the release tag and supported target' >&2
    exit 1
fi

# A failed lookup is not permission to modify an existing release. Creation
# also fails if one already exists. Never fall back to editing a published
# release.
if draft="$(gh release view "${tag}" --json isDraft --jq .isDraft 2>/dev/null)"; then
    if [[ "${draft}" != true ]]; then
        echo 'Refusing to modify an already published release' >&2
        exit 1
    fi
else
    gh release create "${tag}" --draft --verify-tag \
        --title "${tag}" --notes "Runseal ${tag}"
fi

repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
release_id="$(gh release view "${tag}" --json databaseId --jq .databaseId)"
if [[ ! "${release_id}" =~ ^[0-9]+$ ]]; then
    echo 'Release ID is missing or invalid' >&2
    exit 1
fi
asset_digest="sha256:$(sha256sum -- "${asset}" | cut -d ' ' -f 1)"
sums_digest="sha256:$(sha256sum -- "${sums}" | cut -d ' ' -f 1)"

verify_draft_manifest() {
    local manifest
    # Query the raw API. Older gh versions can omit digest from --json assets.
    # A missing server-side digest is a failure.
    manifest="$(gh api "repos/${repository}/releases/${release_id}")"
    printf '%s\n' "${manifest}" | python3 -c '
import json, sys
release = json.load(sys.stdin)
tag, release_id, name, digest, sums_digest = sys.argv[1:]
expected = {name: digest, "SHA256SUMS": sums_digest}
assets = release.get("assets")
if (release.get("id") != int(release_id) or release.get("tag_name") != tag
        or release.get("draft") is not True or not isinstance(assets, list)
        or len(assets) != len(expected)):
    sys.exit("Draft release identity or asset set changed")
seen = set()
for asset in assets:
    if (not isinstance(asset, dict) or asset.get("name") not in expected
            or asset["name"] in seen or asset.get("state") != "uploaded"
            or asset.get("digest") != expected[asset["name"]]):
        sys.exit("Draft assets must exactly match the verified local SHA-256 digests")
    seen.add(asset["name"])
' "${tag}" "${release_id}" "${asset_name}" "${asset_digest}" "${sums_digest}"
}

gh release upload "${tag}" "${asset}" "${sums}" --clobber
verify_draft_manifest
verify_dir="$(mktemp -d)"
trap 'rm -rf -- "${verify_dir}"' EXIT
gh release download "${tag}" --pattern "${asset_name}" --pattern SHA256SUMS --dir "${verify_dir}"
cmp -- "${asset}" "${verify_dir}/${asset_name}"
cmp -- "${sums}" "${verify_dir}/SHA256SUMS"
(
    cd "${verify_dir}"
    sha256sum --check --strict SHA256SUMS
    gh attestation verify "${asset_name}" \
        --repo "${repository}" \
        --signer-repo "${repository}" \
        --source-ref "refs/tags/${tag}" \
        --deny-self-hosted-runners
    gh attestation verify SHA256SUMS \
        --repo "${repository}" \
        --signer-repo "${repository}" \
        --source-ref "refs/tags/${tag}" \
        --deny-self-hosted-runners
)
verify_draft_manifest
gh release edit "${tag}" --draft=false
