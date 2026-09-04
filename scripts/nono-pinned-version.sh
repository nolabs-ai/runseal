#!/usr/bin/env bash
# Print the nono version pinned for this action in .github/nono-version/Cargo.toml.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
manifest="${1:-${script_dir}/../.github/nono-version/Cargo.toml}"

if [[ ! -f "${manifest}" ]]; then
    echo "::error::nono version pin ${manifest} not found; pass nono-version explicitly" >&2
    exit 1
fi

pins="$(sed -n 's/^nono-cli[[:space:]]*=[[:space:]]*"=\([^"]*\)".*$/\1/p' "${manifest}")"
count=0
if [[ -n "${pins}" ]]; then
    count="$(printf '%s\n' "${pins}" | wc -l | tr -d '[:space:]')"
fi

if [[ "${count}" != "1" ]]; then
    echo "::error::Expected exactly one exact nono-cli requirement in ${manifest}, found ${count}" >&2
    exit 1
fi

version="${pins}"

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "::error::Pinned nono version '${version}' in ${manifest} is not a bare X.Y.Z version" >&2
    exit 1
fi

printf '%s\n' "${version}"
