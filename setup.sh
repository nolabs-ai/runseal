#!/usr/bin/env bash
set -euo pipefail

RUNSEAL_VERSION="${RUNSEAL_VERSION:-0.3.1}"
NONO_VERSION="${NONO_VERSION:-0.62.0}"
RUNSEAL_REPO="${RUNSEAL_REPO:-always-further/runseal}"
NONO_REPO="${NONO_REPO:-always-further/nono}"
RUNSEAL_VERIFY_ATTESTATIONS="${RUNSEAL_VERIFY_ATTESTATIONS:-true}"
RUNSEAL_ACTION_PATH="${RUNSEAL_ACTION_PATH:-${GITHUB_ACTION_PATH:-}}"
INSTALL_ROOT="${RUNNER_TOOL_CACHE:-/tmp}/runseal"

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "${os}:${arch}" in
        Linux:x86_64|Linux:amd64) echo "x86_64-unknown-linux-gnu" ;;
        *)
            echo "::error::Unsupported runner target ${os}/${arch}; Runseal currently supports Linux x86_64"
            exit 1
            ;;
    esac
}

strip_v() {
    local version="$1"
    printf '%s' "${version#v}"
}

resolve_latest() {
    local repo="$1"
    curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest" \
        | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' \
        | tail -n 1 \
        | sed 's/^v//'
}

resolve_version() {
    local repo="$1"
    local requested="$2"

    if [[ "${requested}" == "latest" ]]; then
        resolve_latest "${repo}"
    else
        strip_v "${requested}"
    fi
}

verify_checksum() {
    local sums_file="$1"
    local asset="$2"

    if command -v sha256sum >/dev/null 2>&1; then
        grep -F "  ${asset}" "${sums_file}" | awk -v asset="${asset}" '$2 == asset' | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
        grep -F "  ${asset}" "${sums_file}" | awk -v asset="${asset}" '$2 == asset' | shasum -a 256 -c -
    else
        echo "::error::No SHA-256 verifier found on PATH"
        exit 1
    fi
}

sha256_file() {
    local file="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file}" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${file}" | awk '{print $1}'
    else
        echo "::error::No SHA-256 verifier found on PATH"
        exit 1
    fi
}

verify_attestation() {
    local repo="$1"
    local version="$2"
    local artifact="$3"

    if [[ "${RUNSEAL_VERIFY_ATTESTATIONS}" != "true" ]]; then
        echo "::warning::GitHub artifact attestation verification disabled for ${artifact}"
        return
    fi

    if ! command -v gh >/dev/null 2>&1; then
        echo "::error::gh CLI is required to verify GitHub artifact attestations"
        exit 1
    fi

    echo "Verifying GitHub artifact attestation for ${artifact} from ${repo}"
    gh attestation verify "${artifact}" \
        --repo "${repo}" \
        --signer-repo "${repo}" \
        --source-ref "refs/tags/v${version}" \
        --deny-self-hosted-runners
}

download_checksums() {
    local repo="$1"
    local version="$2"
    local output="$3"
    local base_url="https://github.com/${repo}/releases/download/v${version}"

    if curl -fsSL "${base_url}/SHA256SUMS" -o "${output}" 2>/dev/null; then
        printf '%s\n' "SHA256SUMS"
        return
    fi
    if curl -fsSL "${base_url}/SHA256SUMS.txt" -o "${output}" 2>/dev/null; then
        printf '%s\n' "SHA256SUMS.txt"
        return
    fi

    echo "::error::No SHA256SUMS asset found for ${repo} v${version}" >&2
    exit 1
}

verify_cached_binary() {
    local name="$1"
    local repo="$2"
    local version="$3"
    local target="$4"
    local install_dir="$5"
    local asset="$6"
    local cached_binary="${install_dir}/${name}"
    local verify_root verify_dir tarball sums_file sums_asset cached_hash verified_hash

    verify_root="${RUNNER_TEMP:-/tmp}"
    mkdir -p "${verify_root}"
    verify_dir="$(mktemp -d "${verify_root}/runseal-verify.XXXXXX")"
    tarball="${verify_dir}/${asset}"
    sums_file="${verify_dir}/SHA256SUMS"

    echo "Verifying cached ${name} v${version} at ${cached_binary}"
    curl -fsSL "https://github.com/${repo}/releases/download/v${version}/${asset}" -o "${tarball}"
    sums_asset="$(download_checksums "${repo}" "${version}" "${sums_file}")"
    if [[ "${sums_asset}" != "$(basename "${sums_file}")" ]]; then
        mv "${sums_file}" "${verify_dir}/${sums_asset}"
        sums_file="${verify_dir}/${sums_asset}"
    fi
    (
        cd "${verify_dir}"
        verify_attestation "${repo}" "${version}" "${asset}"
        verify_checksum "${sums_file}" "${asset}"
        tar -xzf "${asset}"
    )

    if [[ ! -x "${verify_dir}/${name}" ]]; then
        echo "::error::Verified ${asset} did not contain executable ${name}"
        rm -rf "${verify_dir}"
        exit 1
    fi

    cached_hash="$(sha256_file "${cached_binary}")"
    verified_hash="$(sha256_file "${verify_dir}/${name}")"
    rm -rf "${verify_dir}"

    if [[ "${cached_hash}" != "${verified_hash}" ]]; then
        echo "::error::Cached ${name} binary does not match verified ${repo} v${version} release artifact"
        exit 1
    fi
}

install_release_binary() {
    local name="$1"
    local repo="$2"
    local requested_version="$3"
    local target="$4"
    local version asset url install_dir tarball sums_file sums_asset

    version="$(resolve_version "${repo}" "${requested_version}")"
    asset="${name}-v${version}-${target}.tar.gz"
    url="https://github.com/${repo}/releases/download/v${version}/${asset}"
    install_dir="${INSTALL_ROOT}/${name}/${version}/${target}"
    tarball="${install_dir}/${asset}"
    sums_file="${install_dir}/SHA256SUMS"

    if [[ -x "${install_dir}/${name}" ]]; then
        echo "${name} v${version} already installed at ${install_dir}/${name}"
        verify_cached_binary "${name}" "${repo}" "${version}" "${target}" "${install_dir}" "${asset}"
        echo "${install_dir}" >> "${GITHUB_PATH}"
        export PATH="${install_dir}:${PATH}"
        return
    fi

    mkdir -p "${install_dir}"
    echo "Downloading ${name} v${version} for ${target}"
    curl -fsSL "${url}" -o "${tarball}"
    sums_asset="$(download_checksums "${repo}" "${version}" "${sums_file}")"
    if [[ "${sums_asset}" != "$(basename "${sums_file}")" ]]; then
        mv "${sums_file}" "${install_dir}/${sums_asset}"
        sums_file="${install_dir}/${sums_asset}"
    fi
    (
        cd "${install_dir}"
        verify_attestation "${repo}" "${version}" "${asset}"
        verify_checksum "${sums_file}" "${asset}"
        tar -xzf "${asset}"
        rm -f "${asset}" "${sums_asset}"
    )
    chmod +x "${install_dir}/${name}"
    echo "${install_dir}" >> "${GITHUB_PATH}"
    export PATH="${install_dir}:${PATH}"
}

install_runseal_from_source() {
    local target="$1"
    local install_dir="${INSTALL_ROOT}/runseal/source/${target}"

    if [[ -z "${RUNSEAL_ACTION_PATH}" ]]; then
        echo "::error::RUNSEAL_ACTION_PATH is required when runseal-version is 'source'"
        exit 1
    fi

    mkdir -p "${install_dir}"
    echo "Building runseal from action source at ${RUNSEAL_ACTION_PATH}"
    (
        cd "${RUNSEAL_ACTION_PATH}"
        cargo build --release --locked
        cp target/release/runseal "${install_dir}/runseal"
    )
    chmod +x "${install_dir}/runseal"
    echo "${install_dir}" >> "${GITHUB_PATH}"
    export PATH="${install_dir}:${PATH}"
}

TARGET="$(detect_target)"

mkdir -p "${HOME}/.nono/sessions"
chmod 700 "${HOME}/.nono" "${HOME}/.nono/sessions"

install_release_binary "nono" "${NONO_REPO}" "${NONO_VERSION}" "${TARGET}"

if [[ "${RUNSEAL_VERSION}" == "source" ]]; then
    install_runseal_from_source "${TARGET}"
else
    install_release_binary "runseal" "${RUNSEAL_REPO}" "${RUNSEAL_VERSION}" "${TARGET}"
fi

nono --version
runseal --version
