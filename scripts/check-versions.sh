#!/usr/bin/env bash
#
# Fails if the runseal or nono version drifts between the places that pin it.
# Cargo.toml is the source of truth for runseal, setup.sh for nono.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

FAIL=0

fail() {
    printf '::error::%s\n' "$*" >&2
    FAIL=1
}

ok() {
    printf '  ok   %s\n' "$*"
}

# Extract the first capture group of an ERE from a file, or the empty string.
extract() {
    local pattern="$1" file="$2"
    sed -nE "s/${pattern}/\1/p" "${file}" | head -n 1
}

expect() {
    local label="$1" expected="$2" actual="$3"
    if [[ "${actual}" != "${expected}" ]]; then
        fail "${label}: expected '${expected}', found '${actual:-<not found>}'"
    else
        ok "${label} = ${actual}"
    fi
}

RUNSEAL_VERSION="$(extract '^version = "([0-9]+\.[0-9]+\.[0-9]+)"$' Cargo.toml)"
if [[ -z "${RUNSEAL_VERSION}" ]]; then
    fail "could not read the runseal version from Cargo.toml"
    exit 1
fi

NONO_VERSION="$(extract '^NONO_VERSION="\$\{NONO_VERSION:-([0-9]+\.[0-9]+\.[0-9]+)\}"$' setup.sh)"
if [[ -z "${NONO_VERSION}" ]]; then
    fail "could not read the pinned nono version from setup.sh"
    exit 1
fi

printf 'runseal %s (Cargo.toml) · nono %s (setup.sh)\n\n' "${RUNSEAL_VERSION}" "${NONO_VERSION}"

# --- runseal version -------------------------------------------------------

expect "setup.sh RUNSEAL_VERSION default" "${RUNSEAL_VERSION}" \
    "$(extract '^RUNSEAL_VERSION="\$\{RUNSEAL_VERSION:-([0-9]+\.[0-9]+\.[0-9]+)\}"$' setup.sh)"

expect "action.yml runseal-version default" "${RUNSEAL_VERSION}" \
    "$(sed -nE '/^  runseal-version:/,/^  [a-z]/ s/^    default: "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' action.yml)"

expect "README runseal-version input row" "${RUNSEAL_VERSION}" \
    "$(extract '^\| `runseal-version` \| No \| `([0-9]+\.[0-9]+\.[0-9]+)` \|.*$' README.md)"

# --- nono version ----------------------------------------------------------

expect "action.yml nono-version default" "${NONO_VERSION}" \
    "$(sed -nE '/^  nono-version:/,/^  [a-z]/ s/^    default: "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' action.yml)"

expect "README nono-version input row" "${NONO_VERSION}" \
    "$(extract '^\| `nono-version` \| No \| `([0-9]+\.[0-9]+\.[0-9]+)` \|.*$' README.md)"

# --- action pins in docs and examples --------------------------------------
# `@main` and the floating `@v0` tag are exempt; exact pins must be current.

printf '\n'
PIN_FILES=(README.md examples recipes)
STALE_PINS="$(
    grep -rhoE 'runseal@v[0-9]+(\.[0-9]+\.[0-9]+)?' "${PIN_FILES[@]}" 2>/dev/null |
        sed 's/^runseal@//' |
        grep -vxF "v0" |
        grep -vxF "v${RUNSEAL_VERSION}" |
        sort -u || true
)"

if [[ -n "${STALE_PINS}" ]]; then
    while read -r pin; do
        [[ -z "${pin}" ]] && continue
        fail "action pin 'runseal@${pin}' does not match v${RUNSEAL_VERSION} (use v${RUNSEAL_VERSION}, the floating v0 tag, or @main)"
        grep -rn "runseal@${pin}\([^0-9.]\|$\)" "${PIN_FILES[@]}" 2>/dev/null | sed 's/^/         /' >&2 || true
    done <<< "${STALE_PINS}"
else
    ok "all pinned runseal@vX.Y.Z references match v${RUNSEAL_VERSION}"
fi

printf '\n'
if [[ "${FAIL}" -ne 0 ]]; then
    printf 'version check failed\n' >&2
    exit 1
fi
printf 'version check passed\n'
