#!/usr/bin/env bash
#
# Fails if the runseal or nono version drifts between the places that pin it.
# Cargo.toml is the source of truth for runseal; .github/nono-version/Cargo.toml
# is the Dependabot-managed source of truth for nono.

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

NONO_MANIFEST=".github/nono-version/Cargo.toml"
NONO_VERSION="$(bash scripts/nono-pinned-version.sh)"

printf 'runseal %s (Cargo.toml) · nono %s (%s)\n\n' \
    "${RUNSEAL_VERSION}" "${NONO_VERSION}" "${NONO_MANIFEST}"

# --- runseal version -------------------------------------------------------

expect "setup.sh RUNSEAL_VERSION default" "${RUNSEAL_VERSION}" \
    "$(extract '^RUNSEAL_VERSION="\$\{RUNSEAL_VERSION:-([0-9]+\.[0-9]+\.[0-9]+)\}"$' setup.sh)"

expect "action.yml runseal-version default" "${RUNSEAL_VERSION}" \
    "$(sed -nE '/^  runseal-version:/,/^  [a-z]/ s/^    default: "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' action.yml)"

expect "README runseal-version input row" "${RUNSEAL_VERSION}" \
    "$(extract '^\| `runseal-version` \| No \| `([0-9]+\.[0-9]+\.[0-9]+)` \|.*$' README.md)"

# --- nono version ----------------------------------------------------------

# The nono version is single-sourced in ${NONO_MANIFEST} so Dependabot can bump
# it in one place. Nothing else may restate it: setup.sh and action.yml default to
# empty and resolve the pin at install time, and the README defers to the manifest.

# `extract` cannot tell an empty capture from a missing line, so match the whole
# line: a deleted default must fail here rather than read as "correctly empty".
if grep -qxF 'NONO_VERSION="${NONO_VERSION:-}"' setup.sh; then
    ok "setup.sh NONO_VERSION defaults to the pin (empty)"
else
    fail "setup.sh must contain the exact line NONO_VERSION=\"\${NONO_VERSION:-}\"; found '$(extract '^(NONO_VERSION=.*)$' setup.sh)'"
fi

expect "action.yml nono-version default" '""' \
    "$(sed -nE '/^  nono-version:/,/^  [a-z]/ s/^    default: (.+)$/\1/p' action.yml)"

NONO_README_DEFAULT="$(
    awk -F'|' '/^\| `nono-version` \|/ {gsub(/^ +| +$/, "", $4); print $4; exit}' README.md
)"
if [[ -z "${NONO_README_DEFAULT}" ]]; then
    fail "README nono-version input row not found"
elif [[ "${NONO_README_DEFAULT}" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
    fail "README nono-version default '${NONO_README_DEFAULT}' hardcodes a version; defer to ${NONO_MANIFEST}"
else
    ok "README nono-version default defers to the pin (${NONO_README_DEFAULT})"
fi

NONO_PIN_WORKFLOW=".github/workflows/nono-pin.yml"
NONO_OVERRIDE="$(extract '^          nono-version: "([0-9]+\.[0-9]+\.[0-9]+)"$' "${NONO_PIN_WORKFLOW}")"
if [[ -z "${NONO_OVERRIDE}" ]]; then
    fail "no bare X.Y.Z nono-version override found in ${NONO_PIN_WORKFLOW}"
elif [[ "${NONO_OVERRIDE}" == "${NONO_VERSION}" ]]; then
    fail "${NONO_PIN_WORKFLOW} override ${NONO_OVERRIDE} equals the pin; the override job would pass vacuously"
else
    ok "nono-pin.yml override ${NONO_OVERRIDE} differs from the pin ${NONO_VERSION}"
fi

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
