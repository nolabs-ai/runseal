#!/usr/bin/env bash
# Reject binaries that would silently ignore requested profile or audit behavior.
set -euo pipefail

profile_input="${RUNSEAL_PROFILE:-}"
if [[ -n "${profile_input//[[:space:]]/}" ]]; then
    if ! capabilities="$(runseal capabilities)"; then
        echo "::error::The installed runseal does not support profile; select runseal 0.3.4 or newer, or runseal-version: source." >&2
        exit 1
    fi
    if ! grep -qxF 'repo-profile-v1' <<< "${capabilities}"; then
        echo "::error::The installed runseal does not advertise repo-profile-v1; refusing to ignore profile." >&2
        exit 1
    fi
fi

if [[ "${RUNSEAL_AUDIT:-false}" =~ ^[[:space:]]*(artifact|true)[[:space:]]*$ ]]; then
    if ! capabilities="$(runseal capabilities)" || ! grep -qxF 'audit-session-v1' <<< "${capabilities}"; then
        echo "::error::The installed runseal does not advertise audit-session-v1; select a release containing exact audit session export, or runseal-version: source." >&2
        exit 1
    fi
fi

exec runseal run
