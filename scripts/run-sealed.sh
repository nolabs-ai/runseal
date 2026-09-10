#!/usr/bin/env bash
# Reject binaries that would silently ignore the profile input.
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

exec runseal run
