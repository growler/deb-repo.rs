#!/usr/bin/env bash
set -euo pipefail

# Reproduces a regression where a local .deb with a higher version than the
# upstream archive is ignored by the solver because sort_candidates prefers
# higher numeric priority (archive=500 beats local=0).
#
# Uses "ed" because it is a leaf package with no tight versioned
# reverse-dependencies, unlike "sed" which other packages pin by exact version.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "160_local_deb_overrides_archive"

# Require "ed" so it appears in the resolved spec.
run_case_rdb require ed

# Capture the upstream archive version.
archive_version="$(run_case_rdb list | awk '$2 == "ed" { print $3 }')"
note "Archive version of ed: ${archive_version}"
[[ -n "${archive_version}" ]] || die "could not determine archive version of ed"

# Bump the epoch to guarantee a higher version than the archive.
local_version="99:${archive_version}.local"

# Create a local .deb with the higher version.
DEB_NAME="ed_local_amd64.deb"
DEB_PATH="${CASE_DIR}/${DEB_NAME}"
create_local_deb "${DEB_PATH}" "ed" "${local_version}" "local-ed-ok"

# Import the local .deb and refresh.
run_case_rdb deb add "./${DEB_NAME}"

# Verify `list` shows the local version, not the archive version.
listed_version="$(run_case_rdb list | awk '$2 == "ed" { print $3 }')"
note "Listed version of ed after local override: ${listed_version}"

if [[ "${listed_version}" == "${local_version}" ]]; then
    note "PASS: local version selected"
else
    die "FAIL: expected version '${local_version}', got '${listed_version}' (archive version was '${archive_version}')"
fi
