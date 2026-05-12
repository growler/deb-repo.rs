#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "200_manifest_import_git"

if ! command -v git >/dev/null 2>&1; then
    note "skipping: git not on PATH"
    exit 0
fi

BARE_REPO="${CASE_DIR}/imported.git"
WORK_DIR="${CASE_DIR}/git-work"
GIT_CACHE="${CASE_DIR}/git-cache"
DOWNSTREAM_DIR="${CASE_DIR}/downstream"
DOWNSTREAM_MANIFEST="${DOWNSTREAM_DIR}/Manifest.toml"

mkdir -p "${BARE_REPO}" "${WORK_DIR}" "${GIT_CACHE}" "${DOWNSTREAM_DIR}"

git_in() {
    local workdir="$1"
    shift
    GIT_AUTHOR_NAME=test \
    GIT_AUTHOR_EMAIL=test@example.invalid \
    GIT_COMMITTER_NAME=test \
    GIT_COMMITTER_EMAIL=test@example.invalid \
    GIT_TERMINAL_PROMPT=0 \
        git -C "${workdir}" "$@"
}

git init --bare -q "${BARE_REPO}"
git_in "${WORK_DIR}" init -q -b main
git_in "${WORK_DIR}" remote add origin "${BARE_REPO}"

mkdir -p "${WORK_DIR}/system"
cp -- "${MANIFEST}" "${WORK_DIR}/system/Manifest.toml"
cp -- "${LOCK}"     "${WORK_DIR}/system/Manifest.amd64.lock"

git_in "${WORK_DIR}" add -A
git_in "${WORK_DIR}" commit -q -m 'seed imported manifest'
git_in "${WORK_DIR}" push -q origin main

HEAD_SHA="$(git_in "${WORK_DIR}" rev-parse HEAD)"
BARE_REPO_REAL="$(readlink -f "${BARE_REPO}")"

run_downstream() {
    local label="$1"
    shift
    LAST_STDOUT="${CASE_DIR}/${label}.stdout"
    LAST_STDERR="${CASE_DIR}/${label}.stderr"
    if ( cd "${DOWNSTREAM_DIR}" \
        && "${RDEBOOTSTRAP}" --cache-dir "${GIT_CACHE}" -m "${DOWNSTREAM_MANIFEST}" "$@"
       ) >"${LAST_STDOUT}" 2>"${LAST_STDERR}"; then
        LAST_STATUS=0
    else
        LAST_STATUS=$?
        tail -n 40 "${LAST_STDERR}" >&2 || true
        die "downstream command failed (${label}): rdebootstrap --cache-dir ${GIT_CACHE} -m ${DOWNSTREAM_MANIFEST} $*"
    fi
}

# Initialise the downstream manifest from a git+file:// import.  The manifest
# stores the full file:// URL as the remote identifier.
run_downstream "init_git" \
    init \
    --import "git+file://${BARE_REPO_REAL}?rev=${HEAD_SHA}#system/Manifest.toml"

assert_file_exists "${DOWNSTREAM_MANIFEST}"
assert_file_contains "${DOWNSTREAM_MANIFEST}" "[import.git]"
assert_file_contains "${DOWNSTREAM_MANIFEST}" "remote = \"file://${BARE_REPO_REAL}\""
assert_file_contains "${DOWNSTREAM_MANIFEST}" "rev = \"${HEAD_SHA}\""
assert_file_contains "${DOWNSTREAM_MANIFEST}" 'path = "system/Manifest.toml"'

LOCK_PATH="${DOWNSTREAM_DIR}/Manifest.amd64.lock"
assert_file_exists "${LOCK_PATH}"

# Reload via `update --locals` and confirm it is a no-op when no symbolic
# ref is recorded (rev is exact).
run_downstream "update_locals_noop" update --locals
assert_file_contains "${DOWNSTREAM_MANIFEST}" "rev = \"${HEAD_SHA}\""

# Push a second commit on `main` to verify that re-resolving a symbolic
# ref through the import subcommand tracks it.
printf '\n# second commit\n' >>"${WORK_DIR}/system/Manifest.toml"
( cd "${WORK_DIR}" && "${RDEBOOTSTRAP}" -m system/Manifest.toml update >/dev/null )
git_in "${WORK_DIR}" add -A
git_in "${WORK_DIR}" commit -q -m 'tweak imported manifest'
git_in "${WORK_DIR}" push -q origin main
NEW_SHA="$(git_in "${WORK_DIR}" rev-parse HEAD)"

# Re-import with a symbolic ref so that `update --locals` can track it later.
run_downstream "import_main_ref" \
    import "git+file://${BARE_REPO_REAL}?ref=main#system/Manifest.toml"
assert_file_contains "${DOWNSTREAM_MANIFEST}" "rev = \"${NEW_SHA}\""
assert_file_contains "${DOWNSTREAM_MANIFEST}" 'ref = "main"'
assert_file_contains "${DOWNSTREAM_MANIFEST}" "remote = \"file://${BARE_REPO_REAL}\""

# Confirm that no bare clone directories exist: git+file:// imports use the
# source repo directly and must never create a repo.git in the cache.
BARE_COUNT=$(find "${GIT_CACHE}/git" -mindepth 2 -maxdepth 3 -name 'repo.git' -type d 2>/dev/null | wc -l)
if [ "${BARE_COUNT}" -ne 0 ]; then
    die "git+file:// import created unexpected bare clone(s) in ${GIT_CACHE}/git (count=${BARE_COUNT})"
fi

note "git-import scenario passed (HEAD ${HEAD_SHA:0:7} -> ${NEW_SHA:0:7})"
