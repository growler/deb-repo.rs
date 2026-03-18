#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

prepare_case "155_artifact_lock_safety_unlocked"
: >"${MANIFEST}"
cp -- "${MANIFEST}" "${CASE_DIR}/Manifest.before.toml"
printf 'base artifact\n' >"${CASE_DIR}/base.txt"

run_case_expect_fail "artifact_add_unlocked" artifact add ./base.txt /opt/import/base.txt
assert_stderr_contains "manifest lock is not live; run update first"
assert_file_lacks "${LAST_STDERR}" "panicked at"
cmp -s "${MANIFEST}" "${CASE_DIR}/Manifest.before.toml" || die "manifest changed after failed unlocked artifact add"
assert_path_missing "${LOCK}"

bootstrap_manifest "155_artifact_lock_safety_locked"
printf 'locked artifact\n' >"${CASE_DIR}/locked.txt"

run_case_expect_ok "artifact_add_locked" artifact add ./locked.txt /opt/lock-safety/locked.txt
run_case_expect_ok "spec_artifact_new_spec" spec artifact add -s child ./locked.txt
run_case_expect_ok "spec_hash_child" spec hash child
assert_stdout_matches '^[0-9a-f]+$'

printf '\n# stale lock marker\n' >>"${MANIFEST}"
cp -- "${MANIFEST}" "${CASE_DIR}/Manifest.before-stale.toml"

run_case_expect_fail "spec_artifact_stale_lock" spec artifact add -s stale ./locked.txt
assert_stderr_contains "manifest lock is not live; run update first"
assert_file_lacks "${LAST_STDERR}" "panicked at"
cmp -s "${MANIFEST}" "${CASE_DIR}/Manifest.before-stale.toml" || die "manifest changed after failed stale-lock artifact add"
assert_manifest_lacks "[spec.stale]"
