#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "80_spec_subcommands"

printf 'desktop note\n' >"${CASE_DIR}/desktop-note.txt"

run_case_expect_ok "spec_list_initial" spec list
assert_stdout_contains "<default>"

run_case_expect_ok "artifact_add" artifact add ./desktop-note.txt /etc/desktop/note.txt
run_case_expect_ok "spec_require" spec require -s desktop -c "desktop packages" openssh-server
assert_manifest_contains "# desktop packages"

run_case_expect_ok "spec_forbid" spec forbid -s desktop -c "desktop constraints" 'systemd (<< 1)'
assert_manifest_contains "# desktop constraints"

run_case_expect_ok "spec_artifact_add" spec artifact add -s desktop -c "desktop stage" ./desktop-note.txt
assert_manifest_contains "# desktop stage"

run_case_expect_ok "spec_meta_set" spec meta set -s desktop role workstation
run_case_expect_ok "spec_meta_get" spec meta get -s desktop role
assert_equals "workstation" "$(tr -d '\n' <"${LAST_STDOUT}")" "desktop role"

run_case_expect_ok "spec_list_after" spec list
assert_stdout_contains "<default>"
assert_stdout_contains "desktop"

run_case_expect_ok "spec_packages" spec packages -s desktop
assert_stdout_contains "openssh-server"

run_case_expect_ok "spec_hash_before" spec hash desktop
hash_before="$(tr -d '\n' <"${LAST_STDOUT}")"

run_case_expect_ok "spec_require_extra" spec require -s desktop rsync
run_case_expect_ok "spec_hash_after" spec hash desktop
hash_after="$(tr -d '\n' <"${LAST_STDOUT}")"
assert_not_equals "${hash_before}" "${hash_after}" "desktop spec hash"

run_case_expect_ok "spec_hash_sri" spec hash --sri desktop
assert_stdout_matches '^[a-z0-9]+-[A-Za-z0-9+/=]+$'

run_case_expect_ok "spec_remove_requirement" spec remove -s desktop --requirements-only rsync
assert_manifest_lacks "\"rsync\""

run_case_expect_ok "spec_remove_constraint" spec remove -s desktop --constraints-only 'systemd (<< 1)'
assert_manifest_lacks "\"systemd (<< 1)\""

run_case_expect_ok "spec_artifact_remove" spec artifact remove -s desktop ./desktop-note.txt
assert_manifest_lacks "[artifact.\"./desktop-note.txt\"]"
