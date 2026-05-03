#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "80_spec_subcommands"

printf 'desktop note\n' >"${CASE_DIR}/desktop-note.txt"

run_case_expect_ok "spec_list_initial" spec list
assert_stdout_contains "<default>"

run_case_expect_ok "artifact_add" artifact add ./desktop-note.txt /etc/desktop/note.txt
run_case_expect_ok "spec_require" spec require -s desktop -c "desktop packages" openssh-server
assert_manifest_comment_attached_to_list_item "desktop packages" '"openssh-server"'

run_case_expect_ok "spec_forbid" spec forbid -s desktop -c "desktop constraints" 'systemd (<< 1)'
assert_manifest_comment_attached_to_list_item "desktop constraints" '"systemd (<< 1)"'

run_case_expect_ok "spec_artifact_add" spec artifact add -s desktop -c "desktop stage" ./desktop-note.txt
assert_manifest_comment_attached_to_list_item "desktop stage" '"./desktop-note.txt"'

run_case_expect_ok "spec_meta_set" spec meta set -s desktop role workstation
assert_manifest_comment_attached_to_list_item "desktop packages" '"openssh-server"'
assert_manifest_comment_attached_to_list_item "desktop constraints" '"systemd (<< 1)"'
assert_manifest_comment_attached_to_list_item "desktop stage" '"./desktop-note.txt"'
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
assert_manifest_comment_attached_to_list_item "desktop packages" '"openssh-server"'
assert_manifest_comment_attached_to_list_item "desktop constraints" '"systemd (<< 1)"'
assert_manifest_comment_attached_to_list_item "desktop stage" '"./desktop-note.txt"'
run_case_expect_ok "spec_hash_after" spec hash desktop
hash_after="$(tr -d '\n' <"${LAST_STDOUT}")"
assert_not_equals "${hash_before}" "${hash_after}" "desktop spec hash"

run_case_expect_ok "spec_hash_sri" spec hash --sri desktop
assert_stdout_matches '^[a-z0-9]+-[A-Za-z0-9+/=]+$'

run_case_expect_ok "spec_remove_requirement" spec remove -s desktop --requirements-only rsync
assert_manifest_lacks "\"rsync\""
assert_manifest_comment_attached_to_list_item "desktop packages" '"openssh-server"'
assert_manifest_comment_attached_to_list_item "desktop constraints" '"systemd (<< 1)"'
assert_manifest_comment_attached_to_list_item "desktop stage" '"./desktop-note.txt"'

run_case_expect_ok "spec_remove_requirement_main" spec remove -s desktop --requirements-only openssh-server
assert_manifest_lacks "# desktop packages"
assert_manifest_lacks_comment_attached_to_list_item "desktop packages" '"openssh-server"'
assert_manifest_lacks "\"openssh-server\""
assert_manifest_comment_attached_to_list_item "desktop constraints" '"systemd (<< 1)"'
assert_manifest_comment_attached_to_list_item "desktop stage" '"./desktop-note.txt"'

run_case_expect_ok "spec_remove_constraint" spec remove -s desktop --constraints-only 'systemd (<< 1)'
assert_manifest_lacks "# desktop constraints"
assert_manifest_lacks_comment_attached_to_list_item "desktop constraints" '"systemd (<< 1)"'
assert_manifest_lacks "\"systemd (<< 1)\""
assert_manifest_comment_attached_to_list_item "desktop stage" '"./desktop-note.txt"'

run_case_expect_ok "spec_artifact_remove" spec artifact remove -s desktop ./desktop-note.txt
assert_manifest_lacks "# desktop stage"
assert_manifest_lacks_comment_attached_to_list_item "desktop stage" '"./desktop-note.txt"'
assert_manifest_lacks "[artifact.\"./desktop-note.txt\"]"

# --- spec extend ---

# create a backend spec and set it to extend desktop
run_case_expect_ok "spec_extend_set" spec extend -s backend desktop
assert_manifest_contains 'extends = "desktop"'

# hash changes after setting extends
run_case_expect_ok "spec_hash_before_extend" spec hash backend
hash_before_extend="$(tr -d '\n' <"${LAST_STDOUT}")"

run_case_expect_ok "spec_extend_change" spec extend -s backend desktop
run_case_expect_ok "spec_hash_after_extend" spec hash backend
hash_after_extend="$(tr -d '\n' <"${LAST_STDOUT}")"

# clear extends
run_case_expect_ok "spec_extend_clear" spec extend -s backend --clear
assert_manifest_lacks 'extends = "desktop"'

# hash changes after clearing extends
run_case_expect_ok "spec_hash_after_clear" spec hash backend
hash_after_clear="$(tr -d '\n' <"${LAST_STDOUT}")"
assert_not_equals "${hash_before_extend}" "${hash_after_clear}" "backend spec hash after clear"

# error: extend nonexistent spec
run_case_expect_fail "spec_extend_missing" spec extend -s backend no-such-spec
assert_stderr_contains "not found"

# error: self-extend
run_case_expect_fail "spec_extend_self" spec extend -s backend backend
assert_stderr_contains "cannot extend itself"

# --- multi-parent extend ---

# add additional specs to extend so we can exercise the multi-parent shape
run_case_expect_ok "spec_add_extras" spec require -s extras -c "extras packages" curl
run_case_expect_ok "spec_add_foo" spec require -s foo bash

# set two parents at once: array form is persisted
run_case_expect_ok "spec_extend_multi_set" spec extend -s backend desktop extras
assert_manifest_contains 'extends = ["desktop", "extras"]'

# --add appends a parent
run_case_expect_ok "spec_extend_add_existing" spec extend -s backend --add foo
assert_manifest_contains 'extends = ["desktop", "extras", "foo"]'

# --remove drops a single parent
run_case_expect_ok "spec_extend_remove" spec extend -s backend --remove extras
assert_manifest_contains 'extends = ["desktop", "foo"]'

# --remove down to a single parent re-emits the string form
run_case_expect_ok "spec_extend_remove_to_one" spec extend -s backend --remove foo
assert_manifest_contains 'extends = "desktop"'

# error: duplicate parent in positional list
run_case_expect_fail "spec_extend_dup" spec extend -s backend desktop desktop
assert_stderr_contains "duplicate parent"

# error: --add an existing parent
run_case_expect_fail "spec_extend_add_dup" spec extend -s backend --add desktop
assert_stderr_contains "already a parent"

# error: --remove a non-parent
run_case_expect_fail "spec_extend_remove_missing" spec extend -s backend --remove never-was
assert_stderr_contains "does not currently extend"
