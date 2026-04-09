#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "70_manifest_mutation_smoke"

printf 'mutation note\n' >"${CASE_DIR}/note.txt"
PKG_NAME="mutation-local_0.0.1_amd64.deb"
create_local_deb "${CASE_DIR}/${PKG_NAME}" mutation-local 0.0.1 "mutation-local-ok"

run_case_expect_ok \
    "archive_add" \
    archive add -c "extra debian mirror" https://deb.debian.org/debian/ --suite trixie --components main
assert_manifest_comment_attached_to_block \
    "extra debian mirror" \
    "[[archive]]" \
    'url = "https://deb.debian.org/debian/"'

run_case_expect_ok "require_comment" require -c "desktop tooling" curl
assert_manifest_comment_attached_to_list_item "desktop tooling" '"curl"'

run_case_expect_ok "forbid_comment" forbid -c "systemd guard" 'systemd (<< 255)'
assert_manifest_comment_attached_to_list_item "systemd guard" '"systemd (<< 255)"'

assert_manifest_comment_attached_to_block \
    "extra debian mirror" \
    "[[archive]]" \
    'url = "https://deb.debian.org/debian/"'
assert_manifest_comment_attached_to_list_item "desktop tooling" '"curl"'

run_case_expect_ok "artifact_add" artifact add -c "notice artifact" ./note.txt /etc/mutation/notice.txt
assert_manifest_comment_attached_to_block \
    "notice artifact" \
    '[artifact."./note.txt"]' \
    'target = "/etc/mutation/notice.txt"'

run_case_expect_ok "stage_comment" stage -c "stage note" ./note.txt
assert_manifest_comment_attached_to_list_item "stage note" '"./note.txt"'

run_case_expect_ok "deb_add" deb add -c "local package" "./${PKG_NAME}"
assert_manifest_comment_attached_to_block \
    "local package" \
    "[[local]]" \
    "path = \"./${PKG_NAME}\""

assert_manifest_comment_attached_to_block \
    "extra debian mirror" \
    "[[archive]]" \
    'url = "https://deb.debian.org/debian/"'
assert_manifest_comment_attached_to_list_item "desktop tooling" '"curl"'
assert_manifest_comment_attached_to_list_item "systemd guard" '"systemd (<< 255)"'
assert_manifest_comment_attached_to_block \
    "notice artifact" \
    '[artifact."./note.txt"]' \
    'target = "/etc/mutation/notice.txt"'
assert_manifest_comment_attached_to_list_item "stage note" '"./note.txt"'

run_case_expect_ok "remove_requirement" remove --requirements-only curl
assert_manifest_lacks "# desktop tooling"
assert_manifest_lacks_comment_attached_to_list_item "desktop tooling" '"curl"'
assert_manifest_lacks "\"curl\""
assert_manifest_comment_attached_to_block \
    "extra debian mirror" \
    "[[archive]]" \
    'url = "https://deb.debian.org/debian/"'
assert_manifest_comment_attached_to_list_item "systemd guard" '"systemd (<< 255)"'
assert_manifest_comment_attached_to_block \
    "notice artifact" \
    '[artifact."./note.txt"]' \
    'target = "/etc/mutation/notice.txt"'
assert_manifest_comment_attached_to_list_item "stage note" '"./note.txt"'
assert_manifest_comment_attached_to_block \
    "local package" \
    "[[local]]" \
    "path = \"./${PKG_NAME}\""

run_case_expect_ok "remove_constraint" remove --constraints-only 'systemd (<< 255)'
assert_manifest_lacks "# systemd guard"
assert_manifest_lacks_comment_attached_to_list_item "systemd guard" '"systemd (<< 255)"'
assert_manifest_lacks "\"systemd (<< 255)\""
assert_manifest_comment_attached_to_block \
    "extra debian mirror" \
    "[[archive]]" \
    'url = "https://deb.debian.org/debian/"'
assert_manifest_comment_attached_to_block \
    "notice artifact" \
    '[artifact."./note.txt"]' \
    'target = "/etc/mutation/notice.txt"'
assert_manifest_comment_attached_to_list_item "stage note" '"./note.txt"'
assert_manifest_comment_attached_to_block \
    "local package" \
    "[[local]]" \
    "path = \"./${PKG_NAME}\""

run_case_expect_fail "remove_missing_spec" remove --spec missing curl
assert_stderr_contains "spec missing not found"

run_case_expect_ok "unstage" unstage ./note.txt
assert_manifest_lacks "# notice artifact"
assert_manifest_lacks "# stage note"
assert_manifest_lacks_comment_attached_to_block \
    "notice artifact" \
    '[artifact."./note.txt"]' \
    'target = "/etc/mutation/notice.txt"'
assert_manifest_lacks_comment_attached_to_list_item "stage note" '"./note.txt"'
assert_manifest_lacks "[artifact.\"./note.txt\"]"
assert_manifest_comment_attached_to_block \
    "extra debian mirror" \
    "[[archive]]" \
    'url = "https://deb.debian.org/debian/"'
assert_manifest_comment_attached_to_block \
    "local package" \
    "[[local]]" \
    "path = \"./${PKG_NAME}\""

run_case_expect_fail "unstage_missing" unstage ./note.txt
assert_stderr_contains "artifact ./note.txt not found in spec"

run_case_expect_ok "archive_remove" archive remove https://deb.debian.org/debian/
assert_manifest_lacks "# extra debian mirror"
assert_manifest_lacks_comment_attached_to_block \
    "extra debian mirror" \
    "[[archive]]" \
    'url = "https://deb.debian.org/debian/"'
assert_manifest_lacks "https://deb.debian.org/debian/"
assert_manifest_comment_attached_to_block \
    "local package" \
    "[[local]]" \
    "path = \"./${PKG_NAME}\""

run_case_expect_fail "archive_remove_missing" archive remove https://deb.debian.org/debian/
assert_stderr_contains "archive https://deb.debian.org/debian/ not found"

run_case_expect_ok "deb_remove" deb remove "./${PKG_NAME}"
assert_manifest_lacks "# local package"
assert_manifest_lacks_comment_attached_to_block \
    "local package" \
    "[[local]]" \
    "path = \"./${PKG_NAME}\""
assert_manifest_lacks "${PKG_NAME}"

run_case_expect_fail "deb_remove_missing" deb remove "./${PKG_NAME}"
assert_stderr_contains "local package ./${PKG_NAME} not found"
