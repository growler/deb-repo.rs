#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "110_lock_error_paths"

TREE_V1="${CASE_DIR}/tree-v1"
TREE_V2="${CASE_DIR}/tree-v2"
trap 'cleanup_tree "${TREE_V1}"; cleanup_tree "${TREE_V2}"' EXIT

rm -f -- "${LOCK}"
run_case_expect_fail "build_missing_lock" build --path "${TREE_DIR}"

bootstrap_manifest "110_lock_error_paths"
cat >>"${MANIFEST}" <<'EOF'

[spec.extra]
include = ["curl"]
EOF
run_case_expect_fail "build_stale_lock" build --path "${TREE_DIR}"

bootstrap_manifest "110_lock_error_paths"
cp -- "${LOCK}" "${CASE_DIR}/lock.before"
run_case_expect_ok "update_noop" update
cmp -s "${LOCK}" "${CASE_DIR}/lock.before" || die "update rewrote an up-to-date lock"

printf 'artifact-v1\n' >"${CASE_DIR}/refresh-note.txt"
PKG_NAME="refresh-local_0.0.1_amd64.deb"
PKG_PATH="${CASE_DIR}/${PKG_NAME}"
create_local_deb "${PKG_PATH}" refresh-local 0.0.1 "package-v1"

run_case_expect_ok "artifact_add" artifact add --stage ./refresh-note.txt /opt/refresh/note.txt
run_case_expect_ok "deb_add" deb add "./${PKG_NAME}"
run_case_expect_ok "require_refresh_local" require refresh-local

require_rootless_podman
build_tree "sandbox" "${TREE_V1}"
assert_runtime_file_content "${TREE_V1}" /opt/refresh/note.txt "artifact-v1"
assert_equals \
    "package-v1" \
    "$(run_podman_rootfs "${TREE_V1}" /usr/local/bin/refresh-local)" \
    "refresh-local output v1"
cleanup_tree "${TREE_V1}"

printf 'artifact-v2\n' >"${CASE_DIR}/refresh-note.txt"
create_local_deb "${PKG_PATH}" refresh-local 0.0.1 "package-v2"
run_case_expect_ok "refresh_locals" update --locals

build_tree "sandbox" "${TREE_V2}"
assert_runtime_file_content "${TREE_V2}" /opt/refresh/note.txt "artifact-v2"
assert_equals \
    "package-v2" \
    "$(run_podman_rootfs "${TREE_V2}" /usr/local/bin/refresh-local)" \
    "refresh-local output v2"

cleanup_tree "${TREE_V2}"
trap - EXIT
