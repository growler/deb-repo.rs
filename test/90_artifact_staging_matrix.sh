#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "90_artifact_staging_matrix"
require_rootless_podman

TREE_MATRIX="${CASE_DIR}/tree-matrix"
trap 'cleanup_tree "${TREE_MATRIX}"' EXIT

mkdir -p "${CASE_DIR}/asset-dir"
mkdir -p "${CASE_DIR}/archive-src"
printf 'single artifact\n' >"${CASE_DIR}/single.txt"
printf 'dir artifact\n' >"${CASE_DIR}/asset-dir/nested.txt"
printf 'tar payload\n' >"${CASE_DIR}/archive-src/payload.txt"
printf '#!/bin/bash\necho mode\n' >"${CASE_DIR}/mode-script.sh"
printf 'amd64 only\n' >"${CASE_DIR}/amd64-only.txt"
printf 'arm64 only\n' >"${CASE_DIR}/arm64-only.txt"
printf 'trailing target\n' >"${CASE_DIR}/trailing.txt"
tar -C "${CASE_DIR}/archive-src" -czf "${CASE_DIR}/archive.tar.gz" .

run_case_expect_ok "artifact_single" artifact add --stage ./single.txt /opt/matrix/single-target.txt
run_case_expect_ok "artifact_dir" artifact add --stage ./asset-dir /opt/matrix/assets/
run_case_expect_ok "artifact_archive" artifact add --stage --no-unpack ./archive.tar.gz /opt/matrix/archive.tar.gz
run_case_expect_ok "artifact_mode" artifact add --stage --mode 0750 ./mode-script.sh /opt/matrix/bin/mode-script.sh
run_case_expect_ok "artifact_amd64" artifact add --stage --only-arch amd64 ./amd64-only.txt /opt/matrix/amd64-only.txt
run_case_expect_ok "artifact_arm64" artifact add --stage --only-arch arm64 ./arm64-only.txt /opt/matrix/arm64-only.txt
run_case_expect_ok "artifact_trailing" artifact add --stage ./trailing.txt /opt/matrix/trailing/

run_case_expect_ok "refresh_locals" update --locals
build_tree "sandbox" "${TREE_MATRIX}"

assert_runtime_file_content "${TREE_MATRIX}" /opt/matrix/single-target.txt "single artifact"
assert_runtime_file_content "${TREE_MATRIX}" /opt/matrix/assets/nested.txt "dir artifact"
assert_runtime_file "${TREE_MATRIX}" /opt/matrix/archive.tar.gz
assert_runtime_mode "${TREE_MATRIX}" /opt/matrix/bin/mode-script.sh "750"
assert_runtime_file_content "${TREE_MATRIX}" /opt/matrix/amd64-only.txt "amd64 only"
assert_runtime_file_missing "${TREE_MATRIX}" /opt/matrix/arm64-only.txt
assert_runtime_file_content "${TREE_MATRIX}" /opt/matrix/trailing/trailing.txt "trailing target"

cleanup_tree "${TREE_MATRIX}"
trap - EXIT
