#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "30_local_tar_artifact_refresh"

ARTIFACT_SRC="${CASE_DIR}/artifact-src"
ARTIFACT_TAR="${CASE_DIR}/artifact.tar.gz"
TREE_V1="${CASE_DIR}/tree-v1"
TREE_V2="${CASE_DIR}/tree-v2"
trap 'cleanup_tree "${TREE_V1}"; cleanup_tree "${TREE_V2}"' EXIT

mkdir -p "${ARTIFACT_SRC}"
printf 'v1\n' >"${ARTIFACT_SRC}/marker.txt"
tar -C "${ARTIFACT_SRC}" -czf "${ARTIFACT_TAR}" .

run_case_rdb artifact add --stage ./artifact.tar.gz /opt/integration/
build_tree "sandbox" "${TREE_V1}"
assert_runtime_file_content "${TREE_V1}" /opt/integration/marker.txt "v1"

cleanup_tree "${TREE_V1}"

printf 'v2\n' >"${ARTIFACT_SRC}/marker.txt"
tar -C "${ARTIFACT_SRC}" -czf "${ARTIFACT_TAR}" .

run_case_rdb update --locals
build_tree "sandbox" "${TREE_V2}"
assert_runtime_file_content "${TREE_V2}" /opt/integration/marker.txt "v2"

cleanup_tree "${TREE_V2}"
trap - EXIT
