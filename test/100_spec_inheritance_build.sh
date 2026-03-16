#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "100_spec_inheritance_build"
require_rootless_podman
trap 'cleanup_tree "${TREE_DIR}"' EXIT

printf 'base artifact\n' >"${CASE_DIR}/base.txt"
printf 'child artifact\n' >"${CASE_DIR}/child.txt"

run_case_expect_ok "artifact_base" artifact add ./base.txt /opt/inherit/base.txt
run_case_expect_ok "artifact_child" artifact add ./child.txt /opt/inherit/child.txt

cat >>"${MANIFEST}" <<'EOF'

[spec.base]
include = ["tar"]
stage = ["./base.txt"]
build-script = """
mkdir -p /opt/inherit
printf '%s\n' "$BASE_VALUE" > /opt/inherit/base-env.txt
printf '%s\n' "base" > /opt/inherit/script-order.txt
"""

[spec.base.build-env]
BASE_VALUE = "from-base"
COMMON = "base"

[spec.desktop]
extends = "base"
include = ["rsync"]
stage = ["./child.txt"]
build-script = """
printf '%s\n' "$COMMON" > /opt/inherit/common-env.txt
printf '%s\n' "derived" >> /opt/inherit/script-order.txt
"""

[spec.desktop.build-env]
COMMON = "desktop"
EOF

run_case_expect_ok "update_inheritance" update
run_case_rdb build -s desktop --path "${TREE_DIR}"
assert_file_exists "${TREE_DIR}"

assert_runtime_packages "${TREE_DIR}" tar rsync
assert_runtime_file_content "${TREE_DIR}" /opt/inherit/base.txt "base artifact"
assert_runtime_file_content "${TREE_DIR}" /opt/inherit/child.txt "child artifact"
assert_runtime_file_content "${TREE_DIR}" /opt/inherit/base-env.txt "from-base"
assert_runtime_file_content "${TREE_DIR}" /opt/inherit/common-env.txt "desktop"
assert_runtime_file_content "${TREE_DIR}" /opt/inherit/script-order.txt $'base\nderived'

cleanup_tree "${TREE_DIR}"
trap - EXIT
