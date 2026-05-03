#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "101_spec_multi_parent_build"
require_rootless_podman
trap 'cleanup_tree "${TREE_DIR}"' EXIT

printf 'tools artifact\n' >"${CASE_DIR}/tools.txt"
printf 'extras artifact\n' >"${CASE_DIR}/extras.txt"
printf 'merged artifact\n' >"${CASE_DIR}/merged.txt"

run_case_expect_ok "artifact_tools" artifact add ./tools.txt /opt/multi/tools.txt
run_case_expect_ok "artifact_extras" artifact add ./extras.txt /opt/multi/extras.txt
run_case_expect_ok "artifact_merged" artifact add ./merged.txt /opt/multi/merged.txt

cat >>"${MANIFEST}" <<'EOF'

[spec.tools]
include = ["tar"]
stage = ["./tools.txt"]
build-script = """
mkdir -p /opt/multi
printf '%s\n' "tools" >> /opt/multi/script-order.txt
"""

[spec.tools.build-env]
TOOLS = "yes"

[spec.extras]
include = ["rsync"]
stage = ["./extras.txt"]
build-script = """
mkdir -p /opt/multi
printf '%s\n' "extras" >> /opt/multi/script-order.txt
"""

[spec.extras.build-env]
EXTRAS = "yes"

[spec.merged]
extends = ["tools", "extras"]
stage = ["./merged.txt"]
build-script = """
mkdir -p /opt/multi
printf '%s\n' "$TOOLS"  > /opt/multi/tools-env.txt
printf '%s\n' "$EXTRAS" > /opt/multi/extras-env.txt
printf '%s\n' "merged" >> /opt/multi/script-order.txt
"""
EOF

run_case_expect_ok "update_multi_parent" update
run_case_rdb build -s merged --path "${TREE_DIR}"
assert_file_exists "${TREE_DIR}"

# Both parents' packages must be present in the merged tree.
assert_runtime_packages "${TREE_DIR}" tar rsync

# All three artifacts (one per spec) made it into the tree.
assert_runtime_file_content "${TREE_DIR}" /opt/multi/tools.txt "tools artifact"
assert_runtime_file_content "${TREE_DIR}" /opt/multi/extras.txt "extras artifact"
assert_runtime_file_content "${TREE_DIR}" /opt/multi/merged.txt "merged artifact"

# Build-env entries from both parents are visible to the child script.
assert_runtime_file_content "${TREE_DIR}" /opt/multi/tools-env.txt "yes"
assert_runtime_file_content "${TREE_DIR}" /opt/multi/extras-env.txt "yes"

# Each spec's script ran exactly once and parent scripts ran before
# the child's, with declaration order in `extends` preserved.
assert_runtime_file_content "${TREE_DIR}" /opt/multi/script-order.txt $'tools\nextras\nmerged'

cleanup_tree "${TREE_DIR}"
trap - EXIT
