#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "40_text_artifact_and_build_script"
trap 'cleanup_tree "${TREE_DIR}"' EXIT

printf 'integration notice\n' >"${CASE_DIR}/notice.txt"
run_case_rdb artifact add --stage @./notice.txt /etc/integration/notice.txt

cat >>"${MANIFEST}" <<'EOF'
build-script = """
mkdir -p /opt/integration
printf '%s\n' "$INTEGRATION_VALUE" > /opt/integration/build-script.txt
"""

[spec.build-env]
INTEGRATION_VALUE = "from-build-env"
EOF

run_case_rdb update
build_tree "sandbox" "${TREE_DIR}"
assert_runtime_file_content "${TREE_DIR}" /etc/integration/notice.txt "integration notice"
assert_runtime_file_content "${TREE_DIR}" /opt/integration/build-script.txt "from-build-env"

cleanup_tree "${TREE_DIR}"
trap - EXIT
