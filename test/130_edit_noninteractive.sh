#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "130_edit_noninteractive"
require_rootless_podman
trap 'cleanup_tree "${TREE_DIR}"' EXIT

cat >"${CASE_DIR}/write-env.sh" <<'EOF'
#!/usr/bin/env bash
cat >"$1" <<'EOENV'
# editor managed env
EDITOR_VALUE=from-editor
EOENV
EOF
chmod 0755 "${CASE_DIR}/write-env.sh"

cat >"${CASE_DIR}/write-script.sh" <<'EOF'
#!/usr/bin/env bash
cat >"$1" <<'EOSCRIPT'
mkdir -p /opt/edit
printf '%s\n' "$EDITOR_VALUE" > /opt/edit/script.txt
EOSCRIPT
EOF
chmod 0755 "${CASE_DIR}/write-script.sh"

cat >"${CASE_DIR}/write-artifact.sh" <<'EOF'
#!/usr/bin/env bash
cat >"$1" <<'EOARTIFACT'
edited notice
EOARTIFACT
EOF
chmod 0755 "${CASE_DIR}/write-artifact.sh"

cat >"${CASE_DIR}/write-invalid-env.sh" <<'EOF'
#!/usr/bin/env bash
cat >"$1" <<'EOINVALID'
not valid
EOINVALID
EOF
chmod 0755 "${CASE_DIR}/write-invalid-env.sh"

run_case_expect_ok "edit_env" edit --edit ./write-env.sh env
assert_manifest_contains "EDITOR_VALUE = \"from-editor\""

run_case_expect_ok "edit_script" edit --edit ./write-script.sh script
assert_manifest_contains "/opt/edit/script.txt"

run_case_expect_ok \
    "edit_artifact" \
    edit --edit ./write-artifact.sh artifact notice.txt --target /etc/edit/notice.txt --stage
assert_manifest_contains "[artifact.\"notice.txt\"]"
assert_manifest_contains "/etc/edit/notice.txt"

build_tree "sandbox" "${TREE_DIR}"
assert_runtime_file_content "${TREE_DIR}" /opt/edit/script.txt "from-editor"
assert_runtime_file_content "${TREE_DIR}" /etc/edit/notice.txt "edited notice"

cp -- "${MANIFEST}" "${CASE_DIR}/Manifest.before-invalid.toml"
cp -- "${LOCK}" "${CASE_DIR}/Manifest.before-invalid.lock"
run_case_expect_fail "edit_env_invalid" edit --edit ./write-invalid-env.sh env
assert_stderr_contains "invalid env line"
cmp -s "${MANIFEST}" "${CASE_DIR}/Manifest.before-invalid.toml" || die "manifest rollback failed"
cmp -s "${LOCK}" "${CASE_DIR}/Manifest.before-invalid.lock" || die "lock rollback failed"

cleanup_tree "${TREE_DIR}"
trap - EXIT
