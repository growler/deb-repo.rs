#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "140_manifest_import_build"
require_rootless_podman

SYSTEM_DIR="${CASE_DIR}/system"
SYSTEM_MANIFEST="${SYSTEM_DIR}/Manifest.toml"
SYSTEM_LOCK="${SYSTEM_DIR}/Manifest.amd64.lock"
IMPORTED_TREE="${CASE_DIR}/tree-import"
trap 'cleanup_tree "${IMPORTED_TREE}"' EXIT

mkdir -p "${SYSTEM_DIR}"
cp -- "${MANIFEST}" "${SYSTEM_MANIFEST}"
cp -- "${LOCK}" "${SYSTEM_LOCK}"

run_system_capture() {
    local label="$1"
    shift
    capture_rdebootstrap_manifest "${label}" "${SYSTEM_DIR}" "${SYSTEM_MANIFEST}" "${CASE_DIR}" "$@"
}

run_system_expect_ok() {
    local label="$1"
    shift
    if ! run_system_capture "${label}" "$@"; then
        if ! rdebootstrap_debug_enabled; then
            tail -n 40 "${LAST_STDERR}" >&2 || true
        fi
        die "system command failed (${label}): $(format_rdebootstrap_command "${SYSTEM_MANIFEST}" "$@")"
    fi
}

printf 'imported artifact\n' >"${SYSTEM_DIR}/base.txt"
printf 'extra imported artifact\n' >"${SYSTEM_DIR}/extra.txt"
printf 'downstream artifact\n' >"${CASE_DIR}/base.txt"
PKG_NAME="shared-import_0.0.1_amd64.deb"
create_local_deb "${SYSTEM_DIR}/${PKG_NAME}" shared-import 0.0.1 "shared-import-ok"

run_system_expect_ok "system_artifact_add" artifact add ./base.txt /opt/import/base.txt
run_system_expect_ok "system_artifact_add_extra" artifact add ./extra.txt /opt/import/extra.txt
run_system_expect_ok "system_deb_add" deb add "./${PKG_NAME}"

cat >>"${SYSTEM_MANIFEST}" <<'EOF'

[spec.base]
include = ["tar", "shared-import"]
stage = ["./base.txt"]
build-script = """
mkdir -p /opt/import
printf '%s\n' "$BASE_ONLY" > /opt/import/base-env.txt
printf '%s\n' "base" > /opt/import/script-order.txt
"""
meta = ["origin:system", "role:base"]

[spec.base.build-env]
BASE_ONLY = "from-base"
COMMON = "base"

[spec.bootable-base]
extends = "base"
include = ["gzip"]
build-script = """
printf '%s\n' "$MIDDLE_ONLY" > /opt/import/middle-env.txt
printf '%s\n' "bootable" >> /opt/import/script-order.txt
"""
meta = ["layer:bootable", "role:bootable"]

[spec.bootable-base.build-env]
MIDDLE_ONLY = "from-bootable"
COMMON = "bootable"
EOF

run_system_expect_ok "system_update" update

run_case_expect_ok "import_add" import ./system/Manifest.toml --spec bootable-base
assert_manifest_contains "[import]"
assert_manifest_contains "path = \"./system/Manifest.toml\""
assert_manifest_contains "\"bootable-base\""

cat >>"${MANIFEST}" <<'EOF'

[spec.frontend]
extends = "bootable-base"
include = ["rsync"]
stage = ["./extra.txt"]
build-script = """
printf '%s\n' "$CHILD_ONLY" > /opt/import/child-env.txt
printf '%s\n' "$COMMON" > /opt/import/common-env.txt
printf '%s\n' "derived" >> /opt/import/script-order.txt
"""
meta = ["role:frontend", "tier:web"]

[spec.frontend.build-env]
COMMON = "frontend"
CHILD_ONLY = "from-frontend"
EOF

run_case_expect_ok "downstream_update" update
run_case_expect_ok "frontend_meta_origin" spec meta get -s frontend origin
assert_equals "system" "$(tr -d '\n' <"${LAST_STDOUT}")" "frontend meta origin"
run_case_expect_ok "frontend_meta_layer" spec meta get -s frontend layer
assert_equals "bootable" "$(tr -d '\n' <"${LAST_STDOUT}")" "frontend meta layer"
run_case_expect_ok "frontend_meta_role" spec meta get -s frontend role
assert_equals "frontend" "$(tr -d '\n' <"${LAST_STDOUT}")" "frontend meta role"
run_case_expect_ok "frontend_meta_tier" spec meta get -s frontend tier
assert_equals "web" "$(tr -d '\n' <"${LAST_STDOUT}")" "frontend meta tier"
run_case_rdb build -s frontend --path "${IMPORTED_TREE}"

assert_runtime_packages "${IMPORTED_TREE}" tar gzip rsync shared-import
assert_runtime_file_content "${IMPORTED_TREE}" /opt/import/base.txt "imported artifact"
assert_runtime_file_content "${IMPORTED_TREE}" /opt/import/extra.txt "extra imported artifact"
assert_runtime_file_content "${IMPORTED_TREE}" /opt/import/base-env.txt "from-base"
assert_runtime_file_content "${IMPORTED_TREE}" /opt/import/middle-env.txt "from-bootable"
assert_runtime_file_content "${IMPORTED_TREE}" /opt/import/child-env.txt "from-frontend"
assert_runtime_file_content "${IMPORTED_TREE}" /opt/import/common-env.txt "frontend"
assert_runtime_file_content "${IMPORTED_TREE}" /opt/import/script-order.txt $'base\nbootable\nderived'
assert_equals \
    "shared-import-ok" \
    "$(run_podman_rootfs "${IMPORTED_TREE}" /usr/local/bin/shared-import)" \
    "shared-import output"

cleanup_tree "${IMPORTED_TREE}"
trap - EXIT
