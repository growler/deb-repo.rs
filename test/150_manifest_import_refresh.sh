#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "150_manifest_import_refresh"
require_rootless_podman

SYSTEM_DIR="${CASE_DIR}/system"
SYSTEM_MANIFEST="${SYSTEM_DIR}/Manifest.toml"
SYSTEM_LOCK="${SYSTEM_DIR}/Manifest.amd64.lock"
REFRESH_TREE_V1="${CASE_DIR}/tree-refresh-v1"
REFRESH_TREE_V2="${CASE_DIR}/tree-refresh-v2"
trap 'cleanup_tree "${REFRESH_TREE_V1}"; cleanup_tree "${REFRESH_TREE_V2}"' EXIT

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

printf 'imported artifact v1\n' >"${SYSTEM_DIR}/base.txt"
PKG_NAME="shared-import_0.0.1_amd64.deb"
create_local_deb "${SYSTEM_DIR}/${PKG_NAME}" shared-import 0.0.1 "shared-import-v1"

run_system_expect_ok "system_artifact_add" artifact add ./base.txt /opt/import/base.txt
run_system_expect_ok "system_deb_add" deb add "./${PKG_NAME}"

cat >>"${SYSTEM_MANIFEST}" <<'EOF'

[spec.base]
include = ["tar", "shared-import"]
stage = ["./base.txt"]
EOF

run_system_expect_ok "system_update_base" update
run_case_expect_ok "import_add" import ./system/Manifest.toml --spec base

cat >>"${MANIFEST}" <<'EOF'

[spec.frontend]
extends = "base"
include = ["rsync"]
EOF

run_case_expect_ok "downstream_update" update
run_case_rdb build -s frontend --path "${REFRESH_TREE_V1}"

hash_before="$(grep '^hash = ' "${MANIFEST}" | head -n 1)"
imported_universe_before="$(grep '^imported-universe = ' "${LOCK}" | head -n 1)"
assert_runtime_packages "${REFRESH_TREE_V1}" tar rsync shared-import
assert_runtime_file_content "${REFRESH_TREE_V1}" /opt/import/base.txt "imported artifact v1"
assert_equals \
    "shared-import-v1" \
    "$(run_podman_rootfs "${REFRESH_TREE_V1}" /usr/local/bin/shared-import)" \
    "shared-import v1 output"

printf 'imported artifact v2\n' >"${SYSTEM_DIR}/base.txt"
create_local_deb "${SYSTEM_DIR}/${PKG_NAME}" shared-import 0.0.1 "shared-import-v2"
run_system_expect_ok "system_update_locals" update --locals
printf '\n# import refresh\n' >>"${SYSTEM_MANIFEST}"
run_system_expect_ok "system_update_drift" update
run_case_expect_ok "refresh_import" update
run_case_rdb build -s frontend --path "${REFRESH_TREE_V2}"

hash_after="$(grep '^hash = ' "${MANIFEST}" | head -n 1)"
imported_universe_after="$(grep '^imported-universe = ' "${LOCK}" | head -n 1)"
assert_not_equals "${hash_before}" "${hash_after}" "import hash refresh"
assert_not_equals "${imported_universe_before}" "${imported_universe_after}" "imported universe refresh"
assert_file_contains "${LOCK}" "imported-universe = "
assert_runtime_packages "${REFRESH_TREE_V2}" tar rsync shared-import
assert_runtime_file_content "${REFRESH_TREE_V2}" /opt/import/base.txt "imported artifact v2"
assert_equals \
    "shared-import-v2" \
    "$(run_podman_rootfs "${REFRESH_TREE_V2}" /usr/local/bin/shared-import)" \
    "shared-import v2 output"

cleanup_tree "${REFRESH_TREE_V1}"
cleanup_tree "${REFRESH_TREE_V2}"
trap - EXIT
