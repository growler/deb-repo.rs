#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "152_manifest_import_archives_only"
require_rootless_podman

SYSTEM_DIR="${CASE_DIR}/system"
SYSTEM_MANIFEST="${SYSTEM_DIR}/Manifest.toml"
SYSTEM_LOCK="${SYSTEM_DIR}/Manifest.amd64.lock"
IMPORTED_TREE="${CASE_DIR}/tree-import-archives-only"
IMPORT_COMMAND_DIR="${CASE_DIR}/import-command/work"
INIT_IMPORT_DIR="${CASE_DIR}/init-import"
INIT_IMPORT_MANIFEST="${INIT_IMPORT_DIR}/Manifest.toml"
INIT_IMPORT_LOCK="${INIT_IMPORT_DIR}/Manifest.amd64.lock"
INIT_IMPORT_COMMAND_DIR="${CASE_DIR}/init-import-command/work"
INIT_IMPORTED_TREE="${CASE_DIR}/tree-init-import-archives-only"
trap 'cleanup_tree "${IMPORTED_TREE}"; cleanup_tree "${INIT_IMPORTED_TREE}"' EXIT

mkdir -p "${SYSTEM_DIR}"
cp -- "${MANIFEST}" "${SYSTEM_MANIFEST}"
cp -- "${LOCK}" "${SYSTEM_LOCK}"
mkdir -p "${IMPORT_COMMAND_DIR}" "${INIT_IMPORT_DIR}" "${INIT_IMPORT_COMMAND_DIR}"

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

run_import_capture() {
    local label="$1"
    shift
    capture_rdebootstrap_manifest "${label}" "${IMPORT_COMMAND_DIR}" "${MANIFEST}" "${CASE_DIR}" "$@"
}

run_import_expect_ok() {
    local label="$1"
    shift
    if ! run_import_capture "${label}" "$@"; then
        if ! rdebootstrap_debug_enabled; then
            tail -n 40 "${LAST_STDERR}" >&2 || true
        fi
        die "import command failed (${label}): $(format_rdebootstrap_command "${MANIFEST}" "$@")"
    fi
}

run_init_import_capture() {
    local label="$1"
    shift
    capture_rdebootstrap_manifest "${label}" "${INIT_IMPORT_COMMAND_DIR}" "${INIT_IMPORT_MANIFEST}" "${CASE_DIR}" "$@"
}

run_init_import_expect_ok() {
    local label="$1"
    shift
    if ! run_init_import_capture "${label}" "$@"; then
        if ! rdebootstrap_debug_enabled; then
            tail -n 40 "${LAST_STDERR}" >&2 || true
        fi
        die "init-import command failed (${label}): $(format_rdebootstrap_command "${INIT_IMPORT_MANIFEST}" "$@")"
    fi
}

PKG_NAME="archives-only-import_0.0.1_amd64.deb"
create_local_deb "${SYSTEM_DIR}/${PKG_NAME}" archives-only-import 0.0.1 "archives-only-import-ok"
run_system_expect_ok "system_deb_add" deb add "./${PKG_NAME}"

cat >>"${SYSTEM_MANIFEST}" <<'EOF'

[spec.base]
include = ["archives-only-import"]
EOF

run_system_expect_ok "system_update" update

IMPORTED_MANIFEST_INPUT="../../system/Manifest.toml"
IMPORTED_MANIFEST_PATH="$(manifest_rebased_path "${IMPORTED_MANIFEST_INPUT}" "${MANIFEST}" "${IMPORT_COMMAND_DIR}")"
run_import_expect_ok "import_add" import "${IMPORTED_MANIFEST_INPUT}"
assert_manifest_contains "[import]"
assert_manifest_contains "path = \"${IMPORTED_MANIFEST_PATH}\""
assert_manifest_contains "hash = "
assert_manifest_lacks "specs = "

cat >>"${MANIFEST}" <<'EOF'

[spec.frontend]
include = ["archives-only-import"]
EOF

run_case_expect_ok "downstream_update" update
run_case_rdb build -s frontend --path "${IMPORTED_TREE}"

assert_runtime_packages "${IMPORTED_TREE}" archives-only-import
assert_equals \
    "archives-only-import-ok" \
    "$(run_podman_rootfs "${IMPORTED_TREE}" /usr/local/bin/archives-only-import)" \
    "archives-only import output"

INIT_IMPORT_INPUT="../../system/Manifest.toml"
INIT_IMPORTED_MANIFEST_PATH="$(manifest_rebased_path "${INIT_IMPORT_INPUT}" "${INIT_IMPORT_MANIFEST}" "${INIT_IMPORT_COMMAND_DIR}")"
run_init_import_expect_ok "init_import_create" init --import "${INIT_IMPORT_INPUT}" --package archives-only-import
assert_file_exists "${INIT_IMPORT_MANIFEST}"
assert_file_exists "${INIT_IMPORT_LOCK}"
assert_file_contains "${INIT_IMPORT_MANIFEST}" "[import]"
assert_file_contains "${INIT_IMPORT_MANIFEST}" "path = \"${INIT_IMPORTED_MANIFEST_PATH}\""
assert_file_contains "${INIT_IMPORT_MANIFEST}" "hash = "
assert_file_lacks "${INIT_IMPORT_MANIFEST}" "specs = "
assert_file_contains "${INIT_IMPORT_LOCK}" "imported-universe = "

run_rdebootstrap_manifest "${INIT_IMPORT_DIR}" "${INIT_IMPORT_MANIFEST}" build --path "${INIT_IMPORTED_TREE}"

assert_runtime_packages "${INIT_IMPORTED_TREE}" archives-only-import
assert_equals \
    "archives-only-import-ok" \
    "$(run_podman_rootfs "${INIT_IMPORTED_TREE}" /usr/local/bin/archives-only-import)" \
    "init import output"

cat >>"${MANIFEST}" <<'EOF'

[spec.bad]
extends = "base"
include = ["rsync"]
EOF

run_case_expect_fail "extends_unexported_imported_spec" update
assert_file_contains "${LAST_STDERR}" "spec bad extends missing (base)"

cleanup_tree "${IMPORTED_TREE}"
cleanup_tree "${INIT_IMPORTED_TREE}"
trap - EXIT
