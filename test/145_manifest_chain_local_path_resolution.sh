#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "145_manifest_chain_local_path_resolution"
require_rootless_podman

SYSTEM_DIR="${CASE_DIR}/system-manifest"
SYSTEM_MANIFEST="${SYSTEM_DIR}/Manifest.toml"
SYSTEM_LOCK="${SYSTEM_DIR}/Manifest.amd64.lock"
SYSTEM_COMMAND_DIR="${CASE_DIR}/system-command/work"
OWNED_DIR="${CASE_DIR}/145-chain-owned"
COMMAND_DECOY_DIR="${CASE_DIR}/system-command/145-chain-owned"
DOWNSTREAM_DECOY_DIR="${TEST_ROOT}/145-chain-owned"
ABSOLUTE_DIR="${CASE_DIR}/145-chain-absolute"
TREE_V1="${CASE_DIR}/tree-v1"
TREE_V2="${CASE_DIR}/tree-v2"
trap 'cleanup_tree "${TREE_V1}"; cleanup_tree "${TREE_V2}"' EXIT

RELATIVE_PACKAGE_NAME="imported-chain-relative"
RELATIVE_DEB_NAME="${RELATIVE_PACKAGE_NAME}_0.0.1_amd64.deb"
RELATIVE_DEB_PATH="../145-chain-owned/${RELATIVE_DEB_NAME}"
RELATIVE_ARTIFACT_PATH="../145-chain-owned/relative-note.txt"
RELATIVE_STORED_DEB_PATH="$(manifest_rebased_path "${RELATIVE_DEB_PATH}" "${SYSTEM_MANIFEST}" "${SYSTEM_COMMAND_DIR}")"
RELATIVE_STORED_ARTIFACT_PATH="$(manifest_rebased_path "${RELATIVE_ARTIFACT_PATH}" "${SYSTEM_MANIFEST}" "${SYSTEM_COMMAND_DIR}")"

ABSOLUTE_PACKAGE_NAME="imported-chain-absolute"
ABSOLUTE_DEB_NAME="${ABSOLUTE_PACKAGE_NAME}_0.0.1_amd64.deb"
ABSOLUTE_DEB_PATH="${ABSOLUTE_DIR}/${ABSOLUTE_DEB_NAME}"
ABSOLUTE_ARTIFACT_PATH="${ABSOLUTE_DIR}/absolute-note.txt"

mkdir -p \
    "${SYSTEM_DIR}" \
    "${SYSTEM_COMMAND_DIR}" \
    "${OWNED_DIR}" \
    "${COMMAND_DECOY_DIR}" \
    "${DOWNSTREAM_DECOY_DIR}" \
    "${ABSOLUTE_DIR}"
cp -- "${MANIFEST}" "${SYSTEM_MANIFEST}"
cp -- "${LOCK}" "${SYSTEM_LOCK}"

run_system_capture() {
    local label="$1"
    shift
    capture_rdebootstrap_manifest "${label}" "${SYSTEM_COMMAND_DIR}" "${SYSTEM_MANIFEST}" "${CASE_DIR}" "$@"
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

printf 'manifest relative imported artifact v1\n' >"${OWNED_DIR}/relative-note.txt"
printf 'imported relative artifact v1\n' >"${COMMAND_DECOY_DIR}/relative-note.txt"
printf 'wrong downstream imported relative artifact\n' >"${DOWNSTREAM_DECOY_DIR}/relative-note.txt"
printf 'imported absolute artifact v1\n' >"${ABSOLUTE_ARTIFACT_PATH}"

create_local_deb \
    "${OWNED_DIR}/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "manifest-relative-imported-package-v1"
create_local_deb \
    "${COMMAND_DECOY_DIR}/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "imported-relative-package-v1"
create_local_deb \
    "${DOWNSTREAM_DECOY_DIR}/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "wrong-downstream-imported-relative-package"
create_local_deb \
    "${ABSOLUTE_DEB_PATH}" \
    "${ABSOLUTE_PACKAGE_NAME}" \
    0.0.1 \
    "imported-absolute-package-v1"

run_system_expect_ok "deb_relative" deb add "${RELATIVE_DEB_PATH}"
run_system_expect_ok "deb_absolute" deb add "$(abs_path "${ABSOLUTE_DEB_PATH}")"
run_system_expect_ok \
    "require_base" \
    require -s base "${BASE_PACKAGES[@]}" "${RELATIVE_PACKAGE_NAME}" "${ABSOLUTE_PACKAGE_NAME}"
run_system_expect_ok \
    "artifact_relative" \
    artifact add --stage -s base "${RELATIVE_ARTIFACT_PATH}" /opt/import-paths/relative-note.txt
run_system_expect_ok \
    "artifact_absolute" \
    artifact add --stage -s base "$(abs_path "${ABSOLUTE_ARTIFACT_PATH}")" /opt/import-paths/absolute-note.txt
run_system_expect_ok "system_update" update --archives --locals

assert_file_contains "${SYSTEM_MANIFEST}" "[artifact.\"${RELATIVE_STORED_ARTIFACT_PATH}\"]"
assert_file_contains "${SYSTEM_MANIFEST}" "[artifact.\"$(abs_path "${ABSOLUTE_ARTIFACT_PATH}")\"]"
assert_file_contains "${SYSTEM_MANIFEST}" "path = \"${RELATIVE_STORED_DEB_PATH}\""
assert_file_contains "${SYSTEM_MANIFEST}" "path = \"$(abs_path "${ABSOLUTE_DEB_PATH}")\""

run_case_expect_ok "import_add" import ./system-manifest/Manifest.toml --spec base
cat >>"${MANIFEST}" <<'EOF'

[spec.frontend]
extends = "base"
EOF
run_case_expect_ok "downstream_update" update
run_case_expect_ok "build_v1" build -s frontend --path "${TREE_V1}"
assert_file_exists "${TREE_V1}"

assert_runtime_file_content "${TREE_V1}" /opt/import-paths/relative-note.txt "imported relative artifact v1"
assert_runtime_file_content "${TREE_V1}" /opt/import-paths/absolute-note.txt "imported absolute artifact v1"
assert_equals \
    "imported-relative-package-v1" \
    "$(run_podman_rootfs "${TREE_V1}" /usr/local/bin/${RELATIVE_PACKAGE_NAME})" \
    "imported relative local package output v1"
assert_equals \
    "imported-absolute-package-v1" \
    "$(run_podman_rootfs "${TREE_V1}" /usr/local/bin/${ABSOLUTE_PACKAGE_NAME})" \
    "imported absolute local package output v1"

printf 'manifest relative imported artifact v2\n' >"${OWNED_DIR}/relative-note.txt"
printf 'imported relative artifact v2\n' >"${COMMAND_DECOY_DIR}/relative-note.txt"
printf 'imported absolute artifact v2\n' >"${ABSOLUTE_ARTIFACT_PATH}"
create_local_deb \
    "${OWNED_DIR}/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "manifest-relative-imported-package-v2"
create_local_deb \
    "${COMMAND_DECOY_DIR}/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "imported-relative-package-v2"
create_local_deb \
    "${ABSOLUTE_DEB_PATH}" \
    "${ABSOLUTE_PACKAGE_NAME}" \
    0.0.1 \
    "imported-absolute-package-v2"

run_system_expect_ok "system_update_locals" update --locals
run_case_expect_ok "refresh_import" update
run_case_expect_ok "build_v2" build -s frontend --path "${TREE_V2}"
assert_file_exists "${TREE_V2}"

assert_runtime_file_content "${TREE_V2}" /opt/import-paths/relative-note.txt "imported relative artifact v2"
assert_runtime_file_content "${TREE_V2}" /opt/import-paths/absolute-note.txt "imported absolute artifact v2"
assert_equals \
    "imported-relative-package-v2" \
    "$(run_podman_rootfs "${TREE_V2}" /usr/local/bin/${RELATIVE_PACKAGE_NAME})" \
    "imported relative local package output v2"
assert_equals \
    "imported-absolute-package-v2" \
    "$(run_podman_rootfs "${TREE_V2}" /usr/local/bin/${ABSOLUTE_PACKAGE_NAME})" \
    "imported absolute local package output v2"

cleanup_tree "${TREE_V1}"
cleanup_tree "${TREE_V2}"
trap - EXIT
