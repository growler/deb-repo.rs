#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "55_local_path_resolution"
require_rootless_podman

COMMAND_DIR="${CASE_DIR}/command-dir"
RELATIVE_DIR="${CASE_DIR}/relative-src"
ABSOLUTE_DIR="${CASE_DIR}/absolute-src"
TREE_V1="${CASE_DIR}/tree-v1"
TREE_V2="${CASE_DIR}/tree-v2"
trap 'cleanup_tree "${TREE_V1}"; cleanup_tree "${TREE_V2}"' EXIT

RELATIVE_PACKAGE_NAME="path-relative-local"
RELATIVE_DEB_NAME="${RELATIVE_PACKAGE_NAME}_0.0.1_amd64.deb"
RELATIVE_DEB_PATH="./relative-src/${RELATIVE_DEB_NAME}"
RELATIVE_ARTIFACT_PATH="./relative-src/relative-note.txt"
RELATIVE_STORED_DEB_PATH="$(manifest_rebased_path "${RELATIVE_DEB_PATH}" "${MANIFEST}" "${COMMAND_DIR}")"
RELATIVE_STORED_ARTIFACT_PATH="$(manifest_rebased_path "${RELATIVE_ARTIFACT_PATH}" "${MANIFEST}" "${COMMAND_DIR}")"

ABSOLUTE_PACKAGE_NAME="path-absolute-local"
ABSOLUTE_DEB_NAME="${ABSOLUTE_PACKAGE_NAME}_0.0.1_amd64.deb"
ABSOLUTE_DEB_PATH="${ABSOLUTE_DIR}/${ABSOLUTE_DEB_NAME}"
ABSOLUTE_ARTIFACT_PATH="${ABSOLUTE_DIR}/absolute-note.txt"

mkdir -p "${COMMAND_DIR}/relative-src" "${RELATIVE_DIR}" "${ABSOLUTE_DIR}"

run_external_capture() {
    local label="$1"
    shift
    capture_rdebootstrap_manifest "${label}" "${COMMAND_DIR}" "${MANIFEST}" "${CASE_DIR}" "$@"
}

run_external_expect_ok() {
    local label="$1"
    shift
    if ! run_external_capture "${label}" "$@"; then
        if ! rdebootstrap_debug_enabled; then
            tail -n 40 "${LAST_STDERR}" >&2 || true
        fi
        die "external command failed (${label}): $(format_rdebootstrap_command "${MANIFEST}" "$@")"
    fi
}

printf 'manifest dir relative artifact v1\n' >"${RELATIVE_DIR}/relative-note.txt"
printf 'cwd relative artifact v1\n' >"${COMMAND_DIR}/relative-src/relative-note.txt"
printf 'absolute artifact v1\n' >"${ABSOLUTE_ARTIFACT_PATH}"

create_local_deb \
    "${RELATIVE_DIR}/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "manifest-relative-package-v1"
create_local_deb \
    "${COMMAND_DIR}/relative-src/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "cwd-relative-package-v1"
create_local_deb \
    "${ABSOLUTE_DEB_PATH}" \
    "${ABSOLUTE_PACKAGE_NAME}" \
    0.0.1 \
    "absolute-package-v1"

run_external_expect_ok \
    "artifact_relative" \
    artifact add --stage "${RELATIVE_ARTIFACT_PATH}" /opt/path-resolution/relative-note.txt
run_external_expect_ok \
    "artifact_absolute" \
    artifact add --stage "$(abs_path "${ABSOLUTE_ARTIFACT_PATH}")" /opt/path-resolution/absolute-note.txt
run_external_expect_ok "deb_relative" deb add "${RELATIVE_DEB_PATH}"
run_external_expect_ok "deb_absolute" deb add "$(abs_path "${ABSOLUTE_DEB_PATH}")"
run_external_expect_ok \
    "require_locals" \
    require "${BASE_PACKAGES[@]}" "${RELATIVE_PACKAGE_NAME}" "${ABSOLUTE_PACKAGE_NAME}"
run_external_expect_ok "update_initial" update --archives --locals

assert_manifest_contains "[artifact.\"${RELATIVE_STORED_ARTIFACT_PATH}\"]"
assert_manifest_contains "[artifact.\"$(abs_path "${ABSOLUTE_ARTIFACT_PATH}")\"]"
assert_manifest_contains "path = \"${RELATIVE_STORED_DEB_PATH}\""
assert_manifest_contains "path = \"$(abs_path "${ABSOLUTE_DEB_PATH}")\""

run_external_expect_ok "build_v1" build --path "${TREE_V1}"
assert_file_exists "${TREE_V1}"

assert_runtime_file_content "${TREE_V1}" /opt/path-resolution/relative-note.txt "cwd relative artifact v1"
assert_runtime_file_content "${TREE_V1}" /opt/path-resolution/absolute-note.txt "absolute artifact v1"
assert_equals \
    "cwd-relative-package-v1" \
    "$(run_podman_rootfs "${TREE_V1}" /usr/local/bin/${RELATIVE_PACKAGE_NAME})" \
    "relative local package output v1"
assert_equals \
    "absolute-package-v1" \
    "$(run_podman_rootfs "${TREE_V1}" /usr/local/bin/${ABSOLUTE_PACKAGE_NAME})" \
    "absolute local package output v1"

printf 'manifest dir relative artifact v2\n' >"${RELATIVE_DIR}/relative-note.txt"
printf 'cwd relative artifact v2\n' >"${COMMAND_DIR}/relative-src/relative-note.txt"
printf 'absolute artifact v2\n' >"${ABSOLUTE_ARTIFACT_PATH}"
create_local_deb \
    "${RELATIVE_DIR}/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "manifest-relative-package-v2"
create_local_deb \
    "${COMMAND_DIR}/relative-src/${RELATIVE_DEB_NAME}" \
    "${RELATIVE_PACKAGE_NAME}" \
    0.0.1 \
    "cwd-relative-package-v2"
create_local_deb \
    "${ABSOLUTE_DEB_PATH}" \
    "${ABSOLUTE_PACKAGE_NAME}" \
    0.0.1 \
    "absolute-package-v2"

run_external_expect_ok "update_locals" update --locals
run_external_expect_ok "build_v2" build --path "${TREE_V2}"
assert_file_exists "${TREE_V2}"

assert_runtime_file_content "${TREE_V2}" /opt/path-resolution/relative-note.txt "cwd relative artifact v2"
assert_runtime_file_content "${TREE_V2}" /opt/path-resolution/absolute-note.txt "absolute artifact v2"
assert_equals \
    "cwd-relative-package-v2" \
    "$(run_podman_rootfs "${TREE_V2}" /usr/local/bin/${RELATIVE_PACKAGE_NAME})" \
    "relative local package output v2"
assert_equals \
    "absolute-package-v2" \
    "$(run_podman_rootfs "${TREE_V2}" /usr/local/bin/${ABSOLUTE_PACKAGE_NAME})" \
    "absolute local package output v2"

cleanup_tree "${TREE_V1}"
cleanup_tree "${TREE_V2}"
trap - EXIT
