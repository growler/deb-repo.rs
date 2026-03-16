#!/usr/bin/env bash
set -euo pipefail

BASE_PACKAGES=(
    bash
    coreutils
    grep
    sed
    ca-certificates
)

BASELINE_CASE_NAME="00_baseline"
BASELINE_CASE_DIR="${TEST_ROOT}/${BASELINE_CASE_NAME}"
BASELINE_MANIFEST="${BASELINE_CASE_DIR}/Manifest.toml"
BASELINE_LOCK="${BASELINE_CASE_DIR}/Manifest.amd64.lock"

LAST_STDOUT=""
LAST_STDERR=""
LAST_STATUS=0

note() {
    printf '==> %s\n' "$*" >&2
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

abs_path() {
    readlink -f -- "$1"
}

assert_inside_test_root() {
    local path
    path="$(abs_path "$1")"
    case "${path}" in
        "${TEST_ROOT}"|"${TEST_ROOT}"/*) ;;
        *)
            die "refusing to use path outside ${TEST_ROOT}: ${path}"
            ;;
    esac
}

reset_dir() {
    assert_inside_test_root "$1"
    rm -rf -- "$1"
    mkdir -p -- "$1"
}

set_case_paths() {
    CASE_NAME="$1"
    CASE_DIR="${TEST_ROOT}/${CASE_NAME}"
    MANIFEST="${CASE_DIR}/Manifest.toml"
    LOCK="${CASE_DIR}/Manifest.amd64.lock"
    TREE_DIR="${CASE_DIR}/tree"
}

prepare_case() {
    set_case_paths "$1"
    reset_dir "${CASE_DIR}"
}

run_case_rdb() {
    (
        cd "${CASE_DIR}"
        "${RDEBOOTSTRAP}" -m "${MANIFEST}" "$@"
    )
}

capture_case_command() {
    local label="$1"
    shift
    LAST_STDOUT="${CASE_DIR}/${label}.stdout"
    LAST_STDERR="${CASE_DIR}/${label}.stderr"
    if (
        cd "${CASE_DIR}"
        "$@"
    ) >"${LAST_STDOUT}" 2>"${LAST_STDERR}"; then
        LAST_STATUS=0
        return 0
    else
        LAST_STATUS=$?
        return "${LAST_STATUS}"
    fi
}

run_case_capture() {
    local label="$1"
    shift
    capture_case_command "${label}" "${RDEBOOTSTRAP}" -m "${MANIFEST}" "$@"
}

run_case_expect_ok() {
    local label="$1"
    shift
    if ! run_case_capture "${label}" "$@"; then
        tail -n 40 "${LAST_STDERR}" >&2 || true
        die "command failed (${label}): rdebootstrap -m ${MANIFEST} $*"
    fi
}

run_case_expect_ok_raw() {
    local label="$1"
    shift
    if ! capture_case_command "${label}" "$@"; then
        tail -n 40 "${LAST_STDERR}" >&2 || true
        die "command failed (${label}): $*"
    fi
}

run_case_expect_fail() {
    local label="$1"
    shift
    if run_case_capture "${label}" "$@"; then
        die "expected command to fail (${label}): rdebootstrap -m ${MANIFEST} $*"
    fi
}

run_case_expect_fail_raw() {
    local label="$1"
    shift
    if capture_case_command "${label}" "$@"; then
        die "expected command to fail (${label}): $*"
    fi
}

bootstrap_baseline_manifest() {
    if [[ -e "${BASELINE_MANIFEST}" && -e "${BASELINE_LOCK}" ]]; then
        return
    fi
    note "Bootstrapping baseline manifest"
    prepare_case "${BASELINE_CASE_NAME}"
    run_case_rdb init debian --suite trixie --components main
    run_case_rdb update --archives
    run_case_rdb require "${BASE_PACKAGES[@]}"
    assert_file_exists "${MANIFEST}"
    assert_file_exists "${LOCK}"
}

prepare_case_from_baseline() {
    bootstrap_baseline_manifest
    prepare_case "$1"
    cp -- "${BASELINE_MANIFEST}" "${MANIFEST}"
    cp -- "${BASELINE_LOCK}" "${LOCK}"
    assert_file_exists "${MANIFEST}"
    assert_file_exists "${LOCK}"
}

bootstrap_manifest() {
    prepare_case_from_baseline "$1"
}

assert_file_exists() {
    [[ -e "$1" ]] || die "expected file to exist: $1"
}

assert_path_missing() {
    [[ ! -e "$1" ]] || die "expected path to be absent: $1"
}

assert_file_contains() {
    local file="$1"
    local needle="$2"
    grep -F -- "${needle}" "${file}" >/dev/null || die "expected ${file} to contain: ${needle}"
}

assert_file_lacks() {
    local file="$1"
    local needle="$2"
    if grep -F -- "${needle}" "${file}" >/dev/null; then
        die "expected ${file} to not contain: ${needle}"
    fi
}

assert_file_matches() {
    local file="$1"
    local regex="$2"
    grep -E -- "${regex}" "${file}" >/dev/null || die "expected ${file} to match regex: ${regex}"
}

assert_equals() {
    local expected="$1"
    local actual="$2"
    local label="$3"
    if [[ "${expected}" != "${actual}" ]]; then
        die "${label}: expected '${expected}', got '${actual}'"
    fi
}

assert_not_equals() {
    local left="$1"
    local right="$2"
    local label="$3"
    if [[ "${left}" == "${right}" ]]; then
        die "${label}: expected distinct values, got '${left}'"
    fi
}

assert_stdout_contains() {
    assert_file_contains "${LAST_STDOUT}" "$1"
}

assert_stdout_lacks() {
    assert_file_lacks "${LAST_STDOUT}" "$1"
}

assert_stdout_matches() {
    assert_file_matches "${LAST_STDOUT}" "$1"
}

assert_stderr_contains() {
    assert_file_contains "${LAST_STDERR}" "$1"
}

assert_manifest_contains() {
    assert_file_contains "${MANIFEST}" "$1"
}

assert_manifest_lacks() {
    assert_file_lacks "${MANIFEST}" "$1"
}

require_rootless_podman() {
    require_cmd podman
    podman unshare true >/dev/null
}

cleanup_tree() {
    local tree
    tree="$(abs_path "$1")"
    assert_inside_test_root "${tree}"
    if [[ -e "${tree}" ]]; then
        require_rootless_podman
        podman unshare rm -rf -- "${tree}"
    fi
    assert_path_missing "${tree}"
}

run_podman_rootfs() {
    local tree
    tree="$(abs_path "$1")"
    shift
    require_rootless_podman
    assert_inside_test_root "${tree}"
    [[ "${tree}" = /* ]] || die "podman rootfs path must be absolute: ${tree}"
    podman run --rm --net none --rootfs "${tree}:O" "$@"
}

assert_runtime_packages() {
    local tree="$1"
    shift
    run_podman_rootfs "${tree}" /bin/bash -lc "test -x /bin/bash && dpkg-query -W $* >/dev/null"
}

assert_runtime_file() {
    local tree="$1"
    local path="$2"
    run_podman_rootfs "${tree}" /bin/bash -lc "test -e '${path}'"
}

assert_runtime_file_missing() {
    local tree="$1"
    local path="$2"
    run_podman_rootfs "${tree}" /bin/bash -lc "! test -e '${path}'"
}

assert_runtime_file_content() {
    local tree="$1"
    local path="$2"
    local expected="$3"
    local output
    output="$(run_podman_rootfs "${tree}" /bin/bash -lc "cat '${path}'")"
    assert_equals "${expected}" "${output}" "content mismatch for ${path}"
}

assert_runtime_mode() {
    local tree="$1"
    local path="$2"
    local expected="$3"
    local output
    output="$(run_podman_rootfs "${tree}" /bin/bash -lc "stat -c '%a' '${path}'")"
    assert_equals "${expected}" "${output}" "mode mismatch for ${path}"
}

build_tree() {
    local executor="$1"
    local tree="$2"
    mkdir -p "$(dirname "${tree}")"
    if [[ "${executor}" == "sandbox" ]]; then
        run_case_rdb build --path "${tree}"
    else
        require_rootless_podman
        run_case_rdb build --executor "${executor}" --path "${tree}"
    fi
    assert_file_exists "${tree}"
}

create_local_deb() {
    local deb_path="$1"
    local package_name="$2"
    local version="$3"
    local message="$4"
    local pkg_root="${CASE_DIR}/pkg-root-${package_name}"

    reset_dir "${pkg_root}"
    mkdir -p "${pkg_root}/DEBIAN" "${pkg_root}/usr/local/bin"
    cat >"${pkg_root}/DEBIAN/control" <<EOF
Package: ${package_name}
Version: ${version}
Section: misc
Priority: optional
Architecture: amd64
Maintainer: Integration Test <integration@example.invalid>
Description: Integration test package ${package_name}
EOF

    cat >"${pkg_root}/usr/local/bin/${package_name}" <<EOF
#!/bin/bash
printf '%s\n' "${message}"
EOF
    chmod 0755 "${pkg_root}/usr/local/bin/${package_name}"
    dpkg-deb --root-owner-group --build "${pkg_root}" "${deb_path}" >/dev/null
}
