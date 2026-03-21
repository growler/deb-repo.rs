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

normalize_path() {
    readlink -m -- "$1"
}

manifest_dir_for_path() {
    local manifest="$1"
    local cwd="$2"
    local manifest_abs

    if [[ "${manifest}" = /* ]]; then
        manifest_abs="$(normalize_path "${manifest}")"
    else
        manifest_abs="$(normalize_path "${cwd}/${manifest}")"
    fi

    normalize_path "$(dirname -- "${manifest_abs}")"
}

relative_path_between() {
    local path_abs
    local base_abs
    local trimmed_path
    local trimmed_base
    local -a path_parts=()
    local -a base_parts=()
    local -a relative_parts=()
    local common=0
    local i

    path_abs="$(normalize_path "$1")"
    base_abs="$(normalize_path "$2")"
    trimmed_path="${path_abs#/}"
    trimmed_base="${base_abs#/}"

    if [[ -n "${trimmed_path}" ]]; then
        IFS=/ read -r -a path_parts <<<"${trimmed_path}"
    fi
    if [[ -n "${trimmed_base}" ]]; then
        IFS=/ read -r -a base_parts <<<"${trimmed_base}"
    fi

    while (( common < ${#path_parts[@]} && common < ${#base_parts[@]} )); do
        if [[ "${path_parts[common]}" != "${base_parts[common]}" ]]; then
            break
        fi
        common=$((common + 1))
    done

    for ((i = common; i < ${#base_parts[@]}; i++)); do
        relative_parts+=("..")
    done
    for ((i = common; i < ${#path_parts[@]}; i++)); do
        relative_parts+=("${path_parts[i]}")
    done

    if [[ "${#relative_parts[@]}" -eq 0 ]]; then
        printf '.\n'
    else
        local joined="${relative_parts[*]}"
        printf '%s\n' "${joined// /\/}"
    fi
}

manifest_rebased_path() {
    local input_path="$1"
    local manifest="$2"
    local cwd="$3"
    local manifest_dir
    local cwd_abs
    local resolved

    if [[ "${input_path}" = /* ]]; then
        printf '%s\n' "${input_path}"
        return
    fi

    cwd_abs="$(normalize_path "${cwd}")"
    manifest_dir="$(manifest_dir_for_path "${manifest}" "${cwd_abs}")"
    if [[ "${manifest_dir}" == "${cwd_abs}" ]]; then
        printf '%s\n' "${input_path}"
        return
    fi

    resolved="$(normalize_path "${cwd_abs}/${input_path}")"
    relative_path_between "${resolved}" "${manifest_dir}"
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

rdebootstrap_debug_enabled() {
    [[ "${RDEBOOTSTRAP_DEBUG:-0}" == "1" ]]
}

format_rdebootstrap_command() {
    local manifest="$1"
    shift
    local -a cmd=("rdebootstrap")
    if rdebootstrap_debug_enabled; then
        cmd+=(-d)
    fi
    cmd+=(-m "${manifest}" "$@")
    local rendered
    printf -v rendered '%q ' "${cmd[@]}"
    printf '%s' "${rendered% }"
}

run_rdebootstrap_manifest() {
    local workdir="$1"
    local manifest="$2"
    shift 2
    (
        cd "${workdir}"
        local -a cmd=("${RDEBOOTSTRAP}")
        if rdebootstrap_debug_enabled; then
            cmd+=(-d)
        fi
        cmd+=(-m "${manifest}" "$@")
        "${cmd[@]}"
    )
}

capture_rdebootstrap_manifest() {
    local label="$1"
    local workdir="$2"
    local manifest="$3"
    local output_dir="$4"
    shift 4
    LAST_STDOUT="${output_dir}/${label}.stdout"
    LAST_STDERR="${output_dir}/${label}.stderr"
    if run_rdebootstrap_manifest "${workdir}" "${manifest}" "$@" >"${LAST_STDOUT}" 2>"${LAST_STDERR}"; then
        LAST_STATUS=0
    else
        LAST_STATUS=$?
    fi
    if rdebootstrap_debug_enabled && [[ -s "${LAST_STDERR}" ]]; then
        printf -- '---- %s stderr ----\n' "${label}" >&2
        cat -- "${LAST_STDERR}" >&2
    fi
    return "${LAST_STATUS}"
}

run_case_rdb() {
    run_rdebootstrap_manifest "${CASE_DIR}" "${MANIFEST}" "$@"
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
    capture_rdebootstrap_manifest "${label}" "${CASE_DIR}" "${MANIFEST}" "${CASE_DIR}" "$@"
}

run_case_expect_ok() {
    local label="$1"
    shift
    if ! run_case_capture "${label}" "$@"; then
        if ! rdebootstrap_debug_enabled; then
            tail -n 40 "${LAST_STDERR}" >&2 || true
        fi
        die "command failed (${label}): $(format_rdebootstrap_command "${MANIFEST}" "$@")"
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
        die "expected command to fail (${label}): $(format_rdebootstrap_command "${MANIFEST}" "$@")"
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

assert_file_comment_attached_to_list_item() {
    local file="$1"
    local comment="$2"
    local item="$3"
    awk -v comment="# ${comment}" -v item="${item}" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }
        {
            line = trim($0)
            if (line == comment) {
                pending = 1
                next
            }
            if (pending) {
                if (line == "") {
                    next
                }
                if (substr(line, 1, 1) == "\"" && index(line, item) > 0) {
                    found = 1
                    exit 0
                }
                pending = 0
            }
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "${file}" >/dev/null || die "expected ${file} to attach comment '${comment}' to list item containing: ${item}"
}

assert_file_lacks_comment_attached_to_list_item() {
    local file="$1"
    local comment="$2"
    local item="$3"
    if awk -v comment="# ${comment}" -v item="${item}" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }
        {
            line = trim($0)
            if (line == comment) {
                pending = 1
                next
            }
            if (pending) {
                if (line == "") {
                    next
                }
                if (substr(line, 1, 1) == "\"" && index(line, item) > 0) {
                    found = 1
                    exit 0
                }
                pending = 0
            }
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "${file}" >/dev/null; then
        die "expected ${file} to not attach comment '${comment}' to list item containing: ${item}"
    fi
}

assert_file_comment_attached_to_block() {
    local file="$1"
    local comment="$2"
    local header="$3"
    local body="$4"
    awk -v comment="# ${comment}" -v header="${header}" -v body="${body}" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }
        {
            line = trim($0)
            if (line == comment) {
                pending = 1
                in_block = 0
                next
            }
            if (pending) {
                if (line == "") {
                    next
                }
                if (substr(line, 1, 1) == "[" && index(line, header) > 0) {
                    pending = 0
                    in_block = 1
                    next
                }
                pending = 0
            }
            if (in_block) {
                if (line != "" && substr(line, 1, 1) == "[") {
                    in_block = 0
                } else if (index(line, body) > 0) {
                    found = 1
                    exit 0
                }
            }
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "${file}" >/dev/null || die "expected ${file} to attach comment '${comment}' to block '${header}' containing: ${body}"
}

assert_file_lacks_comment_attached_to_block() {
    local file="$1"
    local comment="$2"
    local header="$3"
    local body="$4"
    if awk -v comment="# ${comment}" -v header="${header}" -v body="${body}" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }
        {
            line = trim($0)
            if (line == comment) {
                pending = 1
                in_block = 0
                next
            }
            if (pending) {
                if (line == "") {
                    next
                }
                if (substr(line, 1, 1) == "[" && index(line, header) > 0) {
                    pending = 0
                    in_block = 1
                    next
                }
                pending = 0
            }
            if (in_block) {
                if (line != "" && substr(line, 1, 1) == "[") {
                    in_block = 0
                } else if (index(line, body) > 0) {
                    found = 1
                    exit 0
                }
            }
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "${file}" >/dev/null; then
        die "expected ${file} to not attach comment '${comment}' to block '${header}' containing: ${body}"
    fi
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

assert_manifest_comment_attached_to_list_item() {
    assert_file_comment_attached_to_list_item "${MANIFEST}" "$1" "$2"
}

assert_manifest_lacks_comment_attached_to_list_item() {
    assert_file_lacks_comment_attached_to_list_item "${MANIFEST}" "$1" "$2"
}

assert_manifest_comment_attached_to_block() {
    assert_file_comment_attached_to_block "${MANIFEST}" "$1" "$2" "$3"
}

assert_manifest_lacks_comment_attached_to_block() {
    assert_file_lacks_comment_attached_to_block "${MANIFEST}" "$1" "$2" "$3"
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
