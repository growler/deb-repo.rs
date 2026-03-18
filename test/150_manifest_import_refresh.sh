#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "150_manifest_import_refresh"

SYSTEM_DIR="${CASE_DIR}/system"
SYSTEM_MANIFEST="${SYSTEM_DIR}/Manifest.toml"
SYSTEM_LOCK="${SYSTEM_DIR}/Manifest.amd64.lock"

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

cat >>"${SYSTEM_MANIFEST}" <<'EOF'

[spec.base]
include = ["tar"]
EOF

run_system_expect_ok "system_update_base" update
run_case_expect_ok "import_add" import ./system/Manifest.toml --spec base

cat >>"${MANIFEST}" <<'EOF'

[spec.frontend]
extends = "base"
include = ["rsync"]
EOF

run_case_expect_ok "downstream_update" update

hash_before="$(grep '^hash = ' "${MANIFEST}" | head -n 1)"

printf '\n# drift\n' >>"${SYSTEM_MANIFEST}"
run_system_expect_ok "system_update_drift" update
run_case_expect_ok "refresh_import" update

hash_after="$(grep '^hash = ' "${MANIFEST}" | head -n 1)"
assert_not_equals "${hash_before}" "${hash_after}" "import hash refresh"
