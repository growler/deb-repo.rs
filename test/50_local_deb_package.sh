#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "50_local_deb_package"
trap 'cleanup_tree "${TREE_DIR}"' EXIT

PKG_ROOT="${CASE_DIR}/pkg-root"
PKG_NAME="integration-local_0.0.1_amd64.deb"
PKG_PATH="${CASE_DIR}/${PKG_NAME}"

mkdir -p "${PKG_ROOT}/DEBIAN" "${PKG_ROOT}/usr/local/bin"
cat >"${PKG_ROOT}/DEBIAN/control" <<'EOF'
Package: integration-local
Version: 0.0.1
Section: misc
Priority: optional
Architecture: amd64
Maintainer: Integration Test <integration@example.invalid>
Description: Integration test package
EOF

cat >"${PKG_ROOT}/usr/local/bin/integration-local" <<'EOF'
#!/bin/bash
printf 'integration-local-ok\n'
EOF
chmod 0755 "${PKG_ROOT}/usr/local/bin/integration-local"

dpkg-deb --root-owner-group --build "${PKG_ROOT}" "${PKG_PATH}" >/dev/null

run_case_rdb deb add "./${PKG_NAME}"
run_case_rdb update --archives --locals
run_case_rdb require integration-local

build_tree "sandbox" "${TREE_DIR}"
assert_runtime_packages "${TREE_DIR}" integration-local
assert_runtime_file "${TREE_DIR}" /usr/local/bin/integration-local

output="$(run_podman_rootfs "${TREE_DIR}" /usr/local/bin/integration-local)"
assert_equals "integration-local-ok" "${output}" "local package command output"

cleanup_tree "${TREE_DIR}"
trap - EXIT
