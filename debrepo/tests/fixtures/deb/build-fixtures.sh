#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/debrepo-deb-fixtures.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

build_minimal_matrix() {
    for compressor in none gzip xz zstd; do
        dpkg-deb --root-owner-group -Z"${compressor}" --build \
            "${ROOT}/minimal-root" \
            "${ROOT}/minimal-${compressor}.deb" >/dev/null
    done
}

prepare_rich_root() {
    local target="${TMPDIR}/rich-root"
    cp -a "${ROOT}/rich-root" "${target}"
    ln -sf ./usr/bin/fixture-rich "${target}/usr/bin/fixture-rich-link"
    ln "${target}/usr/bin/fixture-rich" "${target}/usr/bin/fixture-rich-hard"
}

build_rich_with_dpkg_deb() {
    prepare_rich_root
    dpkg-deb --no-check --root-owner-group -Zxz --build \
        "${TMPDIR}/rich-root" \
        "${ROOT}/rich-xz.deb" >/dev/null
}

build_rich_with_dpkg_buildpackage() {
    [[ -r /var/lib/dpkg/status ]] || return 1
    local src="${TMPDIR}/rich-src-1.0"
    cp -a "${ROOT}/rich-src" "${src}"
    (
        cd "${src}"
        dpkg-buildpackage -b -uc -us -rfakeroot -d >/dev/null
    )
    cp "${TMPDIR}/rich-fixture_1.0_amd64.deb" "${ROOT}/rich-xz.deb"
}

build_minimal_matrix
if ! build_rich_with_dpkg_buildpackage; then
    build_rich_with_dpkg_deb
fi
