#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "20_build_podman_executor"
trap 'cleanup_tree "${TREE_DIR}"' EXIT

build_tree "podman" "${TREE_DIR}"
assert_runtime_packages "${TREE_DIR}" bash coreutils grep sed ca-certificates
assert_runtime_file "${TREE_DIR}" /bin/bash

cleanup_tree "${TREE_DIR}"
trap - EXIT
