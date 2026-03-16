#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TEST_ROOT="${REPO_ROOT}/target/integration-test"
LOG_DIR="${TEST_ROOT}/logs"
RDEBOOTSTRAP="${REPO_ROOT}/target/release/rdebootstrap"

export REPO_ROOT
export TEST_ROOT
export LOG_DIR
export RDEBOOTSTRAP

source "${REPO_ROOT}/test/lib.sh"

require_cmd bash
require_cmd cargo
require_cmd cmp
require_cmd dpkg-deb
require_cmd gzip
require_cmd readlink
require_cmd tar

rm -rf -- "${TEST_ROOT}"
mkdir -p "${LOG_DIR}"

if [[ "${RDEBOOTSTRAP_FORCE_BUILD:-0}" == "1" || ! -x "${RDEBOOTSTRAP}" ]]; then
    note "Building target/release/rdebootstrap"
    cargo build -p rdebootstrap --release
fi

mapfile -t scenarios < <(find "${REPO_ROOT}/test" -maxdepth 1 -type f -name '[0-9][0-9]*_*.sh' | sort -V)
if [[ "${#scenarios[@]}" -eq 0 ]]; then
    die "no integration scenarios found under ${REPO_ROOT}/test"
fi

passes=0
failures=0

for scenario in "${scenarios[@]}"; do
    name="$(basename "${scenario}" .sh)"
    log_file="${LOG_DIR}/${name}.log"
    note "Running ${name}"
    if "${scenario}" >"${log_file}" 2>&1; then
        printf 'PASS %s\n' "${name}"
        passes=$((passes + 1))
    else
        printf 'FAIL %s (log: %s)\n' "${name}" "${log_file}" >&2
        tail -n 40 "${log_file}" >&2 || true
        failures=$((failures + 1))
    fi
done

printf 'Summary: %d passed, %d failed\n' "${passes}" "${failures}"

if (( failures > 0 )); then
    exit 1
fi
