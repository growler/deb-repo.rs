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

debug=0
while getopts ":d" opt; do
    case "${opt}" in
        d)
            debug=1
            ;;
        :)
            die "option requires an argument: -${OPTARG}"
            ;;
        \?)
            die "unknown option: -${OPTARG}"
            ;;
    esac
done
shift $((OPTIND - 1))

export RDEBOOTSTRAP_DEBUG="${debug}"

require_cmd bash
require_cmd awk
require_cmd cargo
require_cmd cmp
require_cmd dpkg-deb
require_cmd find
require_cmd gzip
require_cmd readlink
require_cmd sort
require_cmd tar

mapfile -t scenarios < <(find "${REPO_ROOT}/test" -maxdepth 1 -type f -name '[0-9][0-9]*_*.sh' | sort -V)
if [[ "${#scenarios[@]}" -eq 0 ]]; then
    die "no integration scenarios found under ${REPO_ROOT}/test"
fi

if [[ "$#" -gt 0 ]]; then
    selected_scenarios=()
    for selector in "$@"; do
        normalized_selector="$(basename "${selector}" .sh)"
        matches=()
        for scenario in "${scenarios[@]}"; do
            if [[ "$(basename "${scenario}" .sh)" == "${normalized_selector}" ]]; then
                matches+=("${scenario}")
            fi
        done
        case "${#matches[@]}" in
            1)
                selected_scenarios+=("${matches[0]}")
                ;;
            0)
                die "unknown test scenario: ${selector}"
                ;;
            *)
                die "test scenario is ambiguous: ${selector}"
                ;;
        esac
    done
    scenarios=("${selected_scenarios[@]}")
fi

rm -rf -- "${TEST_ROOT}"
mkdir -p "${LOG_DIR}"

note "Building target/release/rdebootstrap"
cargo build -p rdebootstrap --release

if [[ "${RDEBOOTSTRAP_DEBUG}" == "1" ]]; then
    note "rdebootstrap debug logging enabled"
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
