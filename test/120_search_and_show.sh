#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

bootstrap_manifest "120_search_and_show"

run_case_expect_ok "search" search bash
assert_stdout_contains "bash"

run_case_expect_ok "package_search" package search bash
assert_stdout_contains "bash"

run_case_expect_ok "package_show" package show bash
assert_stdout_contains "Package: bash"
package_version="$(awk '/^Version:/ { print $2; exit }' "${LAST_STDOUT}")"
[[ -n "${package_version}" ]] || die "failed to parse bash version from package show output"

run_case_expect_ok "source_show" source show "bash"
assert_stdout_contains "Package: bash"

run_case_expect_ok "source_stage" source show --stage-to /usr/src "bash"
assert_stdout_contains "[artifact.\""
assert_stdout_contains "stage = ["
