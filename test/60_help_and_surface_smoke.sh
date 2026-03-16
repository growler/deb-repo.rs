#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

prepare_case "60_help_and_surface_smoke"

run_case_expect_ok "version" --version
assert_stdout_contains "rdebootstrap"

run_case_expect_ok "top_help" --help
for command in init archive deb artifact import require forbid remove stage unstage list update build search spec package source edit; do
    assert_stdout_contains "  ${command}"
done

for command in archive deb artifact import require forbid remove stage unstage list update build search spec package source edit; do
    run_case_expect_ok "${command}_help" "${command}" --help
    assert_stdout_contains "Usage: rdebootstrap ${command}"
done

run_case_expect_ok "update_help" update --help
assert_stdout_contains "--import"

run_case_expect_ok "include_help" include --help
assert_stdout_contains "Usage: rdebootstrap require"
assert_stdout_contains "Add one or more package requirements to a spec"

run_case_expect_ok "exclude_help" exclude --help
assert_stdout_contains "Usage: rdebootstrap forbid"
assert_stdout_contains "Add one or more constraints to restrict resolution"

run_case_expect_ok "drop_help" drop --help
assert_stdout_contains "Usage: rdebootstrap remove"
assert_stdout_contains "Remove requirements and/or constraints from a spec"
