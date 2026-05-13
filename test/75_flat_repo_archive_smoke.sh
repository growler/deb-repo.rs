#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/test/lib.sh"

# Offline scenario: exercise the manifest-level invariants for flat-repository
# archives (Debian "flat repository format" -- see sources.list(5)) without
# touching the network.  The baseline manifest already carries a valid lock;
# we append flat-archive blocks directly to the manifest TOML and rely on
# `spec list` to parse + validate the manifest.

bootstrap_manifest "75_flat_repo_archive_smoke"

manifest_with_archive_block() {
    cp -- "${BASELINE_MANIFEST}" "${MANIFEST}"
    cat >>"${MANIFEST}" <<'EOF'

[[archive]]
EOF
    cat >>"${MANIFEST}"
}

# Single-suite flat archive ("/" -- the repository root): must load cleanly
# even though the appended `[[archive]]` block carries no `components` field.
manifest_with_archive_block <<'EOF'
url = "https://example.invalid/cuda/"
suites = ["/"]
signed-by = "/usr/share/keyrings/example.gpg"
EOF
run_case_expect_ok "flat_root_loads" spec list
assert_stdout_contains "<default>"
assert_manifest_contains 'suites = ["/"]'

# Multi-path flat archive: load + validation must accept several `/`-terminated
# paths in a single `suites` array.
manifest_with_archive_block <<'EOF'
url = "https://example.invalid/flat/"
suites = ["./", "extras/"]
EOF
run_case_expect_ok "flat_multi_path_loads" spec list
assert_manifest_contains 'suites = ["./", "extras/"]'

# Flat suite + components is rejected by Archive::validate.
manifest_with_archive_block <<'EOF'
url = "https://example.invalid/cuda/"
suites = ["/"]
components = ["main"]
EOF
run_case_expect_fail "flat_with_components_rejected" spec list
assert_stderr_contains "flat repository suites cannot set"

# Mixed flat and non-flat suites in one archive is rejected.
manifest_with_archive_block <<'EOF'
url = "https://example.invalid/mixed/"
suites = ["/", "stable"]
EOF
run_case_expect_fail "flat_mixed_with_codename_rejected" spec list
assert_stderr_contains "must not mix flat entries"

# Empty suites is always invalid -- the validator phrases the error around the
# flat-repo escape hatch (`suites = ["/"]`).
manifest_with_archive_block <<'EOF'
url = "https://example.invalid/empty/"
suites = []
EOF
run_case_expect_fail "empty_suites_rejected" spec list
assert_stderr_contains "suites"

# Non-flat archive without an explicit `components` list is rejected: there
# is no implicit `["main"]` default.  Vendor presets (debian/ubuntu/devuan)
# remain the only path that supplies defaults, and they do so via
# `as_vendor` expansion, not via the manifest-level fallback.
manifest_with_archive_block <<'EOF'
url = "https://example.invalid/repo/"
suites = ["stable"]
EOF
run_case_expect_fail "non_flat_without_components_rejected" spec list
assert_stderr_contains "non-flat repository requires at least one component"
