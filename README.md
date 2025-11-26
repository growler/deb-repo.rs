# rdebootstrap

`rdebootstrap` is a Rust implementation of a manifest-driven Debian bootstrapper. It consumes a declarative `Manifest.toml`, resolves packages from one or more APT repositories (optionally pinned to snapshot IDs), stages additional artifacts, and builds a root filesystem tree inside a sandbox so maintainer scripts run in a controlled environment. The crate also exposes the same functionality as a reusable library (`debrepo`).

## Features
- **Manifest-first workflow** – describe sources, specs, staged files, and local `.deb` artifacts in `Manifest.toml` and keep the resulting lockfile (`Manifest.<arch>.lock`) under version control.
- **Deterministic package resolution** – fetches and verifies Release files with GPGME, supports Debian snapshot URLs, and locks every spec before builds.
- **Rich spec management** – add/remove requirements and constraints, include local packages, and stage arbitrary files into a spec.
- **Sandboxed builds** – `build` runs maintainer scripts inside an isolated namespace; run as root to preserve ownership or as an unprivileged user when testing.
- **Fast downloads** – concurrent fetcher (`-n/--downloads`) backed by a shared cache (`~/.cache/rdebootstrap` or `XDG_CACHE_HOME`), with opt-outs for air‑gapped builds.

## Requirements
- Linux host with user namespaces enabled (needed for the sandbox helper).
- Rust toolchain ≥ 1.85 (`rustup toolchain install 1.85.0`).
- System dependencies required by `cargo` (SSL, libz, etc.) plus `gpgme`/`libgpg-error` for Release verification.
- Optional: `sudo` if you need to set ownership inside the target rootfs.

## Build and Install
```bash
# clone this repository, then
cargo build --release
# or install into ~/.cargo/bin
cargo install --path .
```

The resulting binary is `target/release/rdebootstrap`.

## Quick Start
```bash
# 1. Create a manifest with Debian sources and a base package set
rdebootstrap init --url debian --package ca-certificates --package vim

# 2. Add more requirements or constraints to a spec
rdebootstrap include --spec desktop 'openssh-server' 'network-manager'
rdebootstrap exclude --spec desktop 'systemd-hwe (= 255.5-1)'

# 3. Pin repositories (optional) and update the lock file
rdebootstrap update --snapshot 20241007T030925Z

# 4. Build the spec into a target directory
sudo rdebootstrap build --spec desktop --path ./out/rootfs
```

During `build`, packages are staged into `./out/rootfs` and maintainer scripts execute inside a helper namespace. The cache lives next to the manifest unless `--cache-dir` or `--no-cache` is supplied.

## Manifest Layout
`Manifest.toml` sits at the repo root by default (override with `--manifest`). A minimal file looks like:

```toml
[[source]]
url = "https://ftp.debian.org/debian/"
suites = ["trixie"]
components = ["main"]
snapshots = "https://snapshot.debian.org/archive/debian/@SNAPSHOTID@/"

[spec]
include = ["ca-certificates", "openssh-server"]
stage = ["README.md"]

[[local]]
path = "target/debian/mytool_0.1.0_amd64.deb"
hash = "sha256-..."
```

Sections you can mix in:
- `[[source]]` entries describe APT repositories, suites, components, and optional snapshot templates or trusted keys.
- `[[local]]` registers local `.deb` files so they are copied into the cache and treated like repository packages.
- `[artifact."<name>"]` entries stage arbitrary files or URLs into the tree.
- `[spec]` (and named specs like `[spec.desktop]`) declare requirements/constraints, staged artifacts, and metadata.

`rdebootstrap update` rewrites `Manifest.<arch>.lock` with the resolved versions, while `build` consumes the manifest + lock pair.

## CLI Overview
- `init` – bootstrap a manifest from vendor presets or explicit sources.
- `add source|local` – append repositories or register a local `.deb`.
- `include` / `exclude` – manage package requirements and version constraints per spec.
- `drop` – remove requirements or constraints from a spec.
- `stage` / `unstage` – add or remove arbitrary files/URLs that should appear in the tree.
- `update` – refresh Release/Packages metadata, solve dependencies, and refresh the lockfile (optionally pinning `--snapshot`).
- `list`, `search`, `show` – inspect the currently resolved universe.
- `build` – expand a spec into a directory, running maintainer scripts inside the sandbox helper.

Global flags worth knowing:
- `--manifest <PATH>` selects an alternate manifest.
- `--arch <ARCH>` targets a different architecture (defaults to the host arch).
- `-n/--downloads <N>` controls concurrent downloads (default 20).
- `--cache-dir <DIR>` or `--no-cache` to override caching.
- `-K/--no-verify` and `-k/--insecure` relax Release or TLS verification (not recommended).

Run `rdebootstrap <command> --help` for the full option list.

## Development
- `cargo fmt` and `cargo clippy --all-targets` keep the codebase tidy.
- `cargo test` exercises the parsing, solver, and staging layers.
- `cargo bench -p debrepo version` (etc.) runs the Criterion benches under `benches/`.

## License
Licensed under the [MIT License](LICENSE).
