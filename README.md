# rdebootstrap

`rdebootstrap` is a manifest-driven Debian/Ubuntu bootstrapper written in Rust. It resolves packages from user-defined APT archives, locks the full dependency graph, stages arbitrary artifacts, and builds a root filesystem tree inside a sandbox so maintainer scripts run in a controlled environment. The same engine is exposed as the `debrepo` library for embedding in other tooling.

## Highlights
- **Declarative input** – `Manifest.toml` lists archives, specs, staged files, local `.deb`s, and metadata while `Manifest.<arch>.lock` captures the fully resolved set for reproducible builds.
- **Deterministic resolution** – Release and Packages files are fetched with GPG verification, optional snapshot pinning, and a solver that locks each spec before anything is installed.
- **Sandboxed builds** – `build` expands packages inside an isolated helper namespace; run as root for production ownership or unprivileged while iterating.
- **Rich spec tooling** – add/drop requirements and constraints per spec, stage local files or HTTP artifacts, and include local packages that ship alongside the manifest.
- **Fast, resumable downloads** – concurrent fetcher (`-n/--downloads`) backed by a shared cache and optional transport relaxations for air-gapped or test environments.

## Requirements
- Linux host with user namespaces enabled (required by the sandbox helper).
- Rust toolchain ≥ 1.85 (`rustup toolchain install 1.85.0`).
- System packages needed by `cargo` plus `gpgme`/`libgpg-error` for Release verification.
- Optional `sudo` when you need ownership preserved inside the target rootfs.

## Installation
```bash
# clone this repo
cargo build --release

# or install into ~/.cargo/bin
cargo install --path .

# nix users
nix build .#rdebootstrap
```

The resulting binary lives at `target/release/rdebootstrap` (or in `~/.cargo/bin` when installed).

## Typical Workflow
1. **Create a manifest**  
   `rdebootstrap init --url debian --package ca-certificates --package vim`
2. **Iterate on specs**  
   `rdebootstrap include --spec desktop openssh-server network-manager`  
   `rdebootstrap exclude --spec desktop 'systemd-hwe (= 255.5-1)'`
3. **Update and lock**  
   `rdebootstrap update --snapshot 20241007T030925Z`  
   This downloads Release/Packages data, solves the specs, and writes `Manifest.<arch>.lock`.
4. **Build a filesystem tree**  
   `sudo rdebootstrap build --spec desktop --path ./out`  
   The resulting tree may be used directly with podman (requires the full path because podman enters its own mount namespace): `podman run --rm -it --systemd=always --rootfs "$(pwd)/out" bash -l`

`build` unpacks packages into the target directory, stages artifacts, and runs maintainer scripts in the sandbox so the host stays clean.

## Manifest Layout
`Manifest.toml` sits at the project root unless `--manifest <path>` is supplied. A small example:

```toml
[[archive]]
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

Key sections:
- `[[archive]]` — APT repositories with suites, components, optional snapshot templates, trusted keys, and priorities.
- `[[local]]` — Local `.deb` files copied into the cache and treated like repo packages.
- `[artifact."<name>"]` — Files or URLs to drop into the tree during staging.
- `[spec]` and `[spec.<name>]` — Package requirements/constraints, staged artifacts, and metadata per spec. Specs can inherit from each other via `extends`.

`rdebootstrap update` keeps the lock file aligned with the manifest, and `build` refuses to run if the lock is missing or stale.

## Cache and Fetching
- By default caching is enabled and lives in `XDG_CACHE_HOME/rdebootstrap` or `~/.cache/rdebootstrap` if `XDG_CACHE_HOME` is unset.  
- Use `--cache-dir <dir>` to point elsewhere or `--no-cache` to disable it entirely.  
- Local artifacts are hashed relative to the manifest directory, so keeping manifests and artifacts in the same repository ensures stable paths.  
- Content integrity is enforced via the hashes recorded in the lock file; disabling cache does not bypass verification.

## CLI Tour
- `init` – bootstrap a manifest from vendor presets or explicit archives.
- `edit` – edit the manifest or spec metadata.
- `add archive`, `add local` – append repositories or register a local `.deb`.
- `include` / `exclude` – add requirements or version constraints to a spec.
- `drop` – remove requirements or constraints.
- `stage` / `unstage` – add or remove artifacts (local files or URLs).
- `update` – refresh metadata, solve dependencies, and rewrite the lock file (supports `--snapshot`).
- `list`, `search`, `show` – inspect the resolved package universe.
- `build` – expand a spec into a directory, running maintainer scripts within the sandbox helper.

## Authentication
- `-a/--auth` selects the archive: omit for optional `auth.toml` in the same directory where Manifest is located, 
use `file:/path/to/auth.toml` (or just a path), or `vault:<prefix>` to read secrets from Vault.

- Auth file (`auth.toml`) supports per-host entries:
```toml
[[auth]]
host = "deb.example.com"
login = "user"
password = "inline"                # or password.env / password.cmd

[[auth]]
host = "deb.other.com"
token = "token-string"

[[auth]]
host = "deb.tls.com"
cert = "relative/cert.pem"         # relative paths are resolved from the auth file directory
key = "relative/key.pem"
# password/env/cmd/file are also supported for passwords
```
`password.env` reads an env var, `password.cmd` runs a shell command (cwd = auth file dir), 
and `password.file`/`password.path` load file content. Tokens and cert/key accept the same source forms.

- Vault secrets: pass `--auth vault:<prefix>`, where `<prefix>` is the full API path 
prefix (e.g. `secret/repos` for KV v1, `secret/data/repos` for KV v2). Each host lives 
at `<prefix>/<host>` with JSON like:

```json
{ "type": "basic", "login": "user", "password": "secret" }
{ "type": "token", "token": "token-string" }
{ "type": "mtls", "cert": "PEM string", "key": "PEM key (decrypted)" }
```

`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, and `VAULT_SKIP_VERIFY` influence the Vault client.

Global flags of note:
- `--manifest <path>` selects an alternate manifest.
- `--arch <arch>` switches the target architecture (default: host arch).
- `-n/--downloads <N>` controls concurrent downloads (default: 20).
- `--cache-dir`, `--no-cache`, `-K/--no-verify`, and `-k/--insecure` adjust caching and verification.

Run `rdebootstrap <command> --help` for exhaustive usage information.

## Development
- `cargo fmt`, `cargo clippy --all-targets`, and `cargo test` keep the codebase healthy.
- `cargo bench -p debrepo version` (and other benches under `benches/`) run Criterion benchmarks.
- The crate can also be embedded directly by depending on `debrepo` and driving `Manifest`/`HostCache` from your own host tooling.

## License
Licensed under the [MIT License](LICENSE).
