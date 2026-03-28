# rdebootstrap

`rdebootstrap` is a manifest-driven Debian/Ubuntu bootstrapper written in Rust.
It resolves packages from user-defined APT archives, locks the full dependency
graph, stages arbitrary artifacts, and builds a root filesystem tree inside a
sandbox so maintainer scripts run in a controlled environment. The same engine
is exposed as the `debrepo` library for embedding in other tooling.

## Highlights

- **Declarative input** – `Manifest.toml` lists archives, optional imports,
  specs, staged files, local `.deb`s, and metadata while
  `Manifest.<arch>.lock` captures the fully resolved set for reproducible
  builds.
- **Deterministic resolution** – Release and Packages files are fetched with GPG
  verification, optional snapshot pinning, and a solver that locks each spec
  before anything is installed.
- **Sandboxed builds** – `build` expands packages inside an isolated helper
  namespace; run as root for production ownership or unprivileged while
  iterating.
- **Rich spec tooling** – add/drop requirements and constraints per spec, stage
  local files or HTTP artifacts, include local packages that ship alongside the
  manifest, and reuse selected parent specs from another locked manifest.
- **Fast, resumable downloads** – concurrent fetcher (`-n/--downloads`) backed
  by a shared cache and optional transport relaxations for air-gapped or test
  environments.

## Requirements

- Linux host with user namespaces enabled (required by the sandbox helper).
- Rust toolchain ≥ 1.89 (`rustup toolchain install 1.89.0`).
- System packages needed by `cargo` plus `gpgme`/`libgpg-error` for Release
  verification.
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

The resulting binary lives at `target/release/rdebootstrap` (or in
`~/.cargo/bin` when installed).

## Typical Workflow

1. **Create a manifest**\
   `rdebootstrap init debian --package ca-certificates --package vim`\
   or bootstrap from another locked manifest:\
   `rdebootstrap init --import ../system/Manifest.toml --spec base --package vim`
2. **Iterate on specs**\
   `rdebootstrap archive add https://mirror.example/debian --suite bookworm,bookworm-updates --components main,contrib`\
   `rdebootstrap require --spec desktop openssh-server network-manager`\
   `rdebootstrap forbid --spec desktop 'systemd-hwe (= 255.5-1)'`
3. **Reuse a locked base manifest (optional)**\
   `rdebootstrap import ../system/Manifest.toml --spec base --spec bootable-base`
4. **Update and lock**\
   `rdebootstrap update --snapshot 20241007T030925Z` (or `--snapshot now`)\
   This downloads Release/Packages data, solves the specs, and writes
   `Manifest.<arch>.lock`.
5. **Build a filesystem tree**\
   `sudo rdebootstrap build --spec desktop --path ./out`\
   The resulting tree may be used directly with podman (requires the full path
   because podman enters its own mount namespace):
   `podman run --rm -it --systemd=always --rootfs "$(pwd)/out" bash -l`

`build` unpacks packages into the target directory, stages artifacts, and runs
maintainer scripts in the sandbox so the host stays clean.

## Manifest Layout

`Manifest.toml` sits at the project root unless `--manifest <path>` is supplied.
The lock file is always written in the same directory as the selected
manifest. For a manifest named `<name>.toml`, the lock file path is
`<name>.<arch>.lock`.

A small example with an imported base spec:

```toml
[import]
path = "../system/Manifest.toml"
hash = "blake3-..."
specs = ["base"]

[[archive]]
url = "https://ftp.debian.org/debian/"
suites = ["trixie"]
components = ["main"]
snapshots = "https://snapshot.debian.org/archive/debian/@SNAPSHOTID@/"

[artifact."motd"]
type = "text"
target = "/etc/motd"
text = "hello from rdebootstrap\n"

[spec.frontend]
extends = "base"
include = ["ca-certificates", "openssh-server"]
stage = ["motd"]

[[local]]
path = "target/debian/mytool_0.1.0_amd64.deb"
hash = "sha256-..."
```

Key sections:

- `[[archive]]` — APT repositories with suites, components, optional snapshot
  templates, trusted keys, and priorities.
- `[import]` — Reuse archives, local packages, and selected named parent specs
  from another manifest. Imported parent specs keep their own staged artifact
  references. `path` and `hash` are required when present; `specs` is optional
  and only needed when exporting imported parent specs for downstream
  `extends`.
- `[[local]]` — Local `.deb` files copied into the cache and treated like repo
  packages.
- `[artifact."<name>"]` — Files or URLs to drop into the tree during staging.
- `[spec]` and `[spec.<name>]` — Package requirements/constraints, staged
  artifacts, build-time environment/script, and metadata per spec. Specs can
  inherit from each other via `extends`. Set `meta = ["apt-lists:stage"]` on a
  spec when you want staging/build output to also include `manifest.sources`
  and downloaded APT list files.

`rdebootstrap import` writes `[import]`, pins the imported manifest bytes in
`hash`, and validates the selected named specs. Imported archives are prepended
to the effective archive list, imported `[[local]]` entries join the effective
package universe, and inherited `stage` entries from imported parent specs keep
resolving their own imported artifacts. Downstream-local `stage` entries still
only resolve artifacts defined in the downstream manifest. Imported local paths
stay anchored to the imported manifest directory.

The downstream lock keeps only downstream-local `archives` and `locals`, plus
an `imported-universe` fingerprint for imported lock state. `rdebootstrap
update` refreshes stale import metadata, re-solves specs when the imported
manifest or imported lock changed, and `build` refuses to run if the resulting
lock is missing or stale.

## Cache and Fetching

- By default caching is enabled and lives in `XDG_CACHE_HOME/rdebootstrap` or
  `~/.cache/rdebootstrap` if `XDG_CACHE_HOME` is unset.
- Use `--cache-dir <dir>` to point elsewhere or `--no-cache` to disable it
  entirely.
- Local artifacts are hashed relative to the manifest directory, so keeping
  manifests and artifacts in the same repository ensures stable paths.
- Content integrity is enforced via the hashes recorded in the lock file;
  disabling cache does not bypass verification.

## Artifacts and Staging

Artifacts are declared at the top level as `[artifact."<name>"]` and referenced
from specs via `stage = ["<name>", ...]`. Use `rdebootstrap artifact add` to
define them and `rdebootstrap stage` to attach them to specs.

APT source metadata is not staged by default. `rdebootstrap` is commonly used
to produce OCI images and other read-only filesystem trees where `apt-get
update` is not expected to work, so staged roots omit `manifest.sources` and
`/var/lib/apt/lists` unless the spec opts in with `meta = ["apt-lists:stage"]`
or `rdebootstrap spec meta set apt-lists stage`.

- Artifact `type` is one of: `file`, `tar`, `dir`, `text`.
- Hashes are serialized in SRI form: `<algo>-<base64>` (for example
  `blake3-...`, `sha256-...`).
- When `rdebootstrap` computes an artifact hash (for example via `artifact add`),
  it uses `blake3`.
- `TARGET_PATH` is treated as an absolute path inside the target filesystem (non-absolute values are
  auto-prefixed with `/` during staging).
  - `{file|text}.ext /path/target` → `/path/target`
  - `{file|text}.ext /path/target/` → `/path/target/file.ext`
- `file.tar /path/target(/?)` → extracted under `/path/target`
- `dir /path/target(/?)` → copied under `/path/target`
- Filename resolution for `{file|text}` artifacts happens during staging; manifests keep the raw
  `target` value.
- Auto-unpack: tar archives and compressed files (`.gz`, `.xz`, `.bz2`, `.zst`,
  `.zstd`) are unpacked by default; use `--no-unpack` to keep them as-is.
- Safety: tar unpacking rejects absolute paths, `..` traversal, and special
  entries like device nodes.
- Inline text artifacts (`type = "text"`) embed a `text` value in the manifest
  and write it to `target` during staging. `rdebootstrap artifact add @file`
  creates a text artifact from a UTF-8 file (target path required).

## Build Environment and Scripts

Specs can set:

- `build-env` — key/value environment variables applied to both `dpkg --configure`
  and `build-script`.
- `build-script` — a bash script executed after package configuration. Scripts
  from `extends` are executed in order (base → derived).

Use `rdebootstrap edit env` / `rdebootstrap edit script` to edit these fields.

`rdebootstrap build` supports `--executor sandbox` (default) and
`--executor podman`. The executor matters mainly for rootless runs: `sandbox`
uses the built-in helper, while `podman` runs configuration inside
`podman run --rootfs ...` (which may require a working rootless podman
environment such as a valid XDG runtime directory).

## CLI Tour

- `init` – bootstrap a manifest from vendor presets (`debian`, `ubuntu`,
  `devuan`), explicit archives, or `--import <path>` from another locked
  manifest.
- `import` – add or replace `[import]` using another already-locked manifest and
  export selected named parent specs.
- `edit` – edit the manifest (`rdebootstrap edit`) or spec metadata (`edit env`,
  `edit script`).
- `archive add`, `deb add` – append repositories or register a local `.deb`.
- `require` / `forbid` – add requirements or version constraints to a spec
  (`include` / `exclude` remain aliases).
- `remove` – remove requirements or constraints (`drop` remains an alias).
- `artifact add`, `stage`, `unstage` – define, add, or remove staged artifacts.
- `update` – refresh metadata, solve dependencies, and rewrite the lock file
  (supports `--snapshot`, `--locals` refreshes local packages and local
  artifacts, and refreshes stored import fingerprints when `[import]` is
  present).
- `list`, `search`, `spec`, `package`, `source` – inspect resolved specs and
  package/source metadata.
- `build` – expand a spec into a directory, running maintainer scripts within
  the sandbox helper.

## Authentication

- `-a/--auth` selects the auth source: omit for optional `auth.toml` next to the
  manifest, use `file:/path/to/auth.toml` (or just a path), or
  `vault:<mount>/<path>` to read secrets from Vault.

Do not commit `auth.toml` to version control.

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

`password.env` reads an env var, `password.cmd` runs a shell command (cwd = auth
file dir), and `password.file`/`password.path` load file content. Tokens and
cert/key accept the same source forms.

- Vault secrets: pass `--auth vault:<mount>/<path>` (for example
  `vault:secret/data/repos`). Each host lives at `<mount>/<path>/<host>` and
  contains JSON like:

```json
{ "type": "basic", "login": "user", "password": "secret" }
{ "type": "token", "token": "token-string" }
{ "type": "mtls", "cert": "PEM string", "key": "PEM key (decrypted)" }
```

`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, and `VAULT_SKIP_VERIFY` influence
the Vault client.

Global flags of note:

- `--manifest <path>` selects an alternate manifest.
- `--arch <arch>` switches the target architecture (default: host arch).
- `-n/--downloads <N>` controls concurrent downloads (default: 20).
- `--cache-dir` / `--no-cache` adjust caching.
- `-k/--insecure` disables TLS certificate and hostname verification
  (not recommended).

Verification controls (scoped):

- `--no-verify` (on `init`, `add archive`, `update`) skips InRelease signature
  verification (not recommended).
- `-K/--allow-insecure` (on archive definitions for `init` and `add archive`, or
  `allow-insecure = true` in the manifest) fetches `Release` instead of
  `InRelease`.

Run `rdebootstrap <command> --help` for exhaustive usage information.

## Known Rough Edges

- Staging/unpacking happens concurrently; this makes `rdebootstrap` incompatible
  with `dpkg-divert` workflows.
- `-q/--quiet` and `-d/--debug` currently affect only `rdebootstrap` output, not
  the output of `dpkg --configure` or `build-script`.

## Development

- `cargo fmt`, `cargo clippy --all-targets`, and `cargo test` keep the codebase
  healthy.
- `cargo bench -p debrepo version` (and other benches under `benches/`) run
  Criterion benchmarks.
- The crate can also be embedded directly by depending on `debrepo` and driving
  `Manifest`/`HostCache` from your own host tooling.

## License

Licensed under the [MIT License](LICENSE).
