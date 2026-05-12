# rdebootstrap
[![Tests](https://github.com/growler/rdebootstrap.rs/actions/workflows/test.yml/badge.svg)](https://github.com/growler/rdebootstrap.rs/actions/workflows/test.yml) ![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/growler/38f16304c1c99d385ef2d8086f16f5e0/raw/coverage.json) [![Docs](https://docs.rs/debrepo/badge.svg)](https://docs.rs/debrepo) [![Crates.io](https://img.shields.io/crates/v/debrepo.svg?maxAge=2592000)](https://crates.io/crates/debrepo)

`rdebootstrap` is a manifest-driven Debian/Ubuntu bootstrapper written in Rust.
It resolves packages from user-defined APT repositories, locks the full dependency
graph, stages arbitrary artifacts, and builds a root filesystem tree inside a
sandbox so that maintainer scripts run in a controlled environment. The same
engine is exposed as the `debrepo` library for embedding in other tooling.

The project uses itself to build locked [Debian](debian-build.toml) and [Ubuntu](ubuntu-build.toml)
trees, and then uses those trees to build its own packages for those distributions.

## Highlights

- **Declarative input** -- `Manifest.toml` lists archives, optional imports,
  specs, staged files, local `.deb`s, and metadata while
  `Manifest.<arch>.lock` captures the fully resolved set for reproducible
  builds.
- **Deterministic resolution** -- Release and Packages files are fetched with GPG
  verification, optional snapshot pinning, and a solver that locks each spec
  before anything is installed.
- **Sandboxed builds** -- `build` expands packages inside an isolated helper
  namespace or inside a `podman` container; run as root for production ownership
  or unprivileged while iterating.
- **Rich spec tooling** -- add/drop requirements and constraints per spec, stage
  local files or HTTP artifacts, include local packages that ship alongside the
  manifest, and reuse selected parent specs from another locked manifest.
- **Fast, resumable downloads** -- concurrent fetcher (`-n/--downloads`) backed
  by a shared cache and optional transport relaxations for air-gapped or test
  environments.

## Requirements

- Linux host with user namespaces enabled (required by the sandbox helper).
- Rust toolchain >= 1.89 (`rustup toolchain install 1.89.0`).
- A handful of libraries are required; see [debian-build.toml](debian-build.toml) for the list.

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
2. **Add requirements to a spec**\
   `rdebootstrap archive add https://mirror.example/debian --suite bookworm,bookworm-updates --components main,contrib`\
   `rdebootstrap require --spec desktop openssh-server network-manager`\
   `rdebootstrap forbid --spec desktop 'systemd-hwe (= 255.5-1)'`
3. **Reuse a locked base manifest (optional)**\
   `rdebootstrap import ../system/Manifest.toml --spec base --spec bootable-base`
4. **Update and lock**\
   `rdebootstrap update --snapshot 20241007T030925Z` (or `--snapshot today`)\
   This downloads Release/Packages data, solves the specs, and writes
   `Manifest.<arch>.lock`.
5. **Build a filesystem tree**\
   `rdebootstrap build --spec desktop --path ./out`\
   The resulting tree may be used directly with podman:
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
url = "https://security.debian.org/debian-security/"
snapshots = "https://snapshot.debian.org/archive/debian-security/@SNAPSHOTID@/"
suites = ["trixie-security"]
components = ["main"]

[[local]]
path = "target/debian/mytool_0.1.0_amd64.deb"
hash = "sha256-..."

[artifact."motd"]
type = "text"
target = "/etc/motd"
text = "hello from rdebootstrap\n"

[spec.backend]
extends = "base"
include = ["ca-certificates", "openssh-server", "mytool"]
stage = ["motd"]

```

Key sections:

- `[[archive]]` -- APT repositories with suites, components, optional snapshot
  templates, trusted keys, and priorities.
- `[import]` -- Reuse archives, local packages, and selected named parent specs
  from another manifest. Imported parent specs keep their own staged artifact
  references. Either `path` (local-filesystem import) or a nested `git` table
  (git-sourced import) is required, plus `hash`; `specs` is optional and only
  needed when exporting imported parent specs for downstream `extends`. See
  *Git-sourced imports* below.
- `[[local]]` -- Local `.deb` files copied into the cache and treated like repo
  packages.
- `[artifact."<name>"]` -- Files or URLs to drop into the tree during staging.
- `[spec]` and `[spec.<name>]` -- Package requirements/constraints, staged
  artifacts, build-time environment/script, and metadata per spec. Specs can
  inherit from one or more other specs via `extends` (see *Spec inheritance*
  below). Set `meta = ["apt-lists:stage"]` on a spec when you want
  staging/build output to also include `manifest.sources` and downloaded APT
  list files.

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

## Git-sourced Imports

`[import.git]` references a manifest hosted in a git repository.  The same
manifest works for developers (typically using SSH) and for CI pipelines
(typically using HTTPS with a token), because the manifest never names a
transport — only the protocol-agnostic `host/path` plus a resolved commit
SHA.  The transport is part of the URL stored in the manifest.

```toml
[import]
hash  = "blake3-..."          # blake3 of the imported manifest file's bytes
specs = ["base"]

[import.git]
remote = "https://gitlab.com/myorg/system-manifests"  # full URL with scheme
rev    = "5b1f9c2a4d3e0f8b7a6c9d2e1f0a3b4c5d6e7f80"    # always a 40-hex SHA
ref    = "release-2024.10"    # optional: branch or tag tracked by `update`
path   = "system/Manifest.toml"   # in-repo path of the imported manifest
```

Add or replace a git import.  `--import` is a single argument that accepts
either a local manifest path or a `git+<scheme>://` URL:

```bash
# Local path (relative or absolute)
rdebootstrap import ../base/Manifest.toml --spec base
rdebootstrap import file:///srv/manifests/base.toml --spec base

# Git-hosted manifest
rdebootstrap import 'git+https://gitlab.com/myorg/repo.git?rev=v1.2.3#system/Manifest.toml' --spec base
rdebootstrap import 'git+http://internal.example/myorg/repo?ref=stable#system/Manifest.toml' --spec base
rdebootstrap import 'git+ssh://git@gitlab.com/myorg/repo.git?ref=main#system/Manifest.toml'

# Local git checkout / bare repo (no network)
rdebootstrap import 'git+file:///srv/git/myorg-repo.git?rev=<sha>#system/Manifest.toml'

# `init --import` accepts the same shapes when bootstrapping a fresh manifest.
```

Only the six forms above are accepted.  Older shorthand spellings
(`git@host:path`, plain `https://`/`ssh://` without the `git+` prefix,
bare `host/path?rev=...#...`) are rejected up-front.

`rdebootstrap update --locals` re-resolves a recorded `ref` (branch or tag)
against the upstream repository and re-pins `rev` if upstream has moved.

### Authentication

The transport is encoded in the remote URL; there is no separate transport
selector.  Use `git+ssh://` or `git+https://` to choose:

```bash
# SSH (uses system ssh — ~/.ssh/config, ssh-agent, smart cards)
rdebootstrap import 'git+ssh://git@gitlab.com/myorg/repo?ref=main#system/Manifest.toml'

# HTTPS (credentials come from auth.toml)
rdebootstrap import 'git+https://gitlab.com/myorg/repo?ref=main#system/Manifest.toml'
```

For HTTPS git, `[[auth]]` entries in `auth.toml` keyed by hostname supply
credentials.  The same entry format used for HTTP archive fetches applies:

```toml
# Bearer / token auth (e.g. GitLab deploy token, GitHub PAT)
[[auth]]
host = "gitlab.com"
token.env = "CI_JOB_TOKEN"

# Basic auth
[[auth]]
host = "internal.example"
login = "myuser"
password.env = "MY_SECRET"

# Client certificate (HTTPS mutual TLS)
[[auth]]
host = "secure.example"
cert = "client.crt"   # path relative to auth.toml, or PEM inline
key  = "client.key"
```

Credentials are injected via `GIT_CONFIG_*` environment variables
(`http.extraHeader` for Basic/Token, `http.sslCert`/`http.sslKey` for Cert)
so secrets never appear on `git`'s argv.

SSH credentials are never written into `auth.toml`; SSH delegates entirely to
the system `ssh` invoked by subprocess `git`, which honours `~/.ssh/config`,
`ssh-agent`, smart cards, and `gpg-agent --enable-ssh-support`.

To remap a URL to a different base — for example to substitute HTTPS for SSH
in a CI environment — use git's own mechanism:

```bash
git config --global url."https://gitlab.com/".insteadOf "ssh://git@gitlab.com/"
# or set GIT_CONFIG_GLOBAL to point at a config file with the same directive.
```

### Requirements and caching

- `git >= 2.30` must be on `PATH`.
- A bare clone is kept under `<cache>/git/<sha256(url)>/repo.git`.
  Per-rev subtree extracts go to `<cache>/git/<sha256>/revs/<sha>/`.
- Partial clone (`--filter=blob:none`) is used so only the imported
  manifest, its lock, and any `[[local]]`/local-artifact blobs the
  manifest references are actually fetched.

The downstream lock file mirrors the resolved commit in
`imported-git-rev = "<sha>"`; mismatch with `[import.git].rev` invalidates
the lock.

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
- `TARGET_PATH` is treated as an absolute path inside the target filesystem
  (non-absolute values are auto-prefixed with `/` during staging).
  - `{file|text}.ext /path/target` → `/path/target`
  - `{file|text}.ext /path/target/` → `/path/target/file.ext`
- `file.tar /path/target(/?)` → extracted under `/path/target`
- `dir /path/target(/?)` → copied under `/path/target`
- Filename resolution for `{file|text}` artifacts happens during staging;
  manifests keep the raw
  `target` value.
- Auto-unpack: tar archives and compressed files (`.gz`, `.xz`, `.bz2`, `.zst`,
  `.zstd`) are unpacked by default; use `--no-unpack` to keep them as-is.
- Safety: tar unpacking rejects absolute paths, `..` traversal, and special
  entries like device nodes.
- Inline text artifacts (`type = "text"`) embed a `text` value in the manifest
  and write it to `target` during staging. `rdebootstrap artifact add @file`
  creates a text artifact from a UTF-8 file (target path required).

## Spec Inheritance

A spec may extend any number of other specs.  Inheritance is **strictly
additive**: a child spec cannot remove a package, build-env entry, meta
entry, or stage artifact contributed by any ancestor.  This keeps lock
semantics monotone and conflict-free even with diamond ancestors.

The `extends` field accepts either a single string (the original
single-parent shape) or an array of strings:

```toml
[spec.tools]
include = ["tar"]

[spec.extras]
include = ["rsync"]

[spec.frontend]
extends = ["tools", "extras"]   # multi-parent
include = ["openssh-server"]
```

Order matters in two places: the entries of `extends` are processed in
declaration order (used as a tie-break in the topological order of
ancestors), and the first listed parent is the *primary* parent --
downstream consumers like `deb-ostree` use it as the OSTree commit's
parent reference, with remaining parents overlaid additively.

Conflict policy:

- `build-env` -- the child always overrides ancestors.  If two distinct
  ancestors set the same key to different values *and* the child does
  not redeclare it, the conflict is reported as a hard error at
  resolve/build time.  Identical values across ancestors are fine.
- `meta` -- same policy as `build-env`.
- `stage` artifacts -- merged in topological order.  The same artifact
  reachable via multiple ancestors is staged exactly once; artifacts
  with the same URI string but defined in different manifests (e.g.,
  imported vs. local) are distinct and both are staged.
- packages -- a child's `exclude` cannot drop a package locked by any
  ancestor; the solver fails with `requested to remove packages from
  ancestor specs: <list>`.

Use `rdebootstrap spec extend` to manage parents:

```text
rdebootstrap spec extend -s frontend tools extras       # replace list
rdebootstrap spec extend -s frontend --add foo          # append
rdebootstrap spec extend -s frontend --remove extras    # drop one
rdebootstrap spec extend -s frontend --clear            # remove all
```

Single-parent manifests are unaffected: `extends = "base"` keeps its
existing TOML form and produces identical lock hashes.

## Build Environment and Scripts

Specs can set:

- `build-env` -- key/value environment variables applied to both `dpkg --configure`
  and `build-script`.
- `build-script` -- a bash script executed after package configuration. Scripts
  from ancestors are executed in topological order (base scripts first,
  then derived).  Each unique ancestor contributes its script at most
  once; sibling ancestors run in `extends` declaration order.

Use `rdebootstrap edit env` / `rdebootstrap edit script` to edit these fields.

`rdebootstrap build` supports `--executor sandbox` (default) and
`--executor podman`. The executor matters mainly for rootless runs: `sandbox`
uses the built-in helper, while `podman` runs configuration inside
`podman run --rootfs ...` (which may require a working rootless podman
environment such as a valid XDG runtime directory).

## CLI Tour

- `init` -- bootstrap a manifest from vendor presets (`debian`, `ubuntu`,
  `devuan`), explicit archives, or `--import <PATH-OR-URL>` from another
  already-locked manifest (local path or `git+<scheme>://` URL).
- `import` -- add or replace `[import]` using another already-locked manifest
  (local path or git URL) and export selected named parent specs.
- `edit` -- edit the manifest (`rdebootstrap edit`) or spec metadata (`edit env`,
  `edit script`).
- `archive add`, `deb add` -- append repositories or register a local `.deb`.
- `require` / `forbid` -- add requirements or version constraints to a spec.
- `remove` -- remove requirements or constraints (`drop` remains an alias).
- `artifact add` -- define, add, or remove staged artifacts.
- `spec artifact add` / `remove` -- add or remove an artifact from the spec.
- `update` -- refresh metadata, solve dependencies, and rewrite the lock file
  (supports `--snapshot`; `--locals` refreshes local packages, local
  artifacts, and stored import fingerprints when `[import]` is present).
- `list`, `search`, `spec`, `package`, `source` -- inspect resolved specs and
  package/source metadata.
- `build` -- expand a spec into a directory, running maintainer scripts within
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

Run `rdebootstrap <command> --help` or `man rdebootstrap` for exhaustive usage
information.

## Known Rough Edges

- Staging/unpacking happens concurrently; this makes `rdebootstrap` incompatible
  with `dpkg-divert` workflows.
- `-q/--quiet` and `-d/--debug` currently affect only `rdebootstrap` output, not
  the output of `dpkg --configure` or `build-script`.

## A Necessary Explanation

The `debrepo` library is a foundation for an in-house CI/CD system (which is
still too ugly to release), and that explains certain design choices. For
example, `debrepo` requires `libgpgme-dev` and `libcurl` instead of pure-Rust
alternatives because that system uses them anyway, and having two GPG or HTTP
client implementations in the same binary seemed a bit much.

For the same reason, the library may feel a bit over-engineered (see the
`StagingFileSystem` trait, for example, or the rather corporatish repo
authentication). All these excesses are absolutely necessary.

## Development

- `cargo fmt`, `cargo clippy`, and `cargo test` keep the codebase
  healthy.
- `cargo bench -p debrepo version` (and other benches under `benches/`) run
  Criterion benchmarks.
- The crate can also be embedded directly by depending on `debrepo`.

## License

Licensed under the [MIT License](LICENSE).
