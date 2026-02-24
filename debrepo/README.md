# debrepo

`debrepo` is an async-first Rust toolkit for working with Debian/Ubuntu **binary
package repositories**: parse APT metadata (`Packages`, `Release`), read `.deb`
artifacts, and compute consistent dependency solutions (via `resolvo`).

It powers the `rdebootstrap` rootfs builder in this repository, but is designed
as a set of reusable building blocks for other tooling too.

## Why debrepo?

- Aims to be the most comprehensive Debian binary package tooling in Rust (built
  for real-world APT repository data).
- Async-first and optimized for streaming I/O and caching (indexes, `.deb`, tar
  payloads).
- Dependency solving over combined `Packages` inputs (solver backend: `resolvo`).

## Status / compatibility

- **Rust MSRV:** 1.89 (see `Cargo.toml`).
- **Stability:** 0.x; API may change between releases.
- **Async runtime:** uses the `smol` ecosystem. Tokio integration is not tested
  or targeted; PRs welcome.
- **Platform:** Unix-like only (uses Unix APIs; intended for Linux).

## Quickstart

Add the dependency:

```toml
[dependencies]
debrepo = "0.1"
```

## Examples

The snippets below are intentionally small and focus on the shape of the API.

### Parse a `Packages` index

```rust
use debrepo::Packages;

let pkgs: Packages = packages_text
    .to_string()
    .try_into()
    .expect("valid Debian Packages file");

let bash = pkgs.package_by_name("bash").expect("bash present");
println!("{} {}", bash.name(), bash.raw_version());
```

### Solve dependencies (Universe + `resolvo`)

```rust
use debrepo::{Dependency, Packages, Universe};

let pkgs: Packages = packages_text.to_string().try_into().expect("valid Packages");
let mut u = Universe::new("amd64", [pkgs]).expect("universe");

let sol = u
    .solve(
        ["bash".parse::<Dependency<String>>().expect("dep")],
        std::iter::empty::<debrepo::Constraint<String>>(),
    )
    .expect("solvable");
println!("selected: {}", sol.len());
```

### Read a `.deb` (control payload)

```rust
use debrepo::deb::DebReader;

// inside an `async fn` (smol-based I/O):
let f = smol::fs::File::open("pkg.deb").await?;
let mut deb = DebReader::new(f);
let control = deb.extract_control().await?;
println!("package = {:?}", control.package_name());
```

## What you get

- `Package` / `Packages`: parse Debian `Packages` index files (binary package
  metadata).
- `Version` / `VersionSet`: Debian version parsing + ranges / constraints (e.g.
  `(>= 1.0)`, epochs like `2:1.0-3`, and `a | b` dependencies).
- `Release`: parse `Release` files and discover hashed index paths.
- `HttpTransport` (+ caching helpers): fetch repository content over HTTP(S).
- `deb::DebReader`: async `.deb` reader for control/data payloads.
- `tar`: simple async tar reader/writer for common cases.
- `universe::Universe`: combine multiple `Packages` inputs and solve with
  `resolvo`.
- `StagingFileSystem`: stage files into a target filesystem layout.
- `Manifest` / `LockBase`: manifest + lockfile structures used by `rdebootstrap`.

Full API docs are on https://docs.rs/debrepo.

## System dependencies

`debrepo` uses `gpgme` for OpenPGP-related operations (e.g. repository metadata
verification). On Debian/Ubuntu you will typically need `libgpgme-dev` and
`pkg-config` installed for builds.

## Related

- `rdebootstrap`: the end-to-end rootfs builder powered by this crate (in this
  repository).

## Thanks

Special thanks to the authors of `resolvo`: https://github.com/prefix-dev/resolvo
