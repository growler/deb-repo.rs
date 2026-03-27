# Debian Fixture Blobs

These fixture blobs are used by [debrepo/tests/deb.rs](/home/growler/projects/rust-nightly/deb-repo/debrepo/tests/deb.rs).

- `minimal-*.deb` are valid binary packages built from `minimal-root/` with `dpkg-deb`.
- `rich-xz.deb` is the richer valid package used for `extract_to` and `DebStage` tests.
- `rich-src/` is a minimal Debian source package wrapper intended for regenerating `rich-xz.deb` with `dpkg-buildpackage` on a standard Debian-like system.

Regenerate the committed blobs with:

```bash
./debrepo/tests/fixtures/deb/build-fixtures.sh
```

The script prefers `dpkg-buildpackage` for the rich fixture when the host has a usable Debian package database. In environments like this Nix workspace, that often is not available, so the script falls back to `dpkg-deb` while still keeping the source package around for Debian-native regeneration.
