use criterion::{black_box, criterion_group, criterion_main, Criterion};
use debrepo::ControlFile;

const TEXT : &str = "\
Package: coreutils
Version: 9.1-1
Architecture: amd64
Essential: yes
Maintainer: Michael Stone <mstone@debian.org>
Installed-Size: 18062
Pre-Depends: libacl1 (>= 2.2.23), libattr1 (>= 1:2.4.44), libc6 (>= 2.34), libgmp10 (>= 2:6.2.1+dfsg1), libselinux1 (>= 3.1~)
Section: utils
Priority: required
Multi-Arch: foreign
Homepage: http://gnu.org/software/coreutils
Description: GNU core utilities
 This package contains the basic file, shell and text manipulation
 utilities which are expected to exist on every operating system.
 .
 Specifically, this package includes:
 arch base64 basename cat chcon chgrp chmod chown chroot cksum comm cp
 csplit cut date dd df dir dircolors dirname du echo env expand expr
 factor false flock fmt fold groups head hostid id install join link ln
 logname ls md5sum mkdir mkfifo mknod mktemp mv nice nl nohup nproc numfmt
 od paste pathchk pinky pr printenv printf ptx pwd readlink realpath rm
 rmdir runcon sha*sum seq shred sleep sort split stat stty sum sync tac
 tail tee test timeout touch tr true truncate tsort tty uname unexpand
 uniq unlink users vdir wc who whoami yes
";

pub fn parse_benchmark(c: &mut Criterion) {
    c.bench_function("parse test", |b| b.iter(||{
        ControlFile::parse(black_box(TEXT)).unwrap();
    }));
}

criterion_group!(benches, parse_benchmark);
criterion_main!(benches);
