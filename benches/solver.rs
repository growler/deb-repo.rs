use criterion::{criterion_group, criterion_main, Criterion};
use debrepo::{
    content::IndexFile, control::ControlParser, hash::Hash, universe::Universe,
    version::Dependency, Package, Packages,
};
use std::path::PathBuf;

async fn fetch_packages() -> IndexFile {
    let path =  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benches/data/snapshot.debian.org_archive_debian_20241201T025825Z_dists_bookworm_main_binary-amd64_Packages.xz");
    let size = 8788624;
    let hash = Hash::from_hex(
        "SHA256",
        "2f674d057c5f274c5a863664a586ef62a0deb571993914ccfe4e2cd784a4840d",
    )
    .unwrap();
    println!("Loading package data from {:?}", path);
    IndexFile::read(debrepo::unpacker(
        path.to_str().expect("valid path"),
        hash.verifying_reader(
            size,
            smol::fs::File::open(&path)
                .await
                .expect("open snapshot file"),
        ),
    ))
    .await
    .expect("read data file")
}

pub fn parse_benchmark(c: &mut Criterion) {
    let data = smol::block_on(fetch_packages());
    let mut g = c.benchmark_group("solve");

    g.bench_function("parse packages", |b| {
        b.iter(|| {
            let mut parser = ControlParser::new(&data);
            let mut count = 0;
            while let Some(pkg) =
                Package::try_parse_from(&mut parser).expect("failed to parse package")
            {
                std::hint::black_box(&pkg);
                count += 1;
            }
            std::hint::black_box(count);
        })
    });
    g.measurement_time(std::time::Duration::from_secs(20));

    g.bench_function("find solution", |b| {
        b.iter(|| {
            let packages =
                Some(Packages::new(data.clone(), None).expect("failed to parse packages"));
            let mut uni = Universe::new("amd64", packages).expect("universe");
            let _ = match uni.solve(
                vec!["task-gnome-desktop | task-kde-desktop"
                    .parse::<Dependency<String>>()
                    .unwrap()],
                vec![],
            ) {
                Ok(solution) => solution,
                Err(err) => {
                    panic!("{}", uni.display_conflict(err))
                }
            };
        })
    });
}

criterion_group!(benches, parse_benchmark);
criterion_main!(benches);
