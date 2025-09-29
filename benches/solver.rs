use criterion::{criterion_group, criterion_main, Criterion};
use debrepo::{
    control::ControlParser, hash::FileHash, universe::Universe, version::Dependency,
    HttpTransportProvider, Package, Packages, TransportProvider,
};
use std::sync::Arc;

async fn fetch_packages() -> Arc<str> {
    let transport = HttpTransportProvider::new(false).await;
    let uri = "https://snapshot.debian.org/archive/debian/20241201T025825Z/dists/bookworm/main/binary-amd64/Packages.xz";
    let size = 8788624;
    let hash: FileHash = "2f674d057c5f274c5a863664a586ef62a0deb571993914ccfe4e2cd784a4840d"
        .try_into()
        .unwrap();
    let data = transport
        .fetch_verify_unpack(uri, size, &hash, 100_000_000)
        .await
        .expect("package downloaded");
    String::from_utf8(data).expect("correct utf-8").into()
}

pub fn parse_benchmark(c: &mut Criterion) {
    let data = smol::block_on(fetch_packages());

    c.bench_function("parse test", |b| {
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

    let mut g = c.benchmark_group("solve");
    g.measurement_time(std::time::Duration::from_secs(10));

    g.bench_function("solve test", |b| {
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
