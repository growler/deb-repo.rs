use async_std::task;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use debrepo::{ControlParser, DebRepo, Dependency, HttpDebRepo, Package, Packages, Universe};
use std::sync::Arc;

async fn fetch_packages() -> Arc<str> {
    let repo: DebRepo =
        HttpDebRepo::new("https://snapshot.debian.org/archive/debian/20241201T025825Z/")
            .await
            .expect("repo")
            .into();
    let release = repo.fetch_release("bookworm").await.expect("release file");
    let (path, size, hash) = release
        .packages_file("main", "amd64")
        .expect("package file found");
    let data = repo
        .fetch_verify_unpack(&path, size, hash)
        .await
        .expect("package file fetched");
    String::from_utf8(data).expect("correct utf-8").into()
}

pub fn parse_benchmark(c: &mut Criterion) {
    let data = task::block_on(fetch_packages());

    c.bench_function("parse test", |b| {
        b.iter(|| {
            let mut parser = ControlParser::new(&data);
            let mut count = 0;
            while let Some(_) =
                Package::try_parse_from(&mut parser).expect("failed to parse package")
            {
                count += 1;
            }
            black_box(count);
        })
    });

    let mut g = c.benchmark_group("solve");
    g.measurement_time(std::time::Duration::from_secs(10));

    g.bench_function("solve test", |b| {
        b.iter(|| {
            let packages = vec![Packages::new(debrepo::null_provider(), data.clone())
                .expect("failed to parse packages")];
            let mut uni = Universe::new("amd64", packages.into_iter()).expect("universe");
            let problem = uni.problem(
                vec![Dependency::try_from("task-gnome-desktop | task-kde-desktop").unwrap()],
                vec![],
            );
            let _ = match uni.solve(problem) {
                Ok(solution) => solution,
                Err(resolvo::UnsolvableOrCancelled::Unsolvable(conflict)) => {
                    panic!("{}", uni.display_conflict(conflict))
                }
                Err(err) => {
                    panic!("{:?}", err)
                }
            };
        })
    });
}

criterion_group!(benches, parse_benchmark);
criterion_main!(benches);
