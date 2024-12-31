use criterion::{criterion_group, criterion_main, Criterion};
use debrepo::{
    ControlParser,
    Dependency, Package, Packages, Universe,
};
use std::fs;
use std::path::PathBuf;

pub fn parse_benchmark(c: &mut Criterion) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("benches/Packages");
    let data = fs::read_to_string(&path).expect("Failed to read test Packages");

    c.bench_function("parse test", |b| {
        b.iter(|| {
            let mut parser = ControlParser::new(&data);
            let mut packages: Vec<Package<'_>> = vec![];
            while let Some(package) =
                Package::try_parse_from(&mut parser).expect("failed to parse package")
            {
                packages.push(package)
            }
        })
    });

    c.bench_function("solve test", |b| {
        b.iter(|| {
            let packages = vec![Packages::try_from(
                fs::read_to_string(&path).expect("failed to read test packages"),
            )
            .expect("failed to parse packages")];
            let uni = Universe::new("amd64", packages.into_iter()).expect("universe");
            let mut solver = resolvo::Solver::new(uni);
            let problem = solver
                .provider()
                .problem(vec![Dependency::try_from("firefox-esr").unwrap()], vec![]);
            let _ = match solver.solve(problem) {
                Ok(solution) => solution,
                Err(resolvo::UnsolvableOrCancelled::Unsolvable(conflict)) => {
                    panic!("{}", conflict.display_user_friendly(&solver))
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
