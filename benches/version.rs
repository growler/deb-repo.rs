use criterion::{criterion_group, criterion_main, Criterion};
use debrepo::version::Version;

macro_rules! bench {
    ($c:expr, $left:tt $op:tt $right:tt) => {{
        use std::str::FromStr;
        let this = Version::from_str($left).unwrap();
        let that = Version::from_str($right).unwrap();
        $c.bench_function(&format!("benchmark {}", stringify!($left $op $right)), |b| b.iter(|| {
            std::hint::black_box({
                &this $op &that
            });
        }));
    }}
}

pub fn version_compare_benchmark(c: &mut Criterion) {
    bench!(c, "2" > "1");
    bench!(c, "1.0.3~rc2+b2" > "1.0.3~rc2+b1");
    bench!(
        c,
        "0.0.0+2016.01.15.git.29cc9e1b05-2+b8" < "0.0.0+2016.02.15.git.29cc9e1b05"
    );
    bench!(
        c,
        "0.0.0+2016.01.15.git.29cc9e1b05-2+b8" != "0.0.0+2016.02.15.git.29cc9e1b05"
    );
}

criterion_group!(benches, version_compare_benchmark);
criterion_main!(benches);
