#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand::{thread_rng, Rng};

use iota_pow::{PearlDiver, PowOptions};
const MIN_WEIGHT_MAGNITUDE: usize = 9;

fn basic_pow(trits: Vec<i8>) {
    let mut pearl = PearlDiver::default();
    pearl
        .search(
            trits,
            PowOptions {
                min_weight_magnitude: MIN_WEIGHT_MAGNITUDE,
                ..PowOptions::default()
            },
        )
        .unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut trits = vec![0; 8019];
    c.bench_function("Run PoW", move |b| {
        b.iter(|| {
            for trit in trits.iter_mut() {
                *trit = rng.gen_range(-1, 2);
            }
            basic_pow(trits.clone());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
