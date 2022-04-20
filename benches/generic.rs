use criterion::{criterion_group, criterion_main, Criterion};
use seahorse::testing::{instantiate_generic_keystore_bench, mocks::MockSystemWithHeight};

pub fn generic(c: &mut Criterion) {
    instantiate_generic_keystore_bench::<MockSystemWithHeight<10>>(c)
}

criterion_group!(benches, generic);
criterion_main!(benches);
