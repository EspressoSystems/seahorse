use criterion::{criterion_group, criterion_main, Criterion};
use seahorse::testing::{instantiate_generic_wallet_bench, mocks::MockSystem};

pub fn generic(c: &mut Criterion) {
    instantiate_generic_wallet_bench::<MockSystem>(c)
}

criterion_group!(benches, generic);
criterion_main!(benches);
