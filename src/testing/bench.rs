use super::*;
use async_std::task::block_on;
use criterion::{
    async_executor::AsyncStdExecutor, measurement::Measurement, AsyncBencher, BenchmarkId,
    Criterion, SamplingMode, Throughput,
};
use futures::future::join_all;
use itertools::Itertools;
use std::collections::hash_map::{Entry, HashMap};
use std::time::{Duration, Instant};

struct BenchLedgerScannerConfig {
    txns_per_block: usize,
    blocks: usize,
    receiver: bool,
    background: bool,
}

#[derive(Clone)]
struct BenchLedgerScanner<'a, T: SystemUnderTest<'a> + Clone> {
    t: T,
    rng: ChaChaRng,
    // A ledger prepopulated with some events.
    ledger: Arc<Mutex<MockLedger<'a, T>>>,
    // The receiver of transactions in the prepopulated event stream.
    receiver: UserKeyPair,
    // The index of the latest event.
    sync_time: EventIndex,
    // A wallet state snapshotted from the initial state of the ledger (before any events were
    // generated). This can be used to create a new wallet which will then scan all of the
    // preopulated events in its main event thread.
    initial_state: WalletState<'a, T::Ledger>,
}

type MockLedger<'a, T> = super::MockLedger<
    'a,
    <T as SystemUnderTest<'a>>::Ledger,
    <T as SystemUnderTest<'a>>::MockNetwork,
    <T as SystemUnderTest<'a>>::MockStorage,
>;

// A cache of benchmark setups with pre-generated event streams, indexed by number of blocks and
// number of transactions per block, so that we only have to generate each setup once. This
// dramatically decreases the time required to run the benchmarks.
type LedgerCache<'a, T> = HashMap<(usize, usize), BenchLedgerScanner<'a, T>>;

async fn bench_ledger_scanner_setup<
    'a,
    T: SystemUnderTest<'a, Ledger = L> + Clone,
    L: 'static + Ledger,
>(
    cfg: &BenchLedgerScannerConfig,
    ledger_cache: &mut LedgerCache<'a, T>,
) -> BenchLedgerScanner<'a, T> {
    match ledger_cache.entry((cfg.blocks, cfg.txns_per_block)) {
        Entry::Occupied(e) => e.get().clone(),
        Entry::Vacant(e) => {
            let mut t = T::default();
            let mut rng = ChaChaRng::from_seed([0; 32]);
            let mut now = Instant::now();
            let (ledger, mut wallets) = t
                .create_test_network(
                    &[(1, 2), (2, 2), (3, 3)],
                    vec![1u64 << 32; cfg.txns_per_block],
                    &mut now,
                )
                .await;
            ledger
                .lock()
                .await
                .set_block_size(cfg.txns_per_block)
                .unwrap();
            let initial_state = wallets[0].0.lock().await.state().clone();

            // Create a receiving key for output records. We generate this key outside of any
            // particular wallet, because we may or may not add it to a wallet being benched later,
            // depending on whether we are benchmarking the receiver of transactions or a
            // third-party observer.
            let receiver = UserKeyPair::generate(&mut rng);

            // Add the key to a fresh wallet to force it to be registered in the address book. We
            // will not use this wallet again.
            let mut w = t.create_wallet(&mut rng, &ledger).await;
            w.add_user_key(receiver.clone(), "key".into(), EventIndex::default())
                .await
                .unwrap();

            // Create events by making a number of transfers. We transfer from a number of different
            // wallets so we can easily parallelize the transfers, which speeds things up and allows
            // them all to be included in the same block.
            for _ in 0..cfg.blocks {
                join_all(wallets.iter_mut().map(|(wallet, _)| {
                    let receiver = receiver.address();
                    async move {
                        let receipt = wallet
                            .transfer(None, &AssetCode::native(), &[(receiver, 1)], 1)
                            .await
                            .unwrap();
                        wallet.await_transaction(&receipt).await.unwrap();
                    }
                }))
                .await;
            }
            let sync_time = ledger.lock().await.now();

            let bench = BenchLedgerScanner {
                t,
                rng,
                ledger,
                receiver,
                sync_time,
                initial_state,
            };
            e.insert(bench.clone());
            bench
        }
    }
}

fn bench_ledger_scanner<
    'a,
    'b,
    T: SystemUnderTest<'a> + Clone,
    M: Measurement<Value = Duration>,
>(
    mut b: AsyncBencher<'_, 'b, AsyncStdExecutor, M>,
    ledger_cache: &mut LedgerCache<'a, T>,
    cfg: BenchLedgerScannerConfig,
) {
    let mut bench = block_on(bench_ledger_scanner_setup(&cfg, ledger_cache));
    let scan_key = if cfg.receiver {
        bench.receiver.clone()
    } else {
        UserKeyPair::generate(&mut bench.rng)
    };
    if cfg.background {
        // To create a background scan, just add a new key to an existing wallet.
        b.iter_custom(|n| {
            let mut bench = bench.clone();
            let scan_key = scan_key.clone();
            async move {
                let mut dur = Duration::default();
                for _ in 0..n {
                    let mut w = bench.t.create_wallet(&mut bench.rng, &bench.ledger).await;
                    // Wait for the main event thread to catch up before starting the timer, so that
                    // it is not consuming CPU time and interfering with the benchmark of the
                    // background thread, and so that the background thread has to run all the way
                    // to `sync_time` in order to catch up.
                    w.sync(bench.sync_time).await.unwrap();

                    let start = Instant::now();
                    w.add_user_key(scan_key.clone(), "key".into(), EventIndex::default())
                        .await
                        .unwrap();
                    w.await_key_scan(&scan_key.address()).await.unwrap();
                    dur += start.elapsed();
                }
                dur
            }
        })
    } else {
        // Otherwise, create a new wallet and wait for it to scan all the events.
        b.iter_custom(|n| {
            let mut bench = bench.clone();
            let scan_key = scan_key.clone();
            async move {
                // Add the key directly to the state, ensuring that it is present immediately when
                // the wallet is created.
                bench
                    .initial_state
                    .sending_accounts
                    .insert(scan_key.address(), Account::new(scan_key, "key".into()));

                let state = bench.initial_state.clone();
                let mut dur = Duration::default();
                for _ in 0..n {
                    let state = state.clone();
                    let start = Instant::now();
                    // Create the wallet, starting the main event thread.
                    let w = bench
                        .t
                        .create_wallet_with_state(&mut bench.rng, &bench.ledger, state)
                        .await;
                    // Wait for the wallet to scan all the events.
                    w.sync(bench.sync_time).await.unwrap();
                    dur += start.elapsed();
                }
                dur
            }
        })
    }
}

pub fn instantiate_generic_wallet_bench<'a, T: SystemUnderTest<'a> + Clone>(c: &mut Criterion) {
    let mut ledger_cache = LedgerCache::default();

    // We create a benchmark group for each combination of {receiver, listener} and
    // {background, foreground}. In each group, we measure the performance with varying numbers of
    // transactions in a block, producing a graph of throughput against block size.
    //
    // We keep the total number of blocks constant throughout, since there is no parallelism between
    // blocks and therefore the scaling with number of blocks is perfectly linear. In other words,
    // measuring with varying numbers of blocks would take a lot longer for little benefit.
    for (receiver, background) in [false, true].iter().cartesian_product(&[false, true]) {
        let mut group = c.benchmark_group(format!(
            "seahorse:scanner{},{}",
            if *receiver { "receiver" } else { "listener" },
            if *background { "bg" } else { "fg" }
        ));
        group.sampling_mode(SamplingMode::Flat).sample_size(10);
        for txns_per_block in &[1, 5, 10, 25, 50] {
            group
                .throughput(Throughput::Elements(*txns_per_block))
                .bench_with_input(
                    BenchmarkId::from_parameter(txns_per_block),
                    txns_per_block,
                    |b, &txns_per_block| {
                        bench_ledger_scanner::<T, _>(
                            b.to_async(AsyncStdExecutor),
                            &mut ledger_cache,
                            BenchLedgerScannerConfig {
                                txns_per_block: txns_per_block as usize,
                                // Only generate one block. Criterion is optimized for smaller
                                // benchmarks, and we only care about scaling/parallelism within a
                                // block anyways.
                                blocks: 1,
                                receiver: *receiver,
                                background: *background,
                            },
                        )
                    },
                );
        }
        group.finish();
    }
}
