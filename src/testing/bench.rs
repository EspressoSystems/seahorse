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
use strum::IntoEnumIterator;

#[derive(Clone, Copy, Debug, PartialEq, Eq, strum_macros::EnumIter, strum_macros::Display)]
enum ScannerRole {
    Listener,
    Receiver,
    Viewer,
}

struct BenchLedgerScannerConfig {
    txns_per_block: usize,
    blocks: usize,
    role: ScannerRole,
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
    // Viewable and freezable assets used in pregenerated transactions.
    assets: Vec<(AssetInfo, AuditorKeyPair, FreezerKeyPair)>,
    // The index of the first event for the benchmark to scan.
    start_time: EventIndex,
    // The index of the latest event for the benchmark to scan.
    end_time: EventIndex,
    // A wallet state snapshotted from the initial state of the benchmark (after `start_time`). This
    // can be used to create a new wallet which will then scan all of the preopulated events in its
    // main event thread.
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
    blocks: usize,
    txns_per_block: usize,
    ledger_cache: &mut LedgerCache<'a, T>,
) -> BenchLedgerScanner<'a, T> {
    match ledger_cache.entry((blocks, txns_per_block)) {
        Entry::Occupied(e) => e.get().clone(),
        Entry::Vacant(e) => {
            let mut t = T::default();
            let mut rng = ChaChaRng::from_seed([0; 32]);
            let mut now = Instant::now();
            let (ledger, mut wallets) = t
                .create_test_network(
                    &[(1, 2), (2, 2), (3, 3)],
                    vec![1u64 << 32; txns_per_block],
                    &mut now,
                )
                .await;
            ledger.lock().await.set_block_size(txns_per_block).unwrap();

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

            // Mint a viewable asset for each wallet.
            let assets = join_all(wallets.iter_mut().enumerate().map(
                |(i, (wallet, addrs))| async move {
                    let viewing_pub_key =
                        wallet.generate_audit_key("viewing".into()).await.unwrap();
                    let viewing_key = wallet
                        .get_auditor_private_key(&viewing_pub_key)
                        .await
                        .unwrap();
                    let freezing_pub_key =
                        wallet.generate_freeze_key("freezing".into()).await.unwrap();
                    let freezing_key = wallet
                        .get_freezer_private_key(&freezing_pub_key)
                        .await
                        .unwrap();
                    let asset = wallet
                        .define_asset(
                            format!("asset {}", i),
                            &[],
                            AssetPolicy::default()
                                .set_auditor_pub_key(viewing_pub_key)
                                .set_freezer_pub_key(freezing_pub_key)
                                .reveal_record_opening()
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    let receipt = wallet
                        .mint(&addrs[0], 1, &asset.code, 1u64 << 32, addrs[0].clone())
                        .await
                        .unwrap();
                    wallet.await_transaction(&receipt).await.unwrap();
                    (AssetInfo::from(asset), viewing_key, freezing_key)
                },
            ))
            .await;

            // Wait for the wallets to catch up to the state before we snapshot the `initial_state`
            // wallet.
            t.sync(&ledger, &wallets).await;

            // Create events by making a number of transfers. We transfer from a number of different
            // wallets so we can easily parallelize the transfers, which speeds things up and allows
            // them all to be included in the same block.
            let start_time = ledger.lock().await.now();
            let initial_state = wallets[0].0.lock().await.state().clone();
            for _ in 0..blocks {
                join_all(
                    wallets
                        .iter_mut()
                        .zip(&assets)
                        .map(|((wallet, _), (asset, _, _))| {
                            let receiver = receiver.address();
                            async move {
                                let receipt = wallet
                                    .transfer(None, &asset.definition.code, &[(receiver, 1)], 1)
                                    .await
                                    .unwrap();
                                wallet.await_transaction(&receipt).await.unwrap();
                            }
                        }),
                )
                .await;
            }
            // Let the wallets finish processing events. This ensures that `end_time` is up-to-date
            // when we snapshot it below, and it keeps the setup wallets' event threads from
            // interfering with the benchmark later on.
            t.sync(&ledger, &wallets).await;
            let end_time = ledger.lock().await.now();

            let bench = BenchLedgerScanner {
                t,
                rng,
                ledger,
                receiver,
                assets,
                start_time,
                end_time,
                initial_state,
            };
            e.insert(bench.clone());
            bench
        }
    }
}

fn bench_ledger_scanner_run<
    'a,
    'b,
    T: SystemUnderTest<'a> + Clone,
    M: Measurement<Value = Duration>,
>(
    mut b: AsyncBencher<'_, 'b, AsyncStdExecutor, M>,
    mut bench: BenchLedgerScanner<'a, T>,
    cfg: BenchLedgerScannerConfig,
) {
    let scan_key = if cfg.role == ScannerRole::Receiver {
        bench.receiver.clone()
    } else {
        UserKeyPair::generate(&mut bench.rng)
    };

    // Set up the wallet state for the benchmark.
    let state = &mut bench.initial_state;
    // If this is a viewing benchmark, add the viewable assets and viewing keys to the state.
    if cfg.role == ScannerRole::Viewer {
        for (asset, viewing_key, freezing_key) in &bench.assets {
            state.freezing_accounts.insert(
                freezing_key.pub_key(),
                Account::new(freezing_key.clone(), "freezing".into()),
            );
            state.viewing_accounts.insert(
                viewing_key.pub_key(),
                Account::new(viewing_key.clone(), "viewing".into()),
            );
            state.assets.add_audit_key(viewing_key.pub_key());
            state.assets.insert(asset.clone());
        }
    }

    if cfg.background {
        // To create a background scan, just add a new key to an existing wallet.
        b.iter_custom(|n| {
            let mut bench = bench.clone();
            let scan_key = scan_key.clone();
            async move {
                let mut dur = Duration::default();
                for _ in 0..n {
                    let mut w = bench
                        .t
                        .create_wallet_with_state(
                            &mut bench.rng,
                            &bench.ledger,
                            bench.initial_state.clone(),
                        )
                        .await;

                    // Wait for the main event thread to catch up before starting the timer, so that
                    // it is not consuming CPU time and interfering with the benchmark of the
                    // background thread, and so that the background thread has to run all the way
                    // to `sync_time` in order to catch up.
                    w.sync(bench.end_time).await.unwrap();

                    let start = Instant::now();
                    w.add_user_key(scan_key.clone(), "key".into(), bench.start_time)
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

                let mut dur = Duration::default();
                for _ in 0..n {
                    let state = bench.initial_state.clone();
                    let start = Instant::now();
                    // Create the wallet, starting the main event thread.
                    let w = bench
                        .t
                        .create_wallet_with_state(&mut bench.rng, &bench.ledger, state)
                        .await;
                    // Wait for the wallet to scan all the events.
                    w.sync(bench.end_time).await.unwrap();
                    dur += start.elapsed();
                }
                dur
            }
        })
    }
}

pub fn instantiate_generic_wallet_bench<'a, T: SystemUnderTest<'a> + Clone>(c: &mut Criterion) {
    // Only generate one block per benchmark. Criterion is optimized for smaller benchmarks, and we
    // only care about scaling/parallelism within a block anyways.
    let blocks = 1;
    let txns_per_block = [1, 5, 10, 25, 50];

    // Prepopulate the cache with all the benchmark setups we will need.
    let mut ledger_cache = LedgerCache::default();
    for txns_per_block in &txns_per_block {
        println!(
            "Pregenerating {} blocks of {} transactions each",
            blocks, *txns_per_block
        );
        block_on(bench_ledger_scanner_setup(
            blocks,
            *txns_per_block,
            &mut ledger_cache,
        ));
    }

    // We create a benchmark group for each combination of {receiver, listener} and
    // {background, foreground}. In each group, we measure the performance with varying numbers of
    // transactions in a block, producing a graph of throughput against block size.
    //
    // We keep the total number of blocks constant throughout, since there is no parallelism between
    // blocks and therefore the scaling with number of blocks is perfectly linear. In other words,
    // measuring with varying numbers of blocks would take a lot longer for little benefit.
    for (role, background) in ScannerRole::iter().cartesian_product(&[false, true]) {
        let mut group = c.benchmark_group(format!(
            "seahorse:scanner:{},{}",
            role,
            if *background { "bg" } else { "fg" }
        ));
        group
            .sampling_mode(SamplingMode::Flat)
            .sample_size(20)
            // Set quite a long warmup and measurement time as this is a slow benchmark.
            .warm_up_time(Duration::from_secs(15))
            .measurement_time(Duration::from_secs(30));
        for txns_per_block in &txns_per_block {
            let bench = ledger_cache[&(blocks, *txns_per_block)].clone();
            group
                .throughput(Throughput::Elements(*txns_per_block as u64))
                .bench_with_input(
                    BenchmarkId::from_parameter(txns_per_block),
                    txns_per_block,
                    |b, &txns_per_block| {
                        bench_ledger_scanner_run::<T, _>(
                            b.to_async(AsyncStdExecutor),
                            bench.clone(),
                            BenchLedgerScannerConfig {
                                txns_per_block: txns_per_block as usize,

                                blocks,
                                role,
                                background: *background,
                            },
                        )
                    },
                );
        }
        group.finish();
    }
}
