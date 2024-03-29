use super::*;
use async_std::task::block_on;
use criterion::{
    async_executor::AsyncStdExecutor, measurement::Measurement, AsyncBencher, BenchmarkId,
    Criterion, SamplingMode, Throughput,
};
use futures::future::join_all;
use itertools::Itertools;
use std::collections::hash_map::HashMap;
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
struct BenchLedgerScannerTransactions<L: Ledger> {
    // Mint transactions which must be submitted before the transfers.
    mints: Vec<(MintNote, TransactionParams<L>)>,
    // Independent transfers, one for each asset type.
    transfers: Vec<(TransferNote, TransactionParams<L>)>,
    // Receiver of transfers.
    receiver: UserKeyPair,
    // Asset types used in the transactions.
    assets: Vec<Asset>,
    // Viewing key for assets used in the transactions.
    viewing_key: ViewerKeyPair,
    // Freezing key for assets used in the transactions.
    freezing_key: FreezerKeyPair,
}

#[derive(Clone)]
struct BenchLedgerScanner<T: SystemUnderTest + Clone> {
    t: T,
    rng: ChaChaRng,
    // A ledger prepopulated with some events.
    ledger: Arc<Mutex<MockLedger<T>>>,
    // The receiver of transactions in the prepopulated event stream.
    receiver: UserKeyPair,
    // Viewable and freezable assets used in pregenerated transactions.
    assets: Vec<Asset>,
    // Viewing key for assets used in the transactions.
    viewing_key: ViewerKeyPair,
    // Freezing key for assets used in the transactions.
    freezing_key: FreezerKeyPair,
    // The index of the first event for the benchmark to scan.
    start_time: EventIndex,
    // The index of the latest event for the benchmark to scan.
    end_time: EventIndex,
    // A keystore state snapshotted from the initial state of the benchmark (after `start_time`). This
    // can be used to create a new keystore which will then scan all of the preopulated events in its
    // main event thread.
    initial_state: LedgerState<T::Ledger>,
}

type MockLedger<T> =
    super::MockLedger<<T as SystemUnderTest>::Ledger, <T as SystemUnderTest>::MockNetwork>;

// A cache of benchmark setups with pre-generated event streams, indexed by number of blocks and
// number of transactions per block, so that we only have to generate each setup once. This
// dramatically decreases the time required to run the benchmarks.
type LedgerCache<'a, T> = HashMap<(usize, usize), BenchLedgerScanner<T>>;

// Generate `n` independent transfers. Since the transfers are independent (no two involve the same
// assets) they can be grouped into blocks and played back in whatever way the benchmark requires.
async fn generate_independent_transactions<
    'a,
    T: SystemUnderTest<Ledger = L> + Clone,
    L: 'static + Ledger,
>(
    n: usize,
) -> BenchLedgerScannerTransactions<L> {
    let mut t = T::default();
    let mut rng = ChaChaRng::from_seed([0; 32]);
    let mut now = Instant::now();
    let (ledger, mut keystores) = t
        .create_test_network(&[(1, 2), (2, 2), (3, 3)], vec![1u64 << 32; n], &mut now)
        .await;
    ledger.lock().await.set_block_size(n).unwrap();

    // Create a receiving key for output records. We generate this key outside of any
    // particular keystore, because we may or may not add it to a keystore being benched later,
    // depending on whether we are benchmarking the receiver of transactions or a
    // third-party observer.
    let receiver = UserKeyPair::generate(&mut rng);

    // Add the key to a fresh keystore to force it to be registered in the address book. We
    // will not use this keystore again.
    let mut w = t
        .create_keystore(KeyTree::random(&mut rng).0, &ledger)
        .await;
    w.0.add_account(receiver.clone(), "key".into(), EventIndex::default())
        .await
        .unwrap();

    // Mint a viewable asset for each keystore.
    let viewing_key = ViewerKeyPair::generate(&mut rng);
    let freezing_key = FreezerKeyPair::generate(&mut rng);
    let (assets, mints): (Vec<_>, Vec<_>) = join_all(keystores.iter_mut().enumerate().map(
        |(i, (keystore, pub_keys, _tmp_dir))| {
            let viewing_key = viewing_key.pub_key();
            let freezing_key = freezing_key.pub_key();
            async move {
                let asset = keystore
                    .define_asset(
                        format!("asset {}", i),
                        &[],
                        AssetPolicy::default()
                            .set_viewer_pub_key(viewing_key)
                            .set_freezer_pub_key(freezing_key)
                            .reveal_record_opening()
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let (mint_note, mint_info) = keystore
                    .build_mint(
                        Some(&pub_keys[0].address()),
                        1,
                        &asset.code,
                        1u64 << 32,
                        pub_keys[0].clone(),
                    )
                    .await
                    .unwrap();
                let receipt = keystore
                    .submit_cap(mint_note.clone().into(), mint_info.clone())
                    .await
                    .unwrap();
                keystore.await_transaction(&receipt).await.unwrap();
                (
                    keystore.asset(asset.code).await.unwrap(),
                    (mint_note, mint_info),
                )
            }
        },
    ))
    .await
    .into_iter()
    .unzip();

    // Create events by making a number of transfers. We transfer from a number of different
    // keystores so we can easily parallelize the transfers, which speeds things up and allows
    // them all to be included in the same block.
    let transfers = join_all(keystores.iter_mut().zip(&assets).map(
        |((keystore, _, _tmp_dir), asset)| {
            let receiver = receiver.pub_key();
            async move {
                keystore
                    .build_transfer(
                        None,
                        &asset.code(),
                        &[(receiver, 1, false)],
                        1,
                        vec![],
                        None,
                    )
                    .await
                    .unwrap()
            }
        },
    ))
    .await;

    // Let the keystores finish processing events. This keeps the setup keystores' event threads from
    // interfering with the benchmark later on.
    t.sync(&ledger, &keystores).await;

    BenchLedgerScannerTransactions {
        mints,
        transfers,
        receiver,
        assets,
        viewing_key,
        freezing_key,
    }
}

async fn bench_ledger_scanner_setup<T: SystemUnderTest<Ledger = L> + Clone, L: 'static + Ledger>(
    blocks: usize,
    txns_per_block: usize,
    txns: BenchLedgerScannerTransactions<L>,
) -> BenchLedgerScanner<T> {
    let mut t = T::default();
    let mut rng = ChaChaRng::from_seed([0; 32]);
    let mut now = Instant::now();
    let (ledger, mut keystores) = t
        .create_test_network(
            &[(1, 2), (2, 2), (3, 3)],
            vec![1u64 << 32; txns_per_block],
            &mut now,
        )
        .await;
    ledger.lock().await.set_block_size(txns_per_block).unwrap();

    // Add the receiver key to a fresh keystore to force it to be registered in the address
    // book. We will not use this keystore again.
    let mut w = t
        .create_keystore(KeyTree::random(&mut rng).0, &ledger)
        .await;
    w.0.add_account(txns.receiver.clone(), "key".into(), EventIndex::default())
        .await
        .unwrap();

    // Mint a viewable asset for each keystore.
    join_all(keystores.iter_mut().zip(txns.mints).map(
        |((keystore, _, _tmp_dir), (mint_note, mint_info))| async move {
            let receipt = keystore
                .submit_cap(mint_note.into(), mint_info)
                .await
                .unwrap();
            keystore.await_transaction(&receipt).await.unwrap();
        },
    ))
    .await;

    // Wait for the keystores to catch up to the state before we snapshot the `initial_state`
    // keystore.
    t.sync(&ledger, &keystores).await;
    // Snapshot the state from which we want the benchmark keystores to start scanning the ledger.
    // Clear out any existing keys so that when we run the benchmark, we have full control over
    // which keys are in the keystore and whether it can receive, view, or freeze certain assets.
    let initial_state = keystores[0].0.read().await.state();

    // Create events by making a number of transfers. We transfer from a number of different
    // keystores so we can easily parallelize the transfers, which speeds things up and allows
    // them all to be included in the same block.
    let start_time = ledger.lock().await.now();
    for i in 0..blocks {
        join_all(
            keystores
                .iter_mut()
                .zip(&txns.transfers[i * txns_per_block..])
                .map(
                    |((keystore, _, _tmp_dir), (xfr_note, xfr_info))| async move {
                        let receipt = keystore
                            .submit_cap(xfr_note.clone().into(), xfr_info.clone())
                            .await
                            .unwrap();
                        keystore.await_transaction(&receipt).await.unwrap();
                    },
                ),
        )
        .await;
    }
    // Let the keystores finish processing events. This ensures that `end_time` is up-to-date
    // when we snapshot it below, and it keeps the setup keystores' event threads from
    // interfering with the benchmark later on.
    t.sync(&ledger, &keystores).await;
    let end_time = ledger.lock().await.now();

    BenchLedgerScanner {
        t,
        rng,
        ledger,
        receiver: txns.receiver,
        assets: txns.assets,
        viewing_key: txns.viewing_key,
        freezing_key: txns.freezing_key,
        start_time,
        end_time,
        initial_state,
    }
}

fn bench_ledger_scanner_run<T: SystemUnderTest + Clone, M: Measurement<Value = Duration>>(
    mut b: AsyncBencher<'_, '_, AsyncStdExecutor, M>,
    mut bench: BenchLedgerScanner<T>,
    cfg: BenchLedgerScannerConfig,
) {
    let scan_key = if cfg.role == ScannerRole::Receiver {
        bench.receiver.clone()
    } else {
        UserKeyPair::generate(&mut bench.rng)
    };

    let is_viewer = cfg.role == ScannerRole::Viewer;

    if cfg.background {
        // To create a background scan, just add a new key to an existing keystore.
        b.iter_custom(|n| {
            let mut bench = bench.clone();
            let scan_key = scan_key.clone();
            async move {
                let (mut viewing_key, mut freezing_key) = (None, None);
                if is_viewer {
                    viewing_key = Some((bench.viewing_key.clone(), "viewing".into()));
                    freezing_key = Some((bench.freezing_key.clone(), "freezing".into()));
                }
                let mut dur = Duration::default();
                for _ in 0..n {
                    let (mut w, _tmp_dir) = bench
                        .t
                        .create_keystore_with_state_and_keys(
                            KeyTree::random(&mut bench.rng).0,
                            &bench.ledger,
                            bench.initial_state.clone(),
                            viewing_key.clone(),
                            freezing_key.clone(),
                            None,
                        )
                        .await;

                    // Wait for the main event thread to catch up before starting the timer, so that
                    // it is not consuming CPU time and interfering with the benchmark of the
                    // background thread, and so that the background thread has to run all the way
                    // to `sync_time` in order to catch up.
                    w.sync(bench.end_time).await.unwrap();

                    let start = Instant::now();
                    w.add_account(scan_key.clone(), "key".into(), bench.start_time)
                        .await
                        .unwrap();
                    w.await_sending_key_scan(&scan_key.address()).await.unwrap();
                    dur += start.elapsed();

                    // Ensure the wallet gets dropped before `_tmp_dir`.
                    drop(w);
                }
                dur
            }
        })
    } else {
        // Otherwise, create a new keystore and wait for it to scan all the events.
        b.iter_custom(|n| {
            let mut bench = bench.clone();
            let scan_key = scan_key.clone();
            async move {
                let (mut viewing_key, mut freezing_key) = (None, None);
                if is_viewer {
                    viewing_key = Some((bench.viewing_key.clone(), "viewing".into()));
                    freezing_key = Some((bench.freezing_key.clone(), "freezing".into()));
                }
                let mut dur = Duration::default();
                for _ in 0..n {
                    let state = bench.initial_state.clone();
                    let start = Instant::now();
                    // Create the keystore, starting the main event thread.
                    let (w, _tmp_dir) = bench
                        .t
                        .create_keystore_with_state_and_keys(
                            KeyTree::random(&mut bench.rng).0,
                            &bench.ledger,
                            state,
                            viewing_key.clone(),
                            freezing_key.clone(),
                            Some((scan_key.clone(), "key".to_string())),
                        )
                        .await;

                    // Wait for the keystore to scan all the events.
                    w.sync(bench.end_time).await.unwrap();
                    dur += start.elapsed();

                    // Ensure the wallet gets dropped before `_tmp_dir`.
                    drop(w);
                }
                dur
            }
        })
    }
}

pub fn instantiate_generic_keystore_bench<T: SystemUnderTest + Clone>(c: &mut Criterion) {
    // Only generate one block per benchmark. Criterion is optimized for smaller benchmarks, and we
    // only care about scaling/parallelism within a block anyways.
    let blocks = 1;
    let txns_per_block = [1, 5, 10, 25, 50];

    // Pregenerate the maximum number of independent transactions we will ever need. Since they are
    // independent, they can be grouped into blocks and submitted however we want in order to
    // create the various benchmark setups.
    let txns = block_on(generate_independent_transactions::<T, T::Ledger>(
        *txns_per_block.last().unwrap(),
    ));

    // Prepopulate the cache with all the benchmark setups we will need.
    let ledger_cache = txns_per_block
        .iter()
        .map(|&txns_per_block| {
            (
                (blocks, txns_per_block),
                block_on(bench_ledger_scanner_setup(
                    blocks,
                    txns_per_block,
                    txns.clone(),
                )),
            )
        })
        .collect::<HashMap<_, _>>();

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
