// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

#![allow(dead_code)]

/// This module contains testing utilities and unit tests for the generic keystore interface.
///
/// This file defines a framework for testing the generic keystore with any mock backend, for any
/// ledger. Implementations of this test interface for various backends and ledgers are in
/// sub-modules in different files (e.g. spectrum_test.rs, cape_test.rs). These files also contain
/// tests which are specific to keystores with a particular ledger type or backend, which depend on
/// properties not exposed or guaranteed by the generic interface. The file tests.rs contains the
/// test suite for the generic keystore interface, which is instantiated for each ledger/backend.
use super::*;
use async_std::sync::{Arc, Mutex};
use chrono::Local;
use futures::{channel::mpsc, stream::iter};
use hd::KeyTree;
use jf_cap::{MerkleTree, Signature, TransactionVerifyingKey};
use key_set::{KeySet, OrderByOutputs, ProverKeySet, VerifierKeySet};
use rand_chacha::rand_core::RngCore;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Instant;
use tempdir::TempDir;

// Loader for using in tests.  Just creates unit metadata and defualt Keytree.
pub struct TrivialKeystoreLoader {
    pub dir: PathBuf,
    pub key_tree: KeyTree,
}

impl<L: Ledger> KeystoreLoader<L> for TrivialKeystoreLoader {
    type Meta = ();

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<((), KeyTree), KeystoreError<L>> {
        Ok(((), self.key_tree.clone()))
    }

    fn load(&mut self, _meta: &mut ()) -> Result<KeyTree, KeystoreError<L>> {
        Ok(self.key_tree.clone())
    }
}

#[async_trait]
pub trait MockNetwork<'a, L: Ledger> {
    fn now(&self) -> EventIndex;
    fn submit(&mut self, block: Block<L>) -> Result<(), KeystoreError<L>>;
    fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), KeystoreError<L>>;
    fn memos_source(&self) -> EventSource;
    fn generate_event(&mut self, event: LedgerEvent<L>);
    fn event(
        &self,
        index: EventIndex,
        source: EventSource,
    ) -> Result<LedgerEvent<L>, KeystoreError<L>>;
}

pub struct MockLedger<'a, L: Ledger, N: MockNetwork<'a, L>> {
    network: N,
    current_block: Block<L>,
    block_size: usize,
    hold_next_transaction: bool,
    held_transaction: Option<reef::Transaction<L>>,
    mangled: bool,
    missing_memos: usize,
    sync_index: EventIndex,
    initial_records: MerkleTree,
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a, L: Ledger, N: MockNetwork<'a, L>> MockLedger<'a, L, N> {
    pub fn new(network: N, records: MerkleTree) -> Self {
        Self {
            network,
            current_block: Block::<L>::new(vec![]),
            block_size: 2,
            hold_next_transaction: false,
            held_transaction: None,
            mangled: false,
            missing_memos: 0,
            sync_index: Default::default(),
            initial_records: records,
            _phantom: Default::default(),
        }
    }

    pub fn network(&mut self) -> &mut N {
        &mut self.network
    }

    pub fn now(&self) -> EventIndex {
        self.network.now()
    }

    pub fn flush(&mut self) -> Result<(), KeystoreError<L>> {
        if self.current_block.is_empty() {
            return Ok(());
        }

        let block = std::mem::replace(&mut self.current_block, Block::<L>::new(vec![]));
        let block_size = block.len();
        self.network.submit(block)?;
        self.missing_memos += block_size;
        Ok(())
    }

    pub fn hold_next_transaction(&mut self) {
        self.hold_next_transaction = true;
    }

    pub fn release_held_transaction(&mut self) -> Option<reef::Transaction<L>> {
        if let Some(txn) = self.held_transaction.take() {
            self.submit(txn.clone()).unwrap();
            Some(txn)
        } else {
            None
        }
    }

    pub fn mangle(&mut self) {
        self.mangled = true;
    }

    pub fn unmangle(&mut self) {
        self.mangled = false;
    }

    pub fn submit(&mut self, txn: reef::Transaction<L>) -> Result<(), KeystoreError<L>> {
        if self.hold_next_transaction {
            self.held_transaction = Some(txn);
            self.hold_next_transaction = false;
        } else if self.mangled {
            let rejected = Block::<L>::new(vec![txn]);
            self.network.generate_event(LedgerEvent::<L>::Reject {
                block: rejected,
                error: ValidationError::<L>::new("block rejected because mock ledger is mangled"),
            });
        } else {
            match self.current_block.add_transaction(txn.clone()) {
                Ok(()) => {
                    if self.current_block.len() >= self.block_size {
                        self.flush()?;
                    }
                }
                Err(error) => {
                    let rejected = Block::<L>::new(vec![txn]);
                    self.network.generate_event(LedgerEvent::<L>::Reject {
                        block: rejected,
                        error,
                    });
                }
            }
        }

        Ok(())
    }

    pub fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), KeystoreError<L>> {
        self.network.post_memos(block_id, txn_id, memos, sig)?;
        Ok(())
    }

    pub fn set_block_size(&mut self, size: usize) -> Result<(), KeystoreError<L>> {
        self.block_size = size;
        if self.current_block.len() >= self.block_size {
            self.flush()?;
        }
        Ok(())
    }

    pub fn get_initial_scan_state(&self) -> Result<(MerkleTree, EventIndex), KeystoreError<L>> {
        Ok((self.initial_records.clone(), EventIndex::default()))
    }
}

// This function checks probabilistic equality for two keystore states, comparing hashes for fields
// that cannot directly be compared for equality. It is sufficient for tests that want to compare
// keystore states (like round-trip serialization tests) but since it is deterministic, we shouldn't
// make it into a PartialEq instance.
pub fn assert_keystore_states_eq<'a, L: Ledger>(
    w1: &KeystoreState<'a, L>,
    w2: &KeystoreState<'a, L>,
) {
    assert_eq!(w1.txn_state.now, w2.txn_state.now);
    assert_eq!(
        w1.txn_state.validator.commit(),
        w2.txn_state.validator.commit()
    );
    assert_eq!(w1.proving_keys, w2.proving_keys);
    assert_eq!(w1.txn_state.records, w2.txn_state.records);
    assert_eq!(w1.key_state, w2.key_state);
    assert_eq!(w1.txn_state.nullifiers, w2.txn_state.nullifiers);
    assert_eq!(
        w1.txn_state.record_mt.commitment(),
        w2.txn_state.record_mt.commitment()
    );
}

#[async_trait]
pub trait SystemUnderTest<'a>: Default + Send + Sync {
    type Ledger: 'static + Ledger;
    type MockBackend: 'a + KeystoreBackend<'a, Self::Ledger> + Send + Sync;
    type MockNetwork: 'a + MockNetwork<'a, Self::Ledger> + Send;

    async fn create_backend(
        &mut self,
        ledger: Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork>>>,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockBackend;
    async fn create_network(
        &mut self,
        verif_crs: VerifierKeySet,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockNetwork;

    async fn create_keystore(
        &mut self,
        key_tree: KeyTree,
        ledger: &Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork>>>,
    ) -> (Keystore<'a, Self::MockBackend, Self::Ledger, ()>, TempDir) {
        let temp_dir = TempDir::new("test_keystore").unwrap();
        let mut loader = TrivialKeystoreLoader {
            dir: temp_dir.path().to_path_buf(),
            key_tree: key_tree.clone(),
        };
        let backend = self.create_backend(ledger.clone(), vec![]).await;
        (Keystore::new(backend, &mut loader).await.unwrap(), temp_dir)
    }

    async fn create_keystore_with_state(
        &mut self,
        key_tree: KeyTree,
        ledger: &Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork>>>,
        state: KeystoreState<'a, Self::Ledger>,
    ) -> (Keystore<'a, Self::MockBackend, Self::Ledger, ()>, TempDir) {
        let temp_dir = TempDir::new("test_keystore").unwrap();
        let mut loader = TrivialKeystoreLoader {
            dir: temp_dir.path().to_path_buf(),
            key_tree: key_tree.clone(),
        };
        let backend = self.create_backend(ledger.clone(), vec![]).await;
        (
            Keystore::with_state(backend, &mut loader, state)
                .await
                .unwrap(),
            temp_dir,
        )
    }

    /// Creates two key pairs for each keystore.
    ///
    /// `initial_grants` - List of total initial grants for each keystore. Each amount will be
    /// divided by 2, and any remainder will be added to the second public key.
    async fn create_test_network(
        &mut self,
        xfr_sizes: &[(usize, usize)],
        initial_grants: Vec<u64>,
        now: &mut Instant,
    ) -> (
        Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork>>>,
        Vec<(
            Keystore<'a, Self::MockBackend, Self::Ledger, ()>,
            Vec<UserPubKey>,
            TempDir,
        )>,
    ) {
        let mut rng = ChaChaRng::from_seed([42u8; 32]);
        let universal_param = Self::Ledger::srs();

        // Populate the unpruned record merkle tree with an initial record commitment for each
        // non-zero initial grant. Collect user-specific info (keys and record openings
        // corresponding to grants) in `users`, which will be used to create the keystores later.
        let mut record_merkle_tree = MerkleTree::new(Self::Ledger::merkle_height()).unwrap();
        let mut users = vec![];
        let mut initial_records = vec![];
        for total_amount in initial_grants {
            let (key, mnemonic) = hd::KeyTree::random(&mut rng);
            let key_stream = key.derive_sub_tree("keystore".as_bytes());
            let keys_for_keystore = hd::KeyTree::from_mnemonic(&mnemonic);
            let sub_tree = key_stream.derive_sub_tree("user".as_bytes());
            let keys_amounts = vec![
                (
                    sub_tree.derive_user_key_pair(&0u64.to_le_bytes()),
                    total_amount / 2,
                ),
                (
                    sub_tree.derive_user_key_pair(&1u64.to_le_bytes()),
                    total_amount - total_amount / 2,
                ),
            ];
            let keys = keys_amounts
                .clone()
                .into_iter()
                .map(|(key, _)| key)
                .collect::<Vec<UserKeyPair>>();
            let mut records = vec![];
            if total_amount > 0 {
                for (key, amount) in keys_amounts {
                    if amount > 0 {
                        let ro = RecordOpening::new(
                            &mut rng,
                            amount.into(),
                            AssetDefinition::native(),
                            key.pub_key(),
                            FreezeFlag::Unfrozen,
                        );
                        let comm = RecordCommitment::from(&ro);
                        let uid = record_merkle_tree.num_leaves();
                        record_merkle_tree.push(comm.to_field_element());
                        records.push((ro.clone(), uid));
                        initial_records.push((ro, uid));
                    }
                }
            }
            users.push((keys_for_keystore, keys, records));
        }

        // Create the validator using the ledger state containing the initial grants, computed
        // above.
        println!(
            "Generating validator keys: {}s",
            now.elapsed().as_secs_f32()
        );
        *now = Instant::now();

        let mut xfr_prove_keys = vec![];
        let mut xfr_verif_keys = vec![];
        for (num_inputs, num_outputs) in xfr_sizes {
            let (xfr_prove_key, xfr_verif_key, _) = jf_cap::proof::transfer::preprocess(
                universal_param,
                *num_inputs,
                *num_outputs,
                Self::Ledger::merkle_height(),
            )
            .unwrap();
            xfr_prove_keys.push(xfr_prove_key);
            xfr_verif_keys.push(TransactionVerifyingKey::Transfer(xfr_verif_key));
        }
        let (mint_prove_key, mint_verif_key, _) =
            jf_cap::proof::mint::preprocess(universal_param, Self::Ledger::merkle_height())
                .unwrap();
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_cap::proof::freeze::preprocess(universal_param, 2, Self::Ledger::merkle_height())
                .unwrap();
        let prover_key_set = ProverKeySet {
            xfr: KeySet::new(xfr_prove_keys.into_iter()).unwrap(),
            mint: mint_prove_key,
            freeze: KeySet::new(vec![freeze_prove_key].into_iter()).unwrap(),
        };

        let ledger = Arc::new(Mutex::new(MockLedger::new(
            self.create_network(
                VerifierKeySet {
                    xfr: KeySet::new(xfr_verif_keys.into_iter()).unwrap(),
                    mint: TransactionVerifyingKey::Mint(mint_verif_key),
                    freeze: KeySet::new(
                        vec![TransactionVerifyingKey::Freeze(freeze_verif_key)].into_iter(),
                    )
                    .unwrap(),
                },
                prover_key_set.clone(),
                record_merkle_tree.clone(),
                initial_records,
            )
            .await,
            record_merkle_tree.clone(),
        )));

        // Create a keystore for each user based on the validator and the per-user information
        // computed above.
        let mut keystores = Vec::new();
        for (key_stream, key_pairs, initial_grants) in users {
            let tmp_dir = TempDir::new("test_keystore").unwrap();
            let mut loader = TrivialKeystoreLoader {
                dir: tmp_dir.path().to_path_buf(),
                key_tree: key_stream,
            };
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let mut keystore = Keystore::new(
                self.create_backend(ledger.clone(), initial_grants).await,
                &mut loader,
            )
            .await
            .unwrap();
            let mut pub_keys = vec![];
            for key_pair in key_pairs.clone() {
                assert_eq!(
                    keystore
                        .generate_sending_account("".into(), Some(EventIndex::default()))
                        .await
                        .unwrap(),
                    key_pair.pub_key()
                );

                // Wait for the keystore to find any records already belonging to this key from the
                // initial grants.

                keystore.await_key_scan(&key_pair.address()).await.unwrap();
                pub_keys.push(key_pair.pub_key());
            }
            keystores.push((keystore, pub_keys, tmp_dir));
        }

        println!("Keystores set up: {}s", now.elapsed().as_secs_f32());
        *now = Instant::now();

        // Sync with any events that were emitted during ledger setup.
        self.sync(&ledger, &keystores).await;
        (ledger, keystores)
    }

    async fn sync(
        &self,
        ledger: &Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork>>>,
        keystores: &[(
            Keystore<'a, Self::MockBackend, Self::Ledger, ()>,
            Vec<UserPubKey>,
            TempDir,
        )],
    ) {
        let memos_source = {
            let mut ledger = ledger.lock().await;
            ledger.flush().unwrap();
            ledger.network.memos_source()
        };

        // Scan events starting from the last processed event (`ledger.sync_index`) until we have
        // found all of the memos corresponding to the transactions that we are syncing with.
        loop {
            // Advance the current event index by the number of missing memos and sync with that
            // index.
            let t = {
                let ledger = ledger.lock().await;
                if ledger.missing_memos == 0 {
                    // If there are no missing memos, we're done.
                    break;
                }
                ledger.sync_index + EventIndex::from_source(memos_source, ledger.missing_memos)
            };
            self.sync_with(keystores, t).await;

            // Count how many memos events we got while incrementing `sync_index`. Note that even
            // though we waited for `missing_memos` events from the memos event source, we may have
            // actually gotten fewer than `missing_memos` Memos events, because the memos event
            // source is not guaranteed to be distinct from other event sources.
            let mut ledger = ledger.lock().await;
            for _ in 0..ledger.missing_memos {
                if matches!(
                    ledger
                        .network
                        .event(ledger.sync_index, memos_source)
                        .unwrap(),
                    LedgerEvent::Memos { .. }
                ) {
                    ledger.missing_memos -= 1;
                }
                ledger.sync_index += EventIndex::from_source(memos_source, 1);
            }
        }

        // Sync with the current time.
        let t = {
            let mut ledger = ledger.lock().await;
            ledger.sync_index = ledger.now();
            ledger.sync_index
        };
        self.sync_with(keystores, t).await;

        // Since we're syncing with the time stamp from the most recent event, the keystores should
        // be in a stable state once they have processed up to that event. Check that each keystore
        // has persisted all of its in-memory state at this point.
        self.check_storage(keystores).await;
    }

    async fn sync_with(
        &self,
        keystores: &[(
            Keystore<'a, Self::MockBackend, Self::Ledger, ()>,
            Vec<UserPubKey>,
            TempDir,
        )],
        t: EventIndex,
    ) {
        println!("waiting for sync point {}", t);
        future::join_all(keystores.iter().map(|(keystore, _, _)| keystore.sync(t))).await;
    }

    async fn check_storage(
        &self,
        keystores: &[(
            Keystore<'a, Self::MockBackend, Self::Ledger, ()>,
            Vec<UserPubKey>,
            TempDir,
        )],
    ) {
        for (keystore, _, _) in keystores {
            let KeystoreSharedState { state, model, .. } = &*keystore.mutex.read().await;
            let persistence = &model.persistence;
            let state = state.clone();
            let loaded = persistence.load().await.unwrap();
            assert_keystore_states_eq(&state, &loaded);
        }
    }
}

type EventSender<L> = mpsc::UnboundedSender<(LedgerEvent<L>, EventSource)>;

// Useful helper type for developing mock networks.
#[derive(Clone)]
pub struct MockEventSource<L: Ledger> {
    source: EventSource,
    events: Vec<LedgerEvent<L>>,
    subscribers: Vec<EventSender<L>>,
    // Clients which have subscribed to events starting at some time in the future, to be added to
    // `subscribers` when the time comes.
    pending_subscribers: BTreeMap<usize, Vec<EventSender<L>>>,
}

impl<L: Ledger + 'static> MockEventSource<L> {
    pub fn new(source_type: EventSource) -> Self {
        Self {
            source: source_type,
            events: Default::default(),
            subscribers: Default::default(),
            pending_subscribers: Default::default(),
        }
    }

    pub fn now(&self) -> EventIndex {
        EventIndex::from_source(self.source, self.events.len())
    }

    pub fn subscribe(
        &mut self,
        from: EventIndex,
        to: Option<EventIndex>,
    ) -> Pin<Box<dyn Stream<Item = (LedgerEvent<L>, EventSource)> + Send>> {
        let from = from.index(self.source);
        let to = to.map(|to| to.index(self.source));

        if from < self.events.len() {
            // If the start time is in the past, send the subscriber all saved events since the
            // start time and make them an active subscriber starting now.
            let past_events = self
                .events
                .iter()
                .skip(from)
                .cloned()
                .map(|event| (event, self.source))
                .collect::<Vec<_>>();

            if let Some(to) = to {
                if to - from <= past_events.len() {
                    // If the subscription ends before the current time, just send them the past
                    // events they requested and don't create a new channel.
                    return Box::pin(iter(past_events.into_iter().take(to - from)));
                }
            }

            let (sender, receiver) = mpsc::unbounded();
            self.subscribers.push(sender);
            let subscription: Pin<Box<dyn Stream<Item = _> + Send>> = if let Some(to) = to {
                Box::pin(receiver.take(to - from - past_events.len()))
            } else {
                Box::pin(receiver)
            };

            Box::pin(iter(past_events).chain(subscription))
        } else {
            // Otherwise, add the subscriber to the list of pending subscribers to start receiving
            // events at time `from`.
            let (sender, receiver) = mpsc::unbounded();
            self.pending_subscribers
                .entry(from)
                .or_default()
                .push(sender);
            if let Some(to) = to {
                Box::pin(receiver.take(to - from))
            } else {
                Box::pin(receiver)
            }
        }
    }

    pub fn publish(&mut self, event: LedgerEvent<L>) {
        // Subscribers who asked for a subscription starting from the current time can now be added
        // to the list of active subscribers.
        let now = self.events.len();
        if let Some(new_subscribers) = self.pending_subscribers.remove(&now) {
            self.subscribers.extend(new_subscribers);
        }

        // Send the message to all active subscribers. Filter out subscribers where the send fails,
        // which means that the client has disconnected.
        self.subscribers = std::mem::take(&mut self.subscribers)
            .into_iter()
            .filter(|s| s.unbounded_send((event.clone(), self.source)).is_ok())
            .collect();

        // Save the event so we can feed it to later subscribers who want to start from some time in
        // the past.
        self.events.push(event);
    }

    pub fn get(&self, index: EventIndex) -> Result<LedgerEvent<L>, KeystoreError<L>> {
        self.events
            .get(index.index(self.source))
            .cloned()
            .ok_or_else(|| KeystoreError::Failed {
                msg: String::from("invalid event index"),
            })
    }
}

/// Wait for the transaction involving `sender` and `receivers` to be processed.
///
/// `Keystore::await_transaction` is not perfect in determining when a receiver has finished
/// processing a transaction which was generated by a different keystore. This is due to limitations
/// in uniquely identifying a transaction in a way that is consistent across keystores and services.
/// This should not matter too much in the real world, since transactions are expected to be
/// asynchronous, but it is problematic in automated tests.
///
/// This function can be used in a test involving multiple to synchronize all keystores involved in a
/// transaction to a point in time after that transaction has been processed. It uses
/// `await_transaction` (which is reliable in the sending keystore) to wait until the sender has
/// processed the transaction. It then uses `sync_with_peer` to wait until each receiver has
/// processed at least as many events as the sender (which, after `await_transaction`, will include
/// the events relating to this transaction).
pub async fn await_transaction<
    'a,
    L: Ledger + 'static,
    Backend: KeystoreBackend<'a, L> + Sync + 'a,
    Meta: 'a + Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq,
>(
    receipt: &TransactionUID<L>,
    sender: &Keystore<'a, Backend, L, Meta>,
    receivers: &[&Keystore<'a, Backend, L, Meta>],
) {
    assert_eq!(
        sender.await_transaction(receipt).await.unwrap(),
        TransactionStatus::Retired
    );
    for receiver in receivers {
        receiver.sync_with_peer(sender).await.unwrap();
    }
}

/// A generic test suite which can be used with any backend implementation.
///
/// To use, first implement [SystemUnderTest] for your backend/network. Then, instantiate the
/// generic tests using the [instantiate_generic_keystore_tests] macro, like so
/// ```
/// #[cfg(test)]
/// mod test {
///     # type MyMockSystemImpl = seahorse::testing::mocks::MockSystem;
///     use seahorse::testing::{generic_keystore_tests, instantiate_generic_keystore_tests};
///     instantiate_generic_keystore_tests!(MyMockSystemImpl);
/// }
/// ```
#[macro_use]
pub mod tests;
pub use tests::generic_keystore_tests;

/// Generic benchmarks which can be used with any backend implementation.
///
/// To use, first implement [SystemUnderTest] for your backend/network. Then, add a benchmark to
/// your project by adding to Cargo.toml:
/// ```toml
/// [dev-dependencies]
/// criterion = "0.3"
///
/// [[bench]]
/// name = "seahorse-generic"
/// harness = false
/// ```
///
/// and create the file `benches/seahorse-generic.rs` with the contents (replacing
/// `MyMockSystemImpl` with your implementation of [SystemUnderTest]):
/// ```
/// use criterion::{criterion_group, criterion_main, Criterion};
/// use seahorse::testing::instantiate_generic_keystore_bench;
/// # type MyMockSystemImpl = seahorse::testing::mocks::MockSystem;
///
/// pub fn seahorse_generic(c: &mut Criterion) {
///     instantiate_generic_keystore_bench::<MyMockSystemImpl>(c)
/// }
///
/// criterion_group!(benches, seahorse_generic);
/// criterion_main!(benches);
/// ```
///
/// You can then run the benchmarks using `cargo bench --features testing`. You may also consider
/// setting `RUSTFLAGS='-Ctarget-cpu=native'` before running the benchmarks. This can result in a
/// performance improvement around 7-10%.
pub mod bench;
pub use bench::instantiate_generic_keystore_bench;

pub mod cli_match;
pub mod mocks;
