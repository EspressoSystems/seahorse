pub use crate::testing::MockLedger;

use crate::{
    events::{EventIndex, EventSource, LedgerEvent},
    hd,
    testing::{MockEventSource, MockNetwork as _},
    txn_builder::{TransactionHistoryEntry, TransactionState},
    CryptoError, RoleKeyPair, WalletBackend, WalletError, WalletState, WalletStorage,
};
use async_std::sync::{Arc, Mutex, MutexGuard};
use async_trait::async_trait;
use futures::stream::Stream;
use itertools::izip;
use jf_aap::{
    keys::{UserAddress, UserPubKey},
    proof::UniversalParam,
    structs::{
        AssetCodeSeed, AssetDefinition, Nullifier, ReceiverMemo, RecordCommitment, RecordOpening,
    },
    MerkleTree, Signature,
};
use key_set::{OrderByOutputs, ProverKeySet, VerifierKeySet};
use lazy_static::lazy_static;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reef::{aap, traits::Ledger as _, traits::Transaction as _, traits::Validator as _};
use snafu::ResultExt;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;

#[derive(Clone, Debug, Default)]
pub struct MockStorage<'a> {
    committed: Option<WalletState<'a, aap::Ledger>>,
    working: Option<WalletState<'a, aap::Ledger>>,
    txn_history: Vec<TransactionHistoryEntry<aap::Ledger>>,
}

#[async_trait]
impl<'a> WalletStorage<'a, aap::Ledger> for MockStorage<'a> {
    fn exists(&self) -> bool {
        self.committed.is_some()
    }

    async fn load(&mut self) -> Result<WalletState<'a, aap::Ledger>, WalletError<aap::Ledger>> {
        Ok(self.committed.as_ref().unwrap().clone())
    }

    async fn store_snapshot(
        &mut self,
        state: &WalletState<'a, aap::Ledger>,
    ) -> Result<(), WalletError<aap::Ledger>> {
        if let Some(working) = &mut self.working {
            working.txn_state = state.txn_state.clone();
            working.key_scans = state.key_scans.clone();
            working.key_state = state.key_state.clone();
        }
        Ok(())
    }

    async fn store_auditable_asset(
        &mut self,
        asset: &AssetDefinition,
    ) -> Result<(), WalletError<aap::Ledger>> {
        if let Some(working) = &mut self.working {
            working.auditable_assets.insert(asset.code, asset.clone());
        }
        Ok(())
    }

    async fn store_key(&mut self, key: &RoleKeyPair) -> Result<(), WalletError<aap::Ledger>> {
        if let Some(working) = &mut self.working {
            match key {
                RoleKeyPair::Auditor(key) => {
                    working.audit_keys.insert(key.pub_key(), key.clone());
                }
                RoleKeyPair::Freezer(key) => {
                    working.freeze_keys.insert(key.pub_key(), key.clone());
                }
                RoleKeyPair::User(key) => {
                    working.user_keys.insert(key.address(), key.clone());
                }
            }
        }
        Ok(())
    }

    async fn store_defined_asset(
        &mut self,
        asset: &AssetDefinition,
        seed: AssetCodeSeed,
        desc: &[u8],
    ) -> Result<(), WalletError<aap::Ledger>> {
        if let Some(working) = &mut self.working {
            working
                .defined_assets
                .insert(asset.code, (asset.clone(), seed, desc.to_vec()));
        }
        Ok(())
    }

    async fn store_transaction(
        &mut self,
        txn: TransactionHistoryEntry<aap::Ledger>,
    ) -> Result<(), WalletError<aap::Ledger>> {
        self.txn_history.push(txn);
        Ok(())
    }

    async fn transaction_history(
        &mut self,
    ) -> Result<Vec<TransactionHistoryEntry<aap::Ledger>>, WalletError<aap::Ledger>> {
        Ok(self.txn_history.clone())
    }

    async fn commit(&mut self) {
        self.committed = self.working.clone();
    }

    async fn revert(&mut self) {
        self.working = self.committed.clone();
    }
}

pub struct MockNetwork<'a> {
    validator: aap::Validator,
    nullifiers: HashSet<Nullifier>,
    records: MerkleTree,
    committed_blocks: Vec<(aap::Block, Vec<Vec<u64>>)>,
    proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,
    address_map: HashMap<UserAddress, UserPubKey>,
    events: MockEventSource<aap::Ledger>,
}

impl<'a> MockNetwork<'a> {
    pub fn new(
        rng: &mut ChaChaRng,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self {
        let mut network = Self {
            validator: aap::Validator {
                now: 0,
                num_records: initial_grants.len() as u64,
            },
            records,
            nullifiers: Default::default(),
            committed_blocks: Vec::new(),
            proving_keys: Arc::new(proof_crs),
            address_map: HashMap::default(),
            events: MockEventSource::new(EventSource::QueryService),
        };

        // Broadcast receiver memos for the records which are included in the tree from the start,
        // so that clients can access records they have been granted at ledger setup time in a
        // uniform way.
        let memo_outputs = initial_grants
            .into_iter()
            .map(|(ro, uid)| {
                let memo = ReceiverMemo::from_ro(rng, &ro, &[]).unwrap();
                let (comm, merkle_path) = network
                    .records
                    .get_leaf(uid)
                    .expect_ok()
                    .map(|(_, proof)| {
                        (
                            RecordCommitment::from_field_element(proof.leaf.0),
                            proof.path,
                        )
                    })
                    .unwrap();
                (memo, comm, uid, merkle_path)
            })
            .collect();
        network.generate_event(LedgerEvent::Memos {
            outputs: memo_outputs,
            transaction: None,
        });

        network
    }
}

impl<'a> super::MockNetwork<'a, aap::Ledger> for MockNetwork<'a> {
    fn now(&self) -> EventIndex {
        self.events.now()
    }

    fn submit(&mut self, block: aap::Block) -> Result<(), WalletError<aap::Ledger>> {
        match self.validator.validate_and_apply(block.clone()) {
            Ok(mut uids) => {
                // Add nullifiers
                for txn in &block {
                    for nullifier in txn.input_nullifiers() {
                        self.nullifiers.insert(nullifier);
                    }
                    for record in txn.output_commitments() {
                        self.records.push(record.to_field_element())
                    }
                }

                // Broadcast the new block
                self.generate_event(LedgerEvent::Commit {
                    block: block.clone(),
                    block_id: self.committed_blocks.len() as u64,
                    state_comm: self.validator.commit(),
                });

                // Store the block in the history
                let mut block_uids = vec![];
                for txn in &block {
                    let mut this_txn_uids = uids;
                    uids = this_txn_uids.split_off(txn.output_len());
                    assert_eq!(this_txn_uids.len(), txn.output_len());
                    block_uids.push(this_txn_uids);
                }
                self.committed_blocks.push((block, block_uids));
            }
            Err(error) => self.generate_event(LedgerEvent::Reject { block, error }),
        }

        Ok(())
    }

    fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError<aap::Ledger>> {
        let (block, block_uids) = &self.committed_blocks[block_id as usize];
        let txn = &block[txn_id as usize];
        let comms = txn.output_commitments();
        let uids = block_uids[txn_id as usize].clone();

        txn.verify_receiver_memos_signature(&memos, &sig)
            .context(CryptoError)?;

        let merkle_paths = uids
            .iter()
            .map(|uid| {
                self.records
                    .get_leaf(*uid)
                    .expect_ok()
                    .map(|(_, proof)| (proof.leaf.0, proof.path))
                    .unwrap()
                    .1
            })
            .collect::<Vec<_>>();
        self.generate_event(LedgerEvent::<aap::Ledger>::Memos {
            outputs: izip!(memos, comms, uids, merkle_paths).collect(),
            transaction: Some((block_id, txn_id)),
        });

        Ok(())
    }

    fn memos_source(&self) -> EventSource {
        EventSource::QueryService
    }

    fn generate_event(&mut self, e: LedgerEvent<aap::Ledger>) {
        println!(
            "generating event {}: {}",
            self.now(),
            match &e {
                LedgerEvent::Commit { .. } => "Commit",
                LedgerEvent::Reject { .. } => "Reject",
                LedgerEvent::Memos { .. } => "Memos",
            },
        );
        self.events.publish(e);
    }
}

#[derive(Clone)]
pub struct MockBackend<'a> {
    storage: Arc<Mutex<MockStorage<'a>>>,
    ledger: Arc<Mutex<MockLedger<'a, aap::Ledger, MockNetwork<'a>, MockStorage<'a>>>>,
    key_stream: hd::KeyTree,
}

impl<'a> MockBackend<'a> {
    pub fn new(
        ledger: Arc<Mutex<MockLedger<'a, aap::Ledger, MockNetwork<'a>, MockStorage<'a>>>>,
        storage: Arc<Mutex<MockStorage<'a>>>,
        key_stream: hd::KeyTree,
    ) -> Self {
        Self {
            ledger,
            storage,
            key_stream,
        }
    }
}

#[async_trait]
impl<'a> WalletBackend<'a, aap::Ledger> for MockBackend<'a> {
    type EventStream = Pin<Box<dyn Stream<Item = (LedgerEvent<aap::Ledger>, EventSource)> + Send>>;
    type Storage = MockStorage<'a>;

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    async fn create(&mut self) -> Result<WalletState<'a, aap::Ledger>, WalletError<aap::Ledger>> {
        let state = {
            let mut ledger = self.ledger.lock().await;
            let network = ledger.network();

            // `records` should be _almost_ completely sparse. However, even a fully pruned Merkle
            // tree contains the last leaf appended, but as a new wallet, we don't care about _any_
            // of the leaves, so make a note to forget the last one once more leaves have been
            // appended.
            let record_mt = network.records.clone();
            let merkle_leaf_to_forget = if record_mt.num_leaves() > 0 {
                Some(record_mt.num_leaves() - 1)
            } else {
                None
            };

            WalletState {
                proving_keys: network.proving_keys.clone(),
                txn_state: TransactionState {
                    validator: network.validator.clone(),

                    records: Default::default(),
                    nullifiers: Default::default(),
                    record_mt,
                    merkle_leaf_to_forget,

                    now: Default::default(),
                    transactions: Default::default(),
                },
                key_state: Default::default(),
                key_scans: Default::default(),
                auditable_assets: Default::default(),
                audit_keys: Default::default(),
                freeze_keys: Default::default(),
                user_keys: Default::default(),
                defined_assets: HashMap::new(),
            }
        };

        // Persist the initial state.
        let mut storage = self.storage().await;
        storage.committed = Some(state.clone());
        storage.working = Some(state.clone());

        Ok(state)
    }

    fn key_stream(&self) -> hd::KeyTree {
        self.key_stream.clone()
    }

    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream {
        let mut ledger = self.ledger.lock().await;
        ledger.network().events.subscribe(from, to)
    }

    async fn get_public_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserPubKey, WalletError<aap::Ledger>> {
        let mut ledger = self.ledger.lock().await;
        match ledger.network().address_map.get(address) {
            Some(key) => Ok(key.clone()),
            None => Err(WalletError::<aap::Ledger>::InvalidAddress {
                address: address.clone(),
            }),
        }
    }

    async fn get_nullifier_proof(
        &self,
        _set: &mut aap::NullifierSet,
        nullifier: Nullifier,
    ) -> Result<(bool, ()), WalletError<aap::Ledger>> {
        let mut ledger = self.ledger.lock().await;
        Ok((ledger.network().nullifiers.contains(&nullifier), ()))
    }

    async fn get_transaction(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<aap::Transaction, WalletError<aap::Ledger>> {
        let mut ledger = self.ledger.lock().await;
        let network = ledger.network();
        let block = &network
            .committed_blocks
            .get(block_id as usize)
            .ok_or_else(|| WalletError::<aap::Ledger>::Failed {
                msg: format!(
                    "invalid block id {}/{}",
                    block_id,
                    network.committed_blocks.len()
                ),
            })?
            .0;

        if txn_id as usize >= block.len() {
            return Err(WalletError::<aap::Ledger>::Failed {
                msg: format!(
                    "invalid transaction id {}/{} for block {}",
                    txn_id,
                    block.len(),
                    block_id
                ),
            });
        }
        Ok(block[txn_id as usize].clone())
    }

    async fn register_user_key(
        &mut self,
        pub_key: &UserPubKey,
    ) -> Result<(), WalletError<aap::Ledger>> {
        let mut ledger = self.ledger.lock().await;
        ledger
            .network()
            .address_map
            .insert(pub_key.address(), pub_key.clone());
        Ok(())
    }

    async fn submit(&mut self, txn: aap::Transaction) -> Result<(), WalletError<aap::Ledger>> {
        self.ledger.lock().await.submit(txn)
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError<aap::Ledger>> {
        self.ledger
            .lock()
            .await
            .post_memos(block_id, txn_id, memos, sig)
    }
}

#[derive(Default)]
pub struct MockSystem;

#[async_trait]
impl<'a> super::SystemUnderTest<'a> for MockSystem {
    type Ledger = aap::Ledger;
    type MockBackend = MockBackend<'a>;
    type MockNetwork = MockNetwork<'a>;
    type MockStorage = MockStorage<'a>;

    async fn create_network(
        &mut self,
        _verif_crs: VerifierKeySet,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockNetwork {
        let mut rng = ChaChaRng::from_seed([42u8; 32]);
        MockNetwork::new(&mut rng, proof_crs, records, initial_grants)
    }

    async fn create_storage(&mut self) -> Self::MockStorage {
        Default::default()
    }

    async fn create_backend(
        &mut self,
        ledger: Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork, Self::MockStorage>>>,
        _initial_grants: Vec<(RecordOpening, u64)>,
        key_stream: hd::KeyTree,
        storage: Arc<Mutex<Self::MockStorage>>,
    ) -> Self::MockBackend {
        MockBackend::new(ledger, storage, key_stream)
    }

    fn universal_param(&self) -> &'a UniversalParam {
        &*UNIVERSAL_PARAM
    }
}

lazy_static! {
    static ref UNIVERSAL_PARAM: UniversalParam = universal_param::get(
        &mut ChaChaRng::from_seed([1u8; 32]),
        aap::Ledger::merkle_height()
    );
}

#[cfg(test)]
mod tests {
    use super::super::generic_wallet_tests;
    instantiate_generic_wallet_tests!(super::MockSystem);
}
