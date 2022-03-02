pub use crate::testing::MockLedger;

use super::UNIVERSAL_PARAM;
use crate::{
    asset_library::AssetInfo,
    events::{EventIndex, EventSource, LedgerEvent},
    hd,
    testing::{MockEventSource, MockNetwork as _},
    txn_builder::{TransactionHistoryEntry, TransactionState, TransactionUID},
    CryptoError, RoleKeyPair, WalletBackend, WalletError, WalletState, WalletStorage,
};
use async_std::sync::{Arc, Mutex, MutexGuard};
use async_trait::async_trait;
use futures::stream::Stream;
use itertools::izip;
use jf_cap::{
    keys::{UserAddress, UserKeyPair, UserPubKey},
    proof::UniversalParam,
    structs::{Nullifier, ReceiverMemo, RecordCommitment, RecordOpening},
    MerkleTree, Signature,
};
use key_set::{OrderByOutputs, ProverKeySet, VerifierKeySet};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reef::{cap, traits::Transaction as _, traits::Validator as _};
use snafu::ResultExt;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;

#[derive(Clone, Debug, Default)]
pub struct MockStorage<'a> {
    committed: Option<WalletState<'a, cap::Ledger>>,
    working: Option<WalletState<'a, cap::Ledger>>,
    txn_history: Vec<TransactionHistoryEntry<cap::Ledger>>,
}

#[async_trait]
impl<'a> WalletStorage<'a, cap::Ledger> for MockStorage<'a> {
    fn exists(&self) -> bool {
        self.committed.is_some()
    }

    async fn load(&mut self) -> Result<WalletState<'a, cap::Ledger>, WalletError<cap::Ledger>> {
        Ok(self.committed.as_ref().unwrap().clone())
    }

    async fn store_snapshot(
        &mut self,
        state: &WalletState<'a, cap::Ledger>,
    ) -> Result<(), WalletError<cap::Ledger>> {
        if let Some(working) = &mut self.working {
            working.txn_state = state.txn_state.clone();
            working.key_scans = state.key_scans.clone();
            working.key_state = state.key_state.clone();
        }
        Ok(())
    }

    async fn store_asset(&mut self, asset: &AssetInfo) -> Result<(), WalletError<cap::Ledger>> {
        if let Some(working) = &mut self.working {
            working.assets.insert(asset.clone());
        }
        Ok(())
    }

    async fn store_key(&mut self, key: &RoleKeyPair) -> Result<(), WalletError<cap::Ledger>> {
        if let Some(working) = &mut self.working {
            match key {
                RoleKeyPair::Auditor(key) => {
                    working.audit_keys.insert(key.pub_key(), key.clone());
                    working.assets.add_audit_key(key.pub_key());
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

    async fn store_transaction(
        &mut self,
        txn: TransactionHistoryEntry<cap::Ledger>,
    ) -> Result<(), WalletError<cap::Ledger>> {
        self.txn_history.push(txn);
        Ok(())
    }

    async fn transaction_history(
        &mut self,
    ) -> Result<Vec<TransactionHistoryEntry<cap::Ledger>>, WalletError<cap::Ledger>> {
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
    validator: cap::Validator,
    nullifiers: HashSet<Nullifier>,
    records: MerkleTree,
    committed_blocks: Vec<(cap::Block, Vec<Vec<u64>>)>,
    proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,
    address_map: HashMap<UserAddress, UserPubKey>,
    events: MockEventSource<cap::Ledger>,
}

impl<'a> MockNetwork<'a> {
    pub fn new(
        rng: &mut ChaChaRng,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self {
        let mut network = Self {
            validator: cap::Validator {
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

impl<'a> super::MockNetwork<'a, cap::Ledger> for MockNetwork<'a> {
    fn now(&self) -> EventIndex {
        self.events.now()
    }

    fn submit(&mut self, block: cap::Block) -> Result<(), WalletError<cap::Ledger>> {
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
    ) -> Result<(), WalletError<cap::Ledger>> {
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
        self.generate_event(LedgerEvent::<cap::Ledger>::Memos {
            outputs: izip!(memos, comms, uids, merkle_paths).collect(),
            transaction: Some((block_id, txn_id)),
        });

        Ok(())
    }

    fn memos_source(&self) -> EventSource {
        EventSource::QueryService
    }

    fn generate_event(&mut self, e: LedgerEvent<cap::Ledger>) {
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

    fn event(
        &self,
        index: EventIndex,
        source: EventSource,
    ) -> Result<LedgerEvent<cap::Ledger>, WalletError<cap::Ledger>> {
        if source == EventSource::QueryService {
            self.events.get(index)
        } else {
            Err(WalletError::Failed {
                msg: String::from("invalid event source"),
            })
        }
    }
}

#[derive(Clone)]
pub struct MockBackend<'a> {
    storage: Arc<Mutex<MockStorage<'a>>>,
    ledger: Arc<Mutex<MockLedger<'a, cap::Ledger, MockNetwork<'a>, MockStorage<'a>>>>,
    key_stream: hd::KeyTree,
    pending_memos: HashMap<TransactionUID<cap::Ledger>, (Vec<ReceiverMemo>, Signature)>,
}

impl<'a> MockBackend<'a> {
    pub fn new(
        ledger: Arc<Mutex<MockLedger<'a, cap::Ledger, MockNetwork<'a>, MockStorage<'a>>>>,
        storage: Arc<Mutex<MockStorage<'a>>>,
        key_stream: hd::KeyTree,
    ) -> MockBackend<'a> {
        Self {
            ledger,
            storage,
            key_stream,
            pending_memos: Default::default(),
        }
    }
}

#[async_trait]
impl<'a> WalletBackend<'a, cap::Ledger> for MockBackend<'a> {
    type EventStream = Pin<Box<dyn Stream<Item = (LedgerEvent<cap::Ledger>, EventSource)> + Send>>;
    type Storage = MockStorage<'a>;

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    async fn create(&mut self) -> Result<WalletState<'a, cap::Ledger>, WalletError<cap::Ledger>> {
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

                    now: network.now(),
                    transactions: Default::default(),
                },
                key_state: Default::default(),
                key_scans: Default::default(),
                assets: Default::default(),
                audit_keys: Default::default(),
                freeze_keys: Default::default(),
                user_keys: Default::default(),
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
    ) -> Result<UserPubKey, WalletError<cap::Ledger>> {
        let mut ledger = self.ledger.lock().await;
        match ledger.network().address_map.get(address) {
            Some(key) => Ok(key.clone()),
            None => Err(WalletError::<cap::Ledger>::InvalidAddress {
                address: address.clone(),
            }),
        }
    }

    async fn get_nullifier_proof(
        &self,
        _set: &mut cap::NullifierSet,
        nullifier: Nullifier,
    ) -> Result<(bool, ()), WalletError<cap::Ledger>> {
        let mut ledger = self.ledger.lock().await;
        Ok((ledger.network().nullifiers.contains(&nullifier), ()))
    }

    async fn get_transaction(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<cap::Transaction, WalletError<cap::Ledger>> {
        let mut ledger = self.ledger.lock().await;
        let network = ledger.network();
        let block = &network
            .committed_blocks
            .get(block_id as usize)
            .ok_or_else(|| WalletError::<cap::Ledger>::Failed {
                msg: format!(
                    "invalid block id {}/{}",
                    block_id,
                    network.committed_blocks.len()
                ),
            })?
            .0;

        if txn_id as usize >= block.len() {
            return Err(WalletError::<cap::Ledger>::Failed {
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
        key_pair: &UserKeyPair,
    ) -> Result<(), WalletError<cap::Ledger>> {
        let pub_key = key_pair.pub_key();
        let mut ledger = self.ledger.lock().await;
        ledger
            .network()
            .address_map
            .insert(pub_key.address(), pub_key.clone());
        Ok(())
    }

    async fn submit(
        &mut self,
        txn: cap::Transaction,
        uid: TransactionUID<cap::Ledger>,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError<cap::Ledger>> {
        match self.ledger.lock().await.submit(txn) {
            Ok(()) => {
                self.pending_memos.insert(uid, (memos, sig));
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn finalize(&mut self, uid: TransactionUID<cap::Ledger>, txn_id: Option<(u64, u64)>) {
        let (memos, sig) = self.pending_memos.remove(&uid).unwrap();
        if let Some((block_id, txn_id)) = txn_id {
            self.ledger
                .lock()
                .await
                .post_memos(block_id, txn_id, memos, sig)
                .unwrap();
        }
    }
}

#[derive(Default)]
pub struct MockSystem;

#[async_trait]
impl<'a> super::SystemUnderTest<'a> for MockSystem {
    type Ledger = cap::Ledger;
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

#[cfg(test)]
mod tests {
    use super::super::generic_wallet_tests;
    instantiate_generic_wallet_tests!(super::MockSystem);
}
