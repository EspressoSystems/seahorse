// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

pub use crate::testing::MockLedger;

use crate::{
    events::{EventIndex, EventSource, LedgerEvent},
    sparse_merkle_tree::SparseMerkleTree,
    testing::{MockEventSource, MockNetwork as _},
    transactions::Transaction,
    txn_builder::TransactionState,
    CryptoSnafu, KeystoreBackend, KeystoreError, KeystoreState,
};
use async_std::sync::{Arc, Mutex};
use async_trait::async_trait;
use futures::stream::Stream;
use itertools::izip;
use jf_cap::{
    keys::{UserAddress, UserKeyPair, UserPubKey},
    structs::{Nullifier, ReceiverMemo, RecordCommitment, RecordOpening},
    MerkleTree, Signature,
};
use key_set::{OrderByOutputs, ProverKeySet, VerifierKeySet};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reef::{
    cap,
    traits::{Transaction as _, Validator as _},
};
use snafu::ResultExt;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;

pub struct MockNetworkWithHeight<'a, const H: u8> {
    validator: cap::Validator,
    nullifiers: HashSet<Nullifier>,
    records: MerkleTree,
    committed_blocks: Vec<(cap::Block, Vec<Vec<u64>>)>,
    proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,
    pub address_map: HashMap<UserAddress, UserPubKey>,
    events: MockEventSource<cap::LedgerWithHeight<H>>,
}

impl<'a, const H: u8> MockNetworkWithHeight<'a, H> {
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

impl<'a, const H: u8> super::MockNetwork<'a, cap::LedgerWithHeight<H>>
    for MockNetworkWithHeight<'a, H>
{
    fn now(&self) -> EventIndex {
        self.events.now()
    }

    fn submit(&mut self, block: cap::Block) -> Result<(), KeystoreError<cap::LedgerWithHeight<H>>> {
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
    ) -> Result<(), KeystoreError<cap::LedgerWithHeight<H>>> {
        let (block, block_uids) = &self.committed_blocks[block_id as usize];
        let txn = &block[txn_id as usize];
        let hash = txn.hash();
        let kind = txn.kind();
        let comms = txn.output_commitments();
        let uids = block_uids[txn_id as usize].clone();

        txn.verify_receiver_memos_signature(&memos, &sig)
            .context(CryptoSnafu)?;

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
        self.generate_event(LedgerEvent::<cap::LedgerWithHeight<H>>::Memos {
            outputs: izip!(memos, comms, uids, merkle_paths).collect(),
            transaction: Some((block_id, txn_id, hash, kind)),
        });

        Ok(())
    }

    fn memos_source(&self) -> EventSource {
        EventSource::QueryService
    }

    fn generate_event(&mut self, e: LedgerEvent<cap::LedgerWithHeight<H>>) {
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
    ) -> Result<LedgerEvent<cap::LedgerWithHeight<H>>, KeystoreError<cap::LedgerWithHeight<H>>>
    {
        if source == EventSource::QueryService {
            self.events.get(index)
        } else {
            Err(KeystoreError::Failed {
                msg: String::from("invalid event source"),
            })
        }
    }
}

#[derive(Clone)]
pub struct MockBackendWithHeight<'a, const H: u8> {
    ledger: Arc<Mutex<MockLedger<'a, cap::LedgerWithHeight<H>, MockNetworkWithHeight<'a, H>>>>,
}

impl<'a, const H: u8> MockBackendWithHeight<'a, H> {
    pub fn new(
        ledger: Arc<Mutex<MockLedger<'a, cap::LedgerWithHeight<H>, MockNetworkWithHeight<'a, H>>>>,
    ) -> Self {
        Self { ledger }
    }
}

#[async_trait]
impl<'a, const H: u8> KeystoreBackend<'a, cap::LedgerWithHeight<H>>
    for MockBackendWithHeight<'a, H>
{
    type EventStream =
        Pin<Box<dyn Stream<Item = (LedgerEvent<cap::LedgerWithHeight<H>>, EventSource)> + Send>>;

    async fn create(
        &mut self,
    ) -> Result<KeystoreState<'a, cap::LedgerWithHeight<H>>, KeystoreError<cap::LedgerWithHeight<H>>>
    {
        let state = {
            let mut ledger = self.ledger.lock().await;
            let network = ledger.network();

            KeystoreState {
                proving_keys: network.proving_keys.clone(),
                txn_state: TransactionState {
                    validator: network.validator.clone(),

                    records: Default::default(),
                    nullifiers: Default::default(),
                    record_mt: SparseMerkleTree::sparse(network.records.clone()),

                    now: network.now(),
                },
                key_state: Default::default(),
            }
        };
        Ok(state)
    }

    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream {
        let mut ledger = self.ledger.lock().await;
        ledger.network().events.subscribe(from, to)
    }

    async fn get_public_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserPubKey, KeystoreError<cap::LedgerWithHeight<H>>> {
        let mut ledger = self.ledger.lock().await;
        match ledger.network().address_map.get(address) {
            Some(key) => Ok(key.clone()),
            None => Err(KeystoreError::<cap::LedgerWithHeight<H>>::InvalidAddress {
                address: address.clone(),
            }),
        }
    }

    async fn get_initial_scan_state(
        &self,
        _from: EventIndex,
    ) -> Result<(MerkleTree, EventIndex), KeystoreError<cap::LedgerWithHeight<H>>> {
        self.ledger.lock().await.get_initial_scan_state()
    }

    async fn get_nullifier_proof(
        &self,
        _set: &mut cap::NullifierSet,
        nullifier: Nullifier,
    ) -> Result<(bool, ()), KeystoreError<cap::LedgerWithHeight<H>>> {
        let mut ledger = self.ledger.lock().await;
        Ok((ledger.network().nullifiers.contains(&nullifier), ()))
    }

    async fn register_user_key(
        &mut self,
        key_pair: &UserKeyPair,
    ) -> Result<(), KeystoreError<cap::LedgerWithHeight<H>>> {
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
        _info: Transaction<cap::LedgerWithHeight<H>>,
    ) -> Result<(), KeystoreError<cap::LedgerWithHeight<H>>> {
        self.ledger.lock().await.submit(txn)
    }

    async fn finalize(
        &mut self,
        txn: Transaction<cap::LedgerWithHeight<H>>,
        txn_id: Option<(u64, u64)>,
    ) {
        if let Some((block_id, txn_id)) = txn_id {
            if let Some(signed_memos) = txn.memos() {
                self.ledger
                    .lock()
                    .await
                    .post_memos(
                        block_id,
                        txn_id,
                        signed_memos.memos.iter().cloned().flatten().collect(),
                        signed_memos.sig.clone(),
                    )
                    .unwrap();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MockSystemWithHeight<const H: u8>;

#[async_trait]
impl<'a, const H: u8> super::SystemUnderTest<'a> for MockSystemWithHeight<H> {
    type Ledger = cap::LedgerWithHeight<H>;
    type MockBackend = MockBackendWithHeight<'a, H>;
    type MockNetwork = MockNetworkWithHeight<'a, H>;

    async fn create_network(
        &mut self,
        _verif_crs: VerifierKeySet,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockNetwork {
        let mut rng = ChaChaRng::from_seed([42u8; 32]);
        MockNetworkWithHeight::new(&mut rng, proof_crs, records, initial_grants)
    }

    async fn create_backend(
        &mut self,
        ledger: Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork>>>,
        _initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockBackend {
        MockBackendWithHeight::new(ledger)
    }
}

pub type MockBackend<'a> = MockBackendWithHeight<'a, 5>;
pub type MockNetwork<'a> = MockNetworkWithHeight<'a, 5>;
pub type MockSystem = MockSystemWithHeight<5>;

#[cfg(test)]
mod tests {
    use super::super::generic_keystore_tests;
    instantiate_generic_keystore_tests!(super::MockSystem);
}
