// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Ledger-agnostic implementation of [KeystoreStorage].
use crate::{
    accounts::Account, hd::KeyTree, txn_builder::TransactionState, EncryptingResourceAdapter,
    KeyStreamState, KeystoreError, KeystoreState,
};
use arbitrary::{Arbitrary, Unstructured};
use async_std::sync::Arc;
use atomic_store::{load_store::BincodeLoadStore, AppendLog, AtomicStoreLoader, RollingLog};
use espresso_macros::ser_test;
use jf_cap::keys::{FreezerKeyPair, UserKeyPair, ViewerKeyPair};
use key_set::{OrderByOutputs, ProverKeySet};
use reef::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt;

const ATOMIC_STORE_RETAINED_ENTRIES: u32 = 5;

// Serialization intermediate for the static part of a KeystoreState.
#[derive(Deserialize, Serialize, Debug)]
struct KeystoreStaticState<'a> {
    #[serde(with = "serde_ark_unchecked")]
    proving_keys: Arc<ProverKeySet<'a, OrderByOutputs>>,
}

impl<'a, L: Ledger> From<&KeystoreState<'a, L>> for KeystoreStaticState<'a> {
    fn from(w: &KeystoreState<'a, L>) -> Self {
        Self {
            proving_keys: w.proving_keys.clone(),
        }
    }
}

mod serde_ark_unchecked {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use serde::{
        de::{Deserialize, Deserializer},
        ser::{Serialize, Serializer},
    };
    use std::sync::Arc;

    pub fn serialize<S: Serializer, T: CanonicalSerialize>(
        t: &Arc<T>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        t.serialize_unchecked(&mut bytes).unwrap();
        Serialize::serialize(&bytes, s)
    }

    pub fn deserialize<'a, D: Deserializer<'a>, T: CanonicalDeserialize>(
        d: D,
    ) -> Result<Arc<T>, D::Error> {
        let bytes = <Vec<u8> as Deserialize<'a>>::deserialize(d)?;
        Ok(Arc::new(T::deserialize_unchecked(&*bytes).unwrap()))
    }
}

// Serialization intermediate for the dynamic part of a KeystoreState.
#[ser_test(arbitrary, types(cap::Ledger), ark(false))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(bound = "")]
struct KeystoreSnapshot<L: Ledger> {
    txn_state: TransactionState<L>,
    key_state: KeyStreamState,
    viewing_accounts: Vec<Account<L, ViewerKeyPair>>,
    freezing_accounts: Vec<Account<L, FreezerKeyPair>>,
    sending_accounts: Vec<Account<L, UserKeyPair>>,
}

impl<L: Ledger> PartialEq<Self> for KeystoreSnapshot<L> {
    fn eq(&self, other: &Self) -> bool {
        self.txn_state == other.txn_state
            && self.key_state == other.key_state
            && self.viewing_accounts == other.viewing_accounts
            && self.freezing_accounts == other.freezing_accounts
            && self.sending_accounts == other.sending_accounts
    }
}

impl<'a, L: Ledger> From<&KeystoreState<'a, L>> for KeystoreSnapshot<L> {
    fn from(w: &KeystoreState<'a, L>) -> Self {
        Self {
            txn_state: w.txn_state.clone(),
            key_state: w.key_state.clone(),
            viewing_accounts: w.viewing_accounts.values().cloned().collect(),
            freezing_accounts: w.freezing_accounts.values().cloned().collect(),
            sending_accounts: w.sending_accounts.values().cloned().collect(),
        }
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for KeystoreSnapshot<L>
where
    TransactionState<L>: Arbitrary<'a>,
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            txn_state: u.arbitrary()?,
            key_state: u.arbitrary()?,
            viewing_accounts: u.arbitrary()?,
            freezing_accounts: u.arbitrary()?,
            sending_accounts: u.arbitrary()?,
        })
    }
}

pub struct AtomicKeystoreStorage<'a, L: Ledger, Meta: Serialize + DeserializeOwned> {
    // Metadata given at initialization time that may not have been written to disk yet.
    meta: Meta,
    // Persisted metadata, if the keystore has already been committed to disk. This is a snapshot log
    // which only ever has at most 1 entry. It is reprsented as a log, rather than a plain file,
    // solely so that we can use the transaction mechanism of AtomicStore to ensure that the
    // metadata and static data are persisted to disk atomically when the keystore is created.
    persisted_meta: RollingLog<BincodeLoadStore<Meta>>,
    meta_dirty: bool,
    // Snapshot log with a single entry containing the static data.
    static_data: RollingLog<EncryptingResourceAdapter<KeystoreStaticState<'a>>>,
    static_dirty: bool,
    dynamic_state: RollingLog<EncryptingResourceAdapter<KeystoreSnapshot<L>>>,
    dynamic_state_dirty: bool,
    keystore_key_tree: KeyTree,
}

impl<'a, L: Ledger, Meta: Send + Serialize + DeserializeOwned + Clone + PartialEq>
    AtomicKeystoreStorage<'a, L, Meta>
{
    pub fn new<T>(
        adapter: EncryptingResourceAdapter<T>,
        atomic_loader: &mut AtomicStoreLoader,
        file_fill_size: u64,
        meta: Meta,
        persisted_meta: RollingLog<BincodeLoadStore<Meta>>,
        meta_dirty: bool,
        key: KeyTree,
    ) -> Result<Self, KeystoreError<L>> {
        let static_data = RollingLog::load(
            atomic_loader,
            adapter.cast(),
            "keystore_static",
            file_fill_size,
        )
        .context(crate::PersistenceSnafu)?;

        let mut dynamic_state = RollingLog::load(
            atomic_loader,
            adapter.cast(),
            "keystore_dyn",
            file_fill_size,
        )
        .context(crate::PersistenceSnafu)?;
        dynamic_state.set_retained_entries(ATOMIC_STORE_RETAINED_ENTRIES);


        Ok(Self {
            meta,
            persisted_meta,
            meta_dirty,
            static_data,
            static_dirty: false,
            dynamic_state,
            dynamic_state_dirty: false,
            keystore_key_tree: key.derive_sub_tree("keystore".as_bytes()),
        })
    }
}

impl<'a, L: Ledger, Meta: Send + Serialize + DeserializeOwned> AtomicKeystoreStorage<'a, L, Meta> {
    pub async fn create(
        mut self: &mut Self,
        w: &KeystoreState<'a, L>,
    ) -> Result<(), KeystoreError<L>> {
        // Store the initial static and dynamic state, and the metadata. We do this in a closure so
        // that if any operation fails, it will exit the closure but not this function, and we can
        // then commit or revert based on the results of the closure.
        let store = &mut self;
        match (|| async move {
            store
                .persisted_meta
                .store_resource(&store.meta)
                .context(crate::PersistenceSnafu)?;
            store.meta_dirty = true;
            store
                .static_data
                .store_resource(&KeystoreStaticState::from(w))
                .context(crate::PersistenceSnafu)?;
            store.static_dirty = true;
            store.store_snapshot(w).await
        })()
        .await
        {
            Ok(()) => {
                self.commit().await;
                Ok(())
            }
            Err(err) => {
                self.revert().await;
                Err(err)
            }
        }
    }

    pub fn key_stream(&self) -> KeyTree {
        self.keystore_key_tree.clone()
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }
}

impl<'a, L: Ledger, Meta: Send + Serialize + DeserializeOwned> AtomicKeystoreStorage<'a, L, Meta> {
    pub fn exists(&self) -> bool {
        self.persisted_meta.load_latest().is_ok()
    }

    pub async fn load(&mut self) -> Result<KeystoreState<'a, L>, KeystoreError<L>> {
        // This function is called once, when the keystore is loaded. It is a good place to persist
        // changes to the metadata that happened during loading.
        self.commit().await;

        let static_state = self
            .static_data
            .load_latest()
            .context(crate::PersistenceSnafu)?;

        let dynamic_state = self
            .dynamic_state
            .load_latest()
            .context(crate::PersistenceSnafu)?;

        Ok(KeystoreState {
            // Static state
            proving_keys: static_state.proving_keys,

            // Dynamic state
            txn_state: dynamic_state.txn_state,
            key_state: dynamic_state.key_state,
            viewing_accounts: dynamic_state
                .viewing_accounts
                .into_iter()
                .map(|account| (account.key.pub_key(), account))
                .collect(),
            freezing_accounts: dynamic_state
                .freezing_accounts
                .into_iter()
                .map(|account| (account.key.pub_key(), account))
                .collect(),
            sending_accounts: dynamic_state
                .sending_accounts
                .into_iter()
                .map(|account| (account.key.address(), account))
                .collect(),
        })
    }

    pub async fn store_snapshot(
        &mut self,
        w: &KeystoreState<'a, L>,
    ) -> Result<(), KeystoreError<L>> {
        self.dynamic_state
            .store_resource(&KeystoreSnapshot::from(w))
            .context(crate::PersistenceSnafu)?;
        self.dynamic_state_dirty = true;
        Ok(())
    }

    // pub async fn store_transaction(
    //     &mut self,
    //     txn: TransactionHistoryEntry<L>,
    // ) -> Result<(), KeystoreError<L>> {
    //     self.txn_history
    //         .store_resource(&txn)
    //         .context(crate::PersistenceSnafu)?;
    //     self.txn_history_dirty = true;
    //     Ok(())
    // }

    // pub async fn transaction_history(
    //     &mut self,
    // ) -> Result<Vec<TransactionHistoryEntry<L>>, KeystoreError<L>> {
    //     self.txn_history
    //         .iter()
    //         .map(|res| res.context(crate::PersistenceSnafu))
    //         .collect()
    // }

    pub async fn commit(&mut self) {
        {
            if self.meta_dirty {
                self.persisted_meta.commit_version().unwrap();
            } else {
                self.persisted_meta.skip_version().unwrap();
            }

            if self.static_dirty {
                self.static_data.commit_version().unwrap();
            } else {
                self.static_data.skip_version().unwrap();
            }

            if self.dynamic_state_dirty {
                self.dynamic_state.commit_version().unwrap();
                self.dynamic_state.prune_file_entries().unwrap();
            } else {
                self.dynamic_state.skip_version().unwrap();
            }
        }

        self.meta_dirty = false;
        self.static_dirty = false;
        self.dynamic_state_dirty = false;
    }

    pub async fn revert(&mut self) {
        self.persisted_meta.revert_version().unwrap();
        self.static_data.revert_version().unwrap();
        self.dynamic_state.revert_version().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        events::{EventIndex, EventSource},
        loader::KeystoreLoader,
        sparse_merkle_tree::SparseMerkleTree,
        testing::{assert_keystore_states_eq, mocks::MockBackend},
        txn_builder::{TransactionUID},
        Keystore,
    };
    use chrono::Local;
    use commit::Commitment;
    use jf_cap::{
        keys::{UserKeyPair, ViewerKeyPair},
        sign_receiver_memos,
        structs::{
            AssetCode, AssetDefinition, FreezeFlag, ReceiverMemo, RecordCommitment, RecordOpening,
        },
        KeyPair, Signature, TransactionVerifyingKey,
    };
    use key_set::KeySet;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaChaRng,
    };
    use reef::{cap, traits::TransactionKind as _};
    use std::iter::repeat_with;
    use std::path::PathBuf;
    use tempdir::TempDir;

    struct MockKeystoreLoader {
        dir: TempDir,
        key: KeyTree,
    }

    impl<L: Ledger> KeystoreLoader<L> for MockKeystoreLoader {
        type Meta = ();

        fn location(&self) -> PathBuf {
            self.dir.path().into()
        }

        fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<L>> {
            Ok(((), self.key.clone()))
        }

        fn load(&mut self, _meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<L>> {
            Ok(self.key.clone())
        }
    }

    fn random_ro(rng: &mut ChaChaRng, key_pair: &UserKeyPair) -> RecordOpening {
        let amount = rng.next_u64();
        RecordOpening::new(
            rng,
            amount.into(),
            AssetDefinition::native(),
            key_pair.pub_key(),
            FreezeFlag::Unfrozen,
        )
    }

    fn random_ros(rng: &mut ChaChaRng, key_pair: &UserKeyPair) -> Vec<RecordOpening> {
        repeat_with(|| random_ro(rng, key_pair)).take(3).collect()
    }

    fn random_memos(
        rng: &mut ChaChaRng,
        key_pair: &UserKeyPair,
    ) -> (Vec<Option<ReceiverMemo>>, Signature) {
        let memos = repeat_with(|| {
            let ro = random_ro(rng, key_pair);
            ReceiverMemo::from_ro(rng, &ro, &[]).unwrap()
        })
        .take(3)
        .collect::<Vec<_>>();
        let sig = sign_receiver_memos(&KeyPair::generate(rng), &memos).unwrap();
        (memos.into_iter().map(|memo| Some(memo)).collect(), sig)
    }

    fn random_txn_hash(rng: &mut ChaChaRng) -> Commitment<cap::Transaction> {
        let mut hash = [0; 64];
        rng.fill_bytes(&mut hash);
        commit::RawCommitmentBuilder::<cap::Transaction>::new("random_txn_hash")
            .fixed_size_bytes(&hash)
            .finalize()
    }

    async fn get_test_state(
        name: &str,
    ) -> (
        KeystoreState<'static, cap::Ledger>,
        MockKeystoreLoader,
        ChaChaRng,
    ) {
        let mut rng = ChaChaRng::from_seed([0x42u8; 32]);

        // Pick a few different sizes. It doesn't matter since all we're going to be doing is
        // serializing and deserializing, but try to choose representative data.
        let xfr_sizes = [(1, 2), (2, 3), (3, 3)];

        let srs = cap::Ledger::srs();
        let mut xfr_prove_keys = vec![];
        let mut xfr_verif_keys = vec![];
        for (num_inputs, num_outputs) in xfr_sizes {
            let (xfr_prove_key, xfr_verif_key, _) = jf_cap::proof::transfer::preprocess(
                &*srs,
                num_inputs,
                num_outputs,
                cap::Ledger::merkle_height(),
            )
            .unwrap();
            xfr_prove_keys.push(xfr_prove_key);
            xfr_verif_keys.push(TransactionVerifyingKey::Transfer(xfr_verif_key));
        }
        let (mint_prove_key, _, _) =
            jf_cap::proof::mint::preprocess(&*srs, cap::Ledger::merkle_height()).unwrap();
        let (freeze_prove_key, _, _) =
            jf_cap::proof::freeze::preprocess(&*srs, 2, cap::Ledger::merkle_height()).unwrap();
        let record_merkle_tree = SparseMerkleTree::new(cap::Ledger::merkle_height()).unwrap();
        let validator = cap::Validator::default();

        let state = KeystoreState {
            proving_keys: Arc::new(ProverKeySet {
                xfr: KeySet::new(xfr_prove_keys.into_iter()).unwrap(),
                freeze: KeySet::new(vec![freeze_prove_key].into_iter()).unwrap(),
                mint: mint_prove_key,
            }),
            txn_state: TransactionState {
                validator,
                now: Default::default(),
                records: Default::default(),
                nullifiers: Default::default(),
                record_mt: record_merkle_tree,
                transactions: Default::default(),
            },
            key_state: Default::default(),
            viewing_accounts: Default::default(),
            freezing_accounts: Default::default(),
            sending_accounts: Default::default(),
        };

        let mut loader = MockKeystoreLoader {
            dir: TempDir::new(name).unwrap(),
            key: KeyTree::random(&mut rng).0,
        };
        {
            let (mut atomic_store, mut storage, mut assets) =
                Keystore::<MockBackend, cap::Ledger, ()>::create_stores(&mut loader).unwrap();
            storage.create(&state).await.unwrap();
            assert!(storage.exists());
            assets.commit::<cap::Ledger>().unwrap();
            atomic_store.commit_version().unwrap();
        }

        (state, loader, rng)
    }

    #[async_std::test]
    async fn test_round_trip() -> std::io::Result<()> {
        let (mut stored, mut loader, mut rng) = get_test_state("test_round_trip").await;

        // Create a new storage instance to load the keystore back from disk, to ensure that what we
        // load comes only from persistent storage and not from any in-memory state of the first
        // instance.
        let loaded = {
            let (mut atomic_store, mut storage, mut assets) =
                Keystore::<MockBackend, cap::Ledger, ()>::create_stores(&mut loader).unwrap();
            let state = storage.load().await.unwrap();
            assets.commit::<cap::Ledger>().unwrap();
            atomic_store.commit_version().unwrap();
            state
        };
        assert_keystore_states_eq(&stored, &loaded);

        // Modify some dynamic state and load the keystore again.
        let user_key = UserKeyPair::generate(&mut rng);
        let ro = random_ro(&mut rng, &user_key);
        let comm = RecordCommitment::from(&ro);
        stored.txn_state.record_mt.push(comm.to_field_element());
        stored.txn_state.validator.now += 1;
        stored.txn_state.now += EventIndex::from_source(EventSource::QueryService, 1);
        stored.txn_state.records.insert(ro, 0, &user_key);
        let (memos, sig) = random_memos(&mut rng, &user_key);
        let txn_uid = TransactionUID(random_txn_hash(&mut rng));
        let txn = PendingTransaction {
            info: TransactionInfo {
                accounts: vec![user_key.address()],
                memos,
                sig,
                freeze_outputs: random_ros(&mut rng, &user_key),
                uid: Some(txn_uid.clone()),
                history: None,
                inputs: random_ros(&mut rng, &user_key),
                outputs: random_ros(&mut rng, &user_key),
            },
            timeout: 5000,
            hash: random_txn_hash(&mut rng),
        };
        stored.txn_state.transactions.insert_pending(txn);
        stored
            .txn_state
            .transactions
            .await_memos(txn_uid, vec![1, 2, 3]);

        // Snapshot the modified dynamic state and then reload.
        {
            let (mut atomic_store, mut storage, mut assets) =
                Keystore::<MockBackend, cap::Ledger, ()>::create_stores(&mut loader).unwrap();
            storage.store_snapshot(&stored).await.unwrap();
            storage.commit().await;
            assets.commit::<cap::Ledger>().unwrap();
            atomic_store.commit_version().unwrap();
        }
        let loaded = {
            let (mut atomic_store, mut storage, mut assets) =
                Keystore::<MockBackend, cap::Ledger, ()>::create_stores(&mut loader).unwrap();
            let state = storage.load().await.unwrap();
            assets.commit::<cap::Ledger>().unwrap();
            atomic_store.commit_version().unwrap();
            state
        };
        assert_keystore_states_eq(&stored, &loaded);

        // Append to monotonic state and then reload.
        let viewing_key = ViewerKeyPair::generate(&mut rng);
        // viewing keys for the asset library get persisted with the viewing accounts.
        stored.viewing_accounts.insert(
            viewing_key.pub_key(),
            Account::new(viewing_key, "viewing_account".into()),
        );
        {
            let (mut atomic_store, mut storage, mut assets) =
                Keystore::<MockBackend, cap::Ledger, ()>::create_stores(&mut loader).unwrap();
            storage.store_snapshot(&stored).await.unwrap();
            storage.commit().await;
            assets.commit::<cap::Ledger>().unwrap();
            atomic_store.commit_version().unwrap();
        }
        let loaded = {
            let (mut atomic_store, mut storage, mut assets) =
                Keystore::<MockBackend, cap::Ledger, ()>::create_stores(&mut loader).unwrap();
            let state = storage.load().await.unwrap();
            assets.commit::<cap::Ledger>().unwrap();
            atomic_store.commit_version().unwrap();
            state
        };
        assert_keystore_states_eq(&stored, &loaded);

        Ok(())
    }

    #[async_std::test]
    async fn test_revert() -> std::io::Result<()> {
        let (mut stored, mut loader, mut rng) = get_test_state("test_revert").await;

        // Change multiple data structures and revert.
        let loaded = {
            let (mut atomic_store, mut storage, mut assets) =
                Keystore::<MockBackend, cap::Ledger, ()>::create_stores(&mut loader).unwrap();

            let user_key = UserKeyPair::generate(&mut rng);
            let ro = random_ro(&mut rng, &user_key);
            let nullifier = user_key.nullify(
                ro.asset_def.policy_ref().freezer_pub_key(),
                0,
                &RecordCommitment::from(&ro),
            );

            // Store some data.
            stored.txn_state.records.insert(ro, 0, &user_key);
            storage.store_snapshot(&stored).await.unwrap();
            storage
                .store_transaction(TransactionHistoryEntry {
                    time: Local::now(),
                    asset: AssetCode::native(),
                    kind: TransactionKind::<cap::Ledger>::send(),
                    hash: None,
                    senders: vec![user_key.address()],
                    receivers: vec![],
                    fee_change: None,
                    asset_change: None,
                    receipt: None,
                })
                .await
                .unwrap();

            // Revert the changes.
            stored
                .txn_state
                .records
                .remove_by_nullifier(nullifier)
                .unwrap();
            storage.revert().await;

            // Loading after revert should be a no-op.
            let state = storage.load().await.unwrap();
            assets.commit::<cap::Ledger>().unwrap();
            atomic_store.commit_version().unwrap();
            state
        };
        assert_keystore_states_eq(&stored, &loaded);

        Ok(())
    }
}
