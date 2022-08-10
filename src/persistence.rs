// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Ledger-agnostic implementation of [KeystoreStorage].
use crate::{
    accounts::{Account, Accounts},
    hd::KeyTree,
    loader::KeystoreLoader,
    txn_builder::TransactionState,
    EncryptingResourceAdapter, KeyStreamState, KeystoreError, KeystoreState,
};
use arbitrary::{Arbitrary, Unstructured};
use async_std::sync::Arc;
use atomic_store::{load_store::BincodeLoadStore, AtomicStoreLoader, RollingLog};
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
#[derive(Deserialize, Serialize)]
#[serde(bound = "")]
struct KeystoreSnapshot<L: Ledger> {
    txn_state: TransactionState<L>,
    key_state: KeyStreamState,
    viewing_accounts: Accounts<L, ViewerKeyPair>,
    freezing_accounts: Accounts<L, FreezerKeyPair>,
    sending_accounts: Accounts<L, UserKeyPair>,
}

// impl<L: Ledger> PartialEq<Self> for KeystoreSnapshot<L> {
//     fn eq(&self, other: &Self) -> bool {
//         self.txn_state == other.txn_state
//             && self.key_state == other.key_state
//             && self.viewing_accounts == other.viewing_accounts
//             && self.freezing_accounts == other.freezing_accounts
//             && self.sending_accounts == other.sending_accounts
//     }
// }

impl<'a, L: Ledger> From<&KeystoreState<'a, L>> for KeystoreSnapshot<L> {
    fn from(w: &KeystoreState<'a, L>) -> Self {
        Self {
            txn_state: w.txn_state.clone(),
            key_state: w.key_state.clone(),
            viewing_accounts: w.viewing_accounts,
            freezing_accounts: w.freezing_accounts,
            sending_accounts: w.sending_accounts,
        }
    }
}

// impl<'a, L: Ledger> Arbitrary<'a> for KeystoreSnapshot<L>
// where
//     TransactionState<L>: Arbitrary<'a>,
//     TransactionHash<L>: Arbitrary<'a>,
// {
//     fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
//         Ok(Self {
//             txn_state: u.arbitrary()?,
//             key_state: u.arbitrary()?,
//             viewing_accounts: u.arbitrary()?,
//             freezing_accounts: u.arbitrary()?,
//             sending_accounts: u.arbitrary()?,
//         })
//     }
// }

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
    root_key_tree: KeyTree,
}

impl<'a, L: Ledger, Meta: Send + Serialize + DeserializeOwned + Clone + PartialEq>
    AtomicKeystoreStorage<'a, L, Meta>
{
    pub fn new(
        loader: &mut impl KeystoreLoader<L, Meta = Meta>,
        atomic_loader: &mut AtomicStoreLoader,
        file_fill_size: u64,
    ) -> Result<Self, KeystoreError<L>> {
        // Load the metadata first so the loader can use it to generate the encryption key needed to
        // read the rest of the data.
        let mut persisted_meta = RollingLog::load(
            atomic_loader,
            BincodeLoadStore::<Meta>::default(),
            "keystore_meta",
            1024,
        )?;
        let (meta, key, meta_dirty) = match persisted_meta.load_latest() {
            Ok(mut meta) => {
                let old_meta = meta.clone();
                let key = loader.load(&mut meta)?;

                // Store the new metadata if the loader changed it
                if meta != old_meta {
                    persisted_meta.store_resource(&meta)?;
                    (meta, key, true)
                } else {
                    (meta, key, false)
                }
            }
            Err(_) => {
                // If there is no persisted metadata, ask the loader to generate a new keystore.
                let (meta, key) = loader.create()?;
                (meta, key, false)
            }
        };
        let adapter = EncryptingResourceAdapter::<()>::new(key.derive_sub_tree("enc".as_bytes()));

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
            root_key_tree: key,
        })
    }
}

impl<'a, L: Ledger, Meta: Send + Serialize + DeserializeOwned> AtomicKeystoreStorage<'a, L, Meta> {
    pub async fn create(
        mut self: &mut Self,
        w: &KeystoreState<'a, L>,
    ) -> Result<(), KeystoreError<L>> {
        // Store the initial static and dynamic state, and the metadata.
        self.persisted_meta
            .store_resource(&self.meta)
            .context(crate::PersistenceSnafu)?;
        self.meta_dirty = true;
        self.static_data
            .store_resource(&KeystoreStaticState::from(w))
            .context(crate::PersistenceSnafu)?;
        self.static_dirty = true;
        self.store_snapshot(w).await
    }

    pub fn key_stream(&self) -> KeyTree {
        self.root_key_tree.derive_sub_tree("keystore".as_bytes())
    }

    pub fn encrypting_storage_adapter<T>(&self) -> EncryptingResourceAdapter<T> {
        EncryptingResourceAdapter::<T>::new(self.root_key_tree.derive_sub_tree("enc".as_bytes()))
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }
}

impl<'a, L: Ledger, Meta: Send + Serialize + DeserializeOwned> AtomicKeystoreStorage<'a, L, Meta> {
    pub fn exists(&self) -> bool {
        self.persisted_meta.load_latest().is_ok()
    }

    pub async fn load(&self) -> Result<KeystoreState<'a, L>, KeystoreError<L>> {
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
            viewing_accounts: dynamic_state.viewing_accounts,
            freezing_accounts: dynamic_state.freezing_accounts,
            sending_accounts: dynamic_state.sending_accounts,
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
        testing::assert_keystore_states_eq,
    };
    use atomic_store::AtomicStore;
    use jf_cap::{
        keys::{UserKeyPair, ViewerKeyPair},
        structs::{AssetDefinition, FreezeFlag, RecordCommitment, RecordOpening},
        TransactionVerifyingKey,
    };
    use key_set::KeySet;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaChaRng,
    };
    use reef::cap;
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
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut storage =
                AtomicKeystoreStorage::new(&mut loader, &mut atomic_loader, 1024).unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();

            storage.commit().await;
            atomic_store.commit_version().unwrap();
            assert!(!storage.exists());

            storage.create(&state).await.unwrap();
            storage.commit().await;
            atomic_store.commit_version().unwrap();
            assert!(storage.exists());
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
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut storage =
                AtomicKeystoreStorage::new(&mut loader, &mut atomic_loader, 1024).unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            let state = storage.load().await.unwrap();
            storage.commit().await;
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

        // Snapshot the modified dynamic state and then reload.
        {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut storage =
                AtomicKeystoreStorage::new(&mut loader, &mut atomic_loader, 1024).unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            storage.store_snapshot(&stored).await.unwrap();
            storage.commit().await;
            atomic_store.commit_version().unwrap();
        }
        let loaded = {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut storage =
                AtomicKeystoreStorage::new(&mut loader, &mut atomic_loader, 1024).unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            let state = storage.load().await.unwrap();
            storage.commit().await;
            atomic_store.commit_version().unwrap();
            state
        };
        assert_keystore_states_eq(&stored, &loaded);

        // Append to monotonic state and then reload.
        let viewing_key = ViewerKeyPair::generate(&mut rng);
        // viewing keys for the asset library get persisted with the viewing accounts.
        stored
            .viewing_accounts
            .create(viewing_key)
            .with_description("viewing_account".into())
            .save()
            .unwrap();
        {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut storage =
                AtomicKeystoreStorage::new(&mut loader, &mut atomic_loader, 1024).unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            storage.store_snapshot(&stored).await.unwrap();
            storage.commit().await;
            atomic_store.commit_version().unwrap();
        }
        let loaded = {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut storage =
                AtomicKeystoreStorage::new(&mut loader, &mut atomic_loader, 1024).unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            let state = storage.load().await.unwrap();
            storage.commit().await;
            atomic_store.commit_version().unwrap();
            state
        };
        assert_keystore_states_eq(&stored, &loaded);

        Ok(())
    }

    #[async_std::test]
    async fn test_revert() -> std::io::Result<()> {
        let (mut stored, mut loader, mut rng) = get_test_state("test_revert").await;

        // Make a change to one of the data structures, but revert it.
        let loaded = {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut storage =
                AtomicKeystoreStorage::new(&mut loader, &mut atomic_loader, 1024).unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            let user_key = UserKeyPair::generate(&mut rng);
            let ro = random_ro(&mut rng, &user_key);

            let mut updated = stored.clone();
            updated.txn_state.records.insert(ro, 0, &user_key);
            storage.store_snapshot(&updated).await.unwrap();
            storage.revert().await;
            storage.commit().await;
            atomic_store.commit_version().unwrap();

            // Make sure loading after a revert does not return the reverted changes.
            let state = storage.load().await.unwrap();
            state
        };
        assert_keystore_states_eq(&stored, &loaded);

        // Change multiple data structures and revert.
        let loaded = {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut storage =
                AtomicKeystoreStorage::new(&mut loader, &mut atomic_loader, 1024).unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();

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

            // Revert the changes.
            stored
                .txn_state
                .records
                .remove_by_nullifier(nullifier)
                .unwrap();
            storage.revert().await;

            // Loading after revert should be a no-op.
            let state = storage.load().await.unwrap();
            storage.commit().await;
            atomic_store.commit_version().unwrap();
            state
        };
        assert_keystore_states_eq(&stored, &loaded);

        Ok(())
    }
}
