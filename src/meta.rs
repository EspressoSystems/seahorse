// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Storage for [KeystoreLoader] metadata.
use crate::{hd::KeyTree, loader::KeystoreLoader, EncryptingResourceAdapter, KeystoreError};
use atomic_store::{load_store::BincodeLoadStore, AtomicStoreLoader, RollingLog};
use reef::*;
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt;

pub struct MetaStore<Meta: Serialize + DeserializeOwned> {
    // Metadata given at initialization time that may not have been written to disk yet.
    meta: Meta,
    // Persisted metadata, if the keystore has already been committed to disk. This is a snapshot log
    // which only ever has at most 1 entry. It is reprsented as a log, rather than a plain file,
    // solely so that we can use the transaction mechanism of AtomicStore to ensure that the
    // metadata and static data are persisted to disk atomically when the keystore is created.
    persisted_meta: RollingLog<BincodeLoadStore<Meta>>,
    meta_dirty: bool,
    root_key_tree: KeyTree,
}

impl<Meta: Send + Serialize + DeserializeOwned + Clone + PartialEq> MetaStore<Meta> {
    pub fn new<L: Ledger, Loader: KeystoreLoader<L, Meta = Meta>>(
        loader: &mut Loader,
        atomic_loader: &mut AtomicStoreLoader,
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

        Ok(Self {
            meta,
            persisted_meta,
            meta_dirty,
            root_key_tree: key,
        })
    }
}

impl<Meta: Send + Serialize + DeserializeOwned> MetaStore<Meta> {
    pub async fn create<L: Ledger>(mut self: &mut Self) -> Result<(), KeystoreError<L>> {
        // Store the metadata.
        self.persisted_meta
            .store_resource(&self.meta)
            .context(crate::PersistenceSnafu)?;
        self.meta_dirty = true;
        Ok(())
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

impl<Meta: Send + Serialize + DeserializeOwned> MetaStore<Meta> {
    pub fn exists(&self) -> bool {
        self.persisted_meta.load_latest().is_ok()
    }

    pub fn commit(&mut self) {
        {
            if self.meta_dirty {
                self.persisted_meta.commit_version().unwrap();
            } else {
                self.persisted_meta.skip_version().unwrap();
            }
        }

        self.meta_dirty = false;
    }

    pub async fn revert(&mut self) {
        self.persisted_meta.revert_version().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        events::{EventIndex, EventSource},
        loader::KeystoreLoader,
        lw_merkle_tree::LWMerkleTree,
        LedgerState, LedgerStates,
    };
    use atomic_store::AtomicStore;
    use jf_cap::{
        keys::UserKeyPair,
        structs::{AssetDefinition, FreezeFlag, RecordCommitment, RecordOpening},
        TransactionVerifyingKey,
    };
    use key_set::{KeySet, ProverKeySet};
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaChaRng,
    };
    use reef::cap;
    use std::path::PathBuf;
    use std::sync::Arc;
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
        LedgerState<'static, cap::Ledger>,
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
                srs,
                num_inputs,
                num_outputs,
                cap::Ledger::merkle_height(),
            )
            .unwrap();
            xfr_prove_keys.push(xfr_prove_key);
            xfr_verif_keys.push(TransactionVerifyingKey::Transfer(xfr_verif_key));
        }
        let (mint_prove_key, _, _) =
            jf_cap::proof::mint::preprocess(srs, cap::Ledger::merkle_height()).unwrap();
        let (freeze_prove_key, _, _) =
            jf_cap::proof::freeze::preprocess(srs, 2, cap::Ledger::merkle_height()).unwrap();
        let record_merkle_tree = LWMerkleTree::new(cap::Ledger::merkle_height()).unwrap();
        let validator = cap::Validator::default();

        let state = LedgerState::new(
            Arc::new(ProverKeySet {
                xfr: KeySet::new(xfr_prove_keys.into_iter()).unwrap(),
                freeze: KeySet::new(vec![freeze_prove_key].into_iter()).unwrap(),
                mint: mint_prove_key,
            }),
            Default::default(),
            validator,
            record_merkle_tree,
            Default::default(),
        );

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
            let mut meta_store =
                MetaStore::new::<cap::Ledger, MockKeystoreLoader>(&mut loader, &mut atomic_loader)
                    .unwrap();
            let adaptor = meta_store.encrypting_storage_adapter::<()>();
            let mut ledger_states =
                LedgerStates::new(&mut atomic_loader, adaptor.cast(), adaptor.cast(), 1024)
                    .unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();

            ledger_states.update(&state).unwrap();
            ledger_states.commit().unwrap();
            meta_store.commit();
            atomic_store.commit_version().unwrap();
            assert!(!meta_store.exists());
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
            let mut meta_store =
                MetaStore::new::<cap::Ledger, MockKeystoreLoader>(&mut loader, &mut atomic_loader)
                    .unwrap();
            let adaptor = meta_store.encrypting_storage_adapter::<()>();
            let mut ledger_states =
                LedgerStates::new(&mut atomic_loader, adaptor.cast(), adaptor.cast(), 1024)
                    .unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            let state = ledger_states.load().unwrap();
            ledger_states.commit().unwrap();
            meta_store.commit();
            atomic_store.commit_version().unwrap();
            state
        };
        assert_eq!(stored, loaded);

        // Modify some dynamic state and load the keystore again.
        let user_key = UserKeyPair::generate(&mut rng);
        let ro = random_ro(&mut rng, &user_key);
        let comm = RecordCommitment::from(&ro);
        stored.record_mt.push(comm.to_field_element());
        stored.validator.block_height += 1;
        stored.now += EventIndex::from_source(EventSource::QueryService, 1);

        // Snapshot the modified dynamic state and then reload.
        {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut meta_store =
                MetaStore::new::<cap::Ledger, MockKeystoreLoader>(&mut loader, &mut atomic_loader)
                    .unwrap();
            let adaptor = meta_store.encrypting_storage_adapter::<()>();
            let mut ledger_states =
                LedgerStates::new(&mut atomic_loader, adaptor.cast(), adaptor.cast(), 1024)
                    .unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            ledger_states.update_dynamic(&stored).unwrap();
            ledger_states.commit().unwrap();
            meta_store.commit();
            atomic_store.commit_version().unwrap();
        }
        let loaded = {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut meta_store =
                MetaStore::new::<cap::Ledger, MockKeystoreLoader>(&mut loader, &mut atomic_loader)
                    .unwrap();
            let adaptor = meta_store.encrypting_storage_adapter::<()>();
            let mut ledger_states =
                LedgerStates::new(&mut atomic_loader, adaptor.cast(), adaptor.cast(), 1024)
                    .unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();
            let state = ledger_states.load().unwrap();
            ledger_states.commit().unwrap();
            meta_store.commit();
            atomic_store.commit_version().unwrap();
            state
        };
        assert_eq!(stored, loaded);

        Ok(())
    }

    #[async_std::test]
    async fn test_revert() -> std::io::Result<()> {
        let (stored, mut loader, mut rng) = get_test_state("test_revert").await;

        let loaded = {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut meta_store =
                MetaStore::new::<cap::Ledger, MockKeystoreLoader>(&mut loader, &mut atomic_loader)
                    .unwrap();
            let adaptor = meta_store.encrypting_storage_adapter::<()>();
            let mut ledger_states =
                LedgerStates::new(&mut atomic_loader, adaptor.cast(), adaptor.cast(), 1024)
                    .unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();

            let mut updated = stored.clone();
            updated.now = EventIndex::new(123, 456);
            ledger_states.update_dynamic(&updated).unwrap();
            ledger_states.revert().unwrap();
            ledger_states.commit().unwrap();
            meta_store.commit();
            atomic_store.commit_version().unwrap();

            // Make sure loading after a revert does not return the reverted changes.
            let state = ledger_states.load().unwrap();
            state
        };
        assert_eq!(stored, loaded);

        // Change multiple data structures and revert.
        let loaded = {
            let mut atomic_loader = AtomicStoreLoader::load(
                &KeystoreLoader::<cap::Ledger>::location(&loader),
                "keystore",
            )
            .unwrap();
            let mut meta_store =
                MetaStore::new::<cap::Ledger, MockKeystoreLoader>(&mut loader, &mut atomic_loader)
                    .unwrap();
            let adaptor = meta_store.encrypting_storage_adapter::<()>();
            let mut ledger_states =
                LedgerStates::new(&mut atomic_loader, adaptor.cast(), adaptor.cast(), 1024)
                    .unwrap();
            let mut atomic_store = AtomicStore::open(atomic_loader).unwrap();

            let user_key = UserKeyPair::generate(&mut rng);
            let ro = random_ro(&mut rng, &user_key);
            let nullifier = user_key.nullify(
                ro.asset_def.policy_ref().freezer_pub_key(),
                0,
                &RecordCommitment::from(&ro),
            );

            let mut updated = stored.clone();
            updated.nullifiers.insert(nullifier.into());
            updated.now = EventIndex::new(123, 456);

            ledger_states.update_dynamic(&updated).unwrap();
            ledger_states.revert().unwrap();
            // Loading after revert should be a no-op.
            let state = ledger_states.load().unwrap();
            ledger_states.commit().unwrap();
            meta_store.commit();
            atomic_store.commit_version().unwrap();
            state
        };
        assert_eq!(stored, loaded);

        Ok(())
    }
}
