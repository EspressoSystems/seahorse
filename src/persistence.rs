// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Ledger-agnostic implementation of [WalletStorage].
use crate::{
    asset_library::{AssetInfo, AssetLibrary},
    encryption::Cipher,
    hd::KeyTree,
    loader::WalletLoader,
    txn_builder::TransactionState,
    BackgroundKeyScan, KeyPair, KeyStreamState, RoleKeyPair, TransactionHistoryEntry, WalletError,
    WalletState, WalletStorage,
};
use arbitrary::{Arbitrary, Unstructured};
use async_std::sync::Arc;
use async_trait::async_trait;
use atomic_store::{
    error::PersistenceError,
    load_store::{BincodeLoadStore, LoadStore},
    AppendLog, AtomicStore, AtomicStoreLoader, RollingLog,
};
use espresso_macros::ser_test;
use key_set::{OrderByOutputs, ProverKeySet};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reef::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt;
use std::collections::HashMap;

// Serialization intermediate for the static part of a WalletState.
#[derive(Deserialize, Serialize)]
struct WalletStaticState<'a> {
    #[serde(with = "serde_ark_unchecked")]
    proving_keys: Arc<ProverKeySet<'a, OrderByOutputs>>,
}

impl<'a, L: Ledger> From<&WalletState<'a, L>> for WalletStaticState<'a> {
    fn from(w: &WalletState<'a, L>) -> Self {
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

// Serialization intermediate for the dynamic part of a WalletState.
#[ser_test(arbitrary, types(cap::Ledger), ark(false))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(bound = "")]
struct WalletSnapshot<L: Ledger> {
    txn_state: TransactionState<L>,
    key_scans: Vec<BackgroundKeyScan>,
    key_state: KeyStreamState,
}

impl<L: Ledger> PartialEq<Self> for WalletSnapshot<L> {
    fn eq(&self, other: &Self) -> bool {
        self.txn_state == other.txn_state
            && self.key_scans == other.key_scans
            && self.key_state == other.key_state
    }
}

impl<'a, L: Ledger> From<&WalletState<'a, L>> for WalletSnapshot<L> {
    fn from(w: &WalletState<'a, L>) -> Self {
        Self {
            txn_state: w.txn_state.clone(),
            key_scans: w.key_scans.values().cloned().collect(),
            key_state: w.key_state.clone(),
        }
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for WalletSnapshot<L>
where
    TransactionState<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            txn_state: u.arbitrary()?,
            key_scans: u.arbitrary()?,
            key_state: u.arbitrary()?,
        })
    }
}

struct EncryptingResourceAdapter<T> {
    cipher: Cipher<ChaChaRng>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> EncryptingResourceAdapter<T> {
    fn new(key: KeyTree) -> Self {
        Self {
            cipher: Cipher::new(key, ChaChaRng::from_entropy()),
            _phantom: Default::default(),
        }
    }

    fn cast<S>(&self) -> EncryptingResourceAdapter<S> {
        EncryptingResourceAdapter {
            cipher: self.cipher.clone(),
            _phantom: Default::default(),
        }
    }
}

impl<T: Serialize + DeserializeOwned> LoadStore for EncryptingResourceAdapter<T> {
    type ParamType = T;

    fn load(&self, stream: &[u8]) -> Result<Self::ParamType, PersistenceError> {
        let ciphertext = bincode::deserialize(stream)
            .map_err(|source| PersistenceError::BincodeDeError { source })?;
        let plaintext =
            self.cipher
                .decrypt(&ciphertext)
                .map_err(|err| PersistenceError::OtherLoadError {
                    inner: Box::new(err),
                })?;
        bincode::deserialize(&plaintext)
            .map_err(|source| PersistenceError::BincodeDeError { source })
    }

    fn store(&mut self, param: &Self::ParamType) -> Result<Vec<u8>, PersistenceError> {
        let plaintext = bincode::serialize(param)
            .map_err(|source| PersistenceError::BincodeSerError { source })?;
        let ciphertext =
            self.cipher
                .encrypt(&plaintext)
                .map_err(|err| PersistenceError::OtherStoreError {
                    inner: Box::new(err),
                })?;
        bincode::serialize(&ciphertext)
            .map_err(|source| PersistenceError::BincodeSerError { source })
    }
}

pub struct AtomicWalletStorage<'a, L: Ledger, Meta: Serialize + DeserializeOwned> {
    store: AtomicStore,
    // Metadata given at initialization time that may not have been written to disk yet.
    meta: Meta,
    // Persisted metadata, if the wallet has already been committed to disk. This is a snapshot log
    // which only ever has at most 1 entry. It is reprsented as a log, rather than a plain file,
    // solely so that we can use the transaction mechanism of AtomicStore to ensure that the
    // metadata and static data are persisted to disk atomically when the wallet is created.
    persisted_meta: RollingLog<BincodeLoadStore<Meta>>,
    meta_dirty: bool,
    // Snapshot log with a single entry containing the static data.
    static_data: RollingLog<EncryptingResourceAdapter<WalletStaticState<'a>>>,
    static_dirty: bool,
    dynamic_state: RollingLog<EncryptingResourceAdapter<WalletSnapshot<L>>>,
    dynamic_state_dirty: bool,
    assets: AppendLog<EncryptingResourceAdapter<AssetInfo>>,
    assets_dirty: bool,
    txn_history: AppendLog<EncryptingResourceAdapter<TransactionHistoryEntry<L>>>,
    txn_history_dirty: bool,
    keys: AppendLog<EncryptingResourceAdapter<RoleKeyPair>>,
    keys_dirty: bool,
    wallet_key_tree: KeyTree,
}

impl<'a, L: Ledger, Meta: Send + Serialize + DeserializeOwned> AtomicWalletStorage<'a, L, Meta> {
    pub fn new(
        loader: &mut impl WalletLoader<L, Meta = Meta>,
        file_fill_size: u64,
    ) -> Result<Self, WalletError<L>> {
        let directory = loader.location();
        let mut atomic_loader =
            AtomicStoreLoader::load(&directory, "wallet").context(crate::PersistenceError)?;

        // Load the metadata first so the loader can use it to generate the encryption key needed to
        // read the rest of the data.
        let persisted_meta = RollingLog::load(
            &mut atomic_loader,
            BincodeLoadStore::default(),
            "wallet_meta",
            1024,
        )
        .context(crate::PersistenceError)?;
        let (meta, key) = match persisted_meta.load_latest() {
            Ok(meta) => {
                let key = loader.load(&meta)?;
                (meta, key)
            }
            Err(_) => {
                // If there is no persisted metadata, ask the loader to generate a new wallet.
                loader.create()?
            }
        };

        let adaptor = EncryptingResourceAdapter::<()>::new(key.derive_sub_tree("enc".as_bytes()));
        let static_data = RollingLog::load(
            &mut atomic_loader,
            adaptor.cast(),
            "wallet_static",
            file_fill_size,
        )
        .context(crate::PersistenceError)?;
        let dynamic_state = RollingLog::load(
            &mut atomic_loader,
            adaptor.cast(),
            "wallet_dyn",
            file_fill_size,
        )
        .context(crate::PersistenceError)?;
        let assets = AppendLog::load(
            &mut atomic_loader,
            adaptor.cast(),
            "wallet_assets",
            file_fill_size,
        )
        .context(crate::PersistenceError)?;
        let txn_history = AppendLog::load(
            &mut atomic_loader,
            adaptor.cast(),
            "wallet_txns",
            file_fill_size,
        )
        .context(crate::PersistenceError)?;
        let keys = AppendLog::load(
            &mut atomic_loader,
            adaptor.cast(),
            "wallet_keys",
            file_fill_size,
        )
        .context(crate::PersistenceError)?;
        let store = AtomicStore::open(atomic_loader).context(crate::PersistenceError)?;

        Ok(Self {
            meta,
            persisted_meta,
            meta_dirty: false,
            static_data,
            static_dirty: false,
            store,
            dynamic_state,
            dynamic_state_dirty: false,
            assets,
            assets_dirty: false,
            txn_history,
            txn_history_dirty: false,
            keys,
            keys_dirty: false,
            wallet_key_tree: key.derive_sub_tree("wallet".as_bytes()),
        })
    }

    pub async fn create(mut self: &mut Self, w: &WalletState<'a, L>) -> Result<(), WalletError<L>> {
        // Store the initial static and dynamic state, and the metadata. We do this in a closure so
        // that if any operation fails, it will exit the closure but not this function, and we can
        // then commit or revert based on the results of the closure.
        let store = &mut self;
        match (|| async move {
            store
                .persisted_meta
                .store_resource(&store.meta)
                .context(crate::PersistenceError)?;
            store.meta_dirty = true;
            store
                .static_data
                .store_resource(&WalletStaticState::from(w))
                .context(crate::PersistenceError)?;
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
        self.wallet_key_tree.clone()
    }

    fn load_keys<K: KeyPair>(&self) -> HashMap<K::PubKey, K> {
        self.keys
            .iter()
            .filter_map(|res| {
                res.ok()
                    // Convert from type-erased RoleKey to strongly typed key, filtering out
                    // RoleKeys of the wrong type.
                    .and_then(|role_key| K::try_from(role_key).ok())
                    // Convert to (pub_key, key_pair) mapping.
                    .map(|key| (key.pub_key(), key))
            })
            .collect()
    }
}

#[async_trait]
impl<'a, L: Ledger, Meta: Send + Serialize + DeserializeOwned> WalletStorage<'a, L>
    for AtomicWalletStorage<'a, L, Meta>
{
    fn exists(&self) -> bool {
        self.persisted_meta.load_latest().is_ok()
    }

    async fn load(&mut self) -> Result<WalletState<'a, L>, WalletError<L>> {
        let static_state = self
            .static_data
            .load_latest()
            .context(crate::PersistenceError)?;
        let dynamic_state = self
            .dynamic_state
            .load_latest()
            .context(crate::PersistenceError)?;
        let assets = self.assets.iter().filter_map(|res| res.ok()).collect();
        let audit_keys = self.load_keys();

        Ok(WalletState {
            // Static state
            proving_keys: static_state.proving_keys,

            // Dynamic state
            txn_state: dynamic_state.txn_state,
            key_scans: dynamic_state
                .key_scans
                .into_iter()
                .map(|scan| (scan.key.address(), scan))
                .collect(),
            key_state: dynamic_state.key_state,

            // Monotonic state
            assets: AssetLibrary::new(assets, audit_keys.keys().cloned().collect()),
            audit_keys,
            freeze_keys: self.load_keys(),
            user_keys: self.load_keys(),
        })
    }

    async fn store_snapshot(&mut self, w: &WalletState<'a, L>) -> Result<(), WalletError<L>> {
        self.dynamic_state
            .store_resource(&WalletSnapshot::from(w))
            .context(crate::PersistenceError)?;
        self.dynamic_state_dirty = true;
        Ok(())
    }

    async fn store_asset(&mut self, asset: &AssetInfo) -> Result<(), WalletError<L>> {
        self.assets
            .store_resource(asset)
            .context(crate::PersistenceError)?;
        self.assets_dirty = true;
        Ok(())
    }

    async fn store_key(&mut self, key: &RoleKeyPair) -> Result<(), WalletError<L>> {
        self.keys
            .store_resource(key)
            .context(crate::PersistenceError)?;
        self.keys_dirty = true;
        Ok(())
    }

    async fn store_transaction(
        &mut self,
        txn: TransactionHistoryEntry<L>,
    ) -> Result<(), WalletError<L>> {
        self.txn_history
            .store_resource(&txn)
            .context(crate::PersistenceError)?;
        self.txn_history_dirty = true;
        Ok(())
    }

    async fn transaction_history(
        &mut self,
    ) -> Result<Vec<TransactionHistoryEntry<L>>, WalletError<L>> {
        self.txn_history
            .iter()
            .map(|res| res.context(crate::PersistenceError))
            .collect()
    }

    async fn commit(&mut self) {
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
            } else {
                self.dynamic_state.skip_version().unwrap();
            }

            if self.assets_dirty {
                self.assets.commit_version().unwrap();
            } else {
                self.assets.skip_version().unwrap();
            }

            if self.txn_history_dirty {
                self.txn_history.commit_version().unwrap();
            } else {
                self.txn_history.skip_version().unwrap();
            }

            if self.keys_dirty {
                self.keys.commit_version().unwrap();
            } else {
                self.keys.skip_version().unwrap();
            }
        }

        self.store.commit_version().unwrap();

        self.meta_dirty = false;
        self.static_dirty = false;
        self.dynamic_state_dirty = false;
        self.assets_dirty = false;
        self.txn_history_dirty = false;
        self.keys_dirty = false;
    }

    async fn revert(&mut self) {
        self.persisted_meta.revert_version().unwrap();
        self.static_data.revert_version().unwrap();
        self.dynamic_state.revert_version().unwrap();
        self.assets.revert_version().unwrap();
        self.keys.revert_version().unwrap();
        self.txn_history.revert_version().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::UNIVERSAL_PARAM;
    use crate::{
        events::{EventIndex, EventSource},
        testing::assert_wallet_states_eq,
        txn_builder::{PendingTransaction, TransactionInfo, TransactionUID},
    };
    use chrono::Local;
    use commit::Commitment;
    use jf_cap::{
        keys::{AuditorKeyPair, FreezerKeyPair, UserKeyPair},
        sign_receiver_memos,
        structs::{
            AssetCode, AssetDefinition, FreezeFlag, ReceiverMemo, RecordCommitment, RecordOpening,
        },
        KeyPair, MerkleTree, Signature, TransactionVerifyingKey,
    };
    use key_set::KeySet;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaChaRng,
    };
    use reef::traits::TransactionKind as _;
    use std::iter::repeat_with;
    use std::path::PathBuf;
    use tempdir::TempDir;

    struct MockWalletLoader {
        dir: TempDir,
        key: KeyTree,
    }

    impl<L: Ledger> WalletLoader<L> for MockWalletLoader {
        type Meta = ();

        fn location(&self) -> PathBuf {
            self.dir.path().into()
        }

        fn create(&mut self) -> Result<(Self::Meta, KeyTree), WalletError<L>> {
            Ok(((), self.key.clone()))
        }

        fn load(&mut self, _meta: &Self::Meta) -> Result<KeyTree, WalletError<L>> {
            Ok(self.key.clone())
        }
    }

    fn random_ro(rng: &mut ChaChaRng, key_pair: &UserKeyPair) -> RecordOpening {
        let amount = rng.next_u64();
        RecordOpening::new(
            rng,
            amount,
            AssetDefinition::native(),
            key_pair.pub_key(),
            FreezeFlag::Unfrozen,
        )
    }

    fn random_ros(rng: &mut ChaChaRng, key_pair: &UserKeyPair) -> Vec<RecordOpening> {
        repeat_with(|| random_ro(rng, key_pair)).take(3).collect()
    }

    fn random_memos(rng: &mut ChaChaRng, key_pair: &UserKeyPair) -> (Vec<ReceiverMemo>, Signature) {
        let memos = repeat_with(|| {
            let ro = random_ro(rng, key_pair);
            ReceiverMemo::from_ro(rng, &ro, &[]).unwrap()
        })
        .take(3)
        .collect::<Vec<_>>();
        let sig = sign_receiver_memos(&KeyPair::generate(rng), &memos).unwrap();
        (memos, sig)
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
        WalletState<'static, cap::Ledger>,
        MockWalletLoader,
        ChaChaRng,
    ) {
        let mut rng = ChaChaRng::from_seed([0x42u8; 32]);

        // Pick a few different sizes. It doesn't matter since all we're going to be doing is
        // serializing and deserializing, but try to choose representative data.
        let xfr_sizes = [(1, 2), (2, 3), (3, 3)];

        let mut xfr_prove_keys = vec![];
        let mut xfr_verif_keys = vec![];
        for (num_inputs, num_outputs) in xfr_sizes {
            let (xfr_prove_key, xfr_verif_key, _) = jf_cap::proof::transfer::preprocess(
                &*UNIVERSAL_PARAM,
                num_inputs,
                num_outputs,
                cap::Ledger::merkle_height(),
            )
            .unwrap();
            xfr_prove_keys.push(xfr_prove_key);
            xfr_verif_keys.push(TransactionVerifyingKey::Transfer(xfr_verif_key));
        }
        let (mint_prove_key, _, _) =
            jf_cap::proof::mint::preprocess(&*UNIVERSAL_PARAM, cap::Ledger::merkle_height())
                .unwrap();
        let (freeze_prove_key, _, _) =
            jf_cap::proof::freeze::preprocess(&*UNIVERSAL_PARAM, 2, cap::Ledger::merkle_height())
                .unwrap();
        let record_merkle_tree = MerkleTree::new(cap::Ledger::merkle_height()).unwrap();
        let validator = cap::Validator::default();

        let state = WalletState {
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
                merkle_leaf_to_forget: None,
                transactions: Default::default(),
            },
            key_scans: Default::default(),
            key_state: Default::default(),
            assets: Default::default(),
            audit_keys: Default::default(),
            freeze_keys: Default::default(),
            user_keys: Default::default(),
        };

        let mut loader = MockWalletLoader {
            dir: TempDir::new(name).unwrap(),
            key: KeyTree::random(&mut rng).unwrap().0,
        };
        {
            let mut storage = AtomicWalletStorage::new(&mut loader, 1024).unwrap();
            assert!(!storage.exists());
            storage.create(&state).await.unwrap();
            assert!(storage.exists());
        }

        (state, loader, rng)
    }

    #[async_std::test]
    async fn test_round_trip() -> std::io::Result<()> {
        let (mut stored, mut loader, mut rng) = get_test_state("test_round_trip").await;

        // Create a new storage instance to load the wallet back from disk, to ensure that what we
        // load comes only from persistent storage and not from any in-memory state of the first
        // instance.
        let loaded = {
            let mut storage = AtomicWalletStorage::new(&mut loader, 1024).unwrap();
            storage.load().await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        // Modify some dynamic state and load the wallet again.
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
                account: user_key.address(),
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
            let mut storage = AtomicWalletStorage::new(&mut loader, 1024).unwrap();
            storage.store_snapshot(&stored).await.unwrap();
            storage.commit().await;
        }
        let loaded = {
            let mut storage = AtomicWalletStorage::new(&mut loader, 1024).unwrap();
            storage.load().await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        // Append to monotonic state and then reload.
        let definition =
            AssetDefinition::new(AssetCode::random(&mut rng).0, Default::default()).unwrap();
        let audit_key = AuditorKeyPair::generate(&mut rng);
        let freeze_key = FreezerKeyPair::generate(&mut rng);
        let asset = AssetInfo {
            definition,
            mint_info: None,
        };
        stored.assets.insert(asset.clone());
        stored.assets.add_audit_key(audit_key.pub_key());
        stored
            .audit_keys
            .insert(audit_key.pub_key(), audit_key.clone());
        stored
            .freeze_keys
            .insert(freeze_key.pub_key(), freeze_key.clone());
        stored
            .user_keys
            .insert(user_key.address(), user_key.clone());
        {
            let mut storage =
                AtomicWalletStorage::<cap::Ledger, _>::new(&mut loader, 1024).unwrap();
            storage.store_asset(&asset).await.unwrap();
            storage
                .store_key(&RoleKeyPair::Auditor(audit_key))
                .await
                .unwrap();
            storage
                .store_key(&RoleKeyPair::Freezer(freeze_key))
                .await
                .unwrap();
            storage
                .store_key(&RoleKeyPair::User(user_key))
                .await
                .unwrap();
            storage.commit().await;
        }
        let loaded = {
            let mut storage = AtomicWalletStorage::new(&mut loader, 1024).unwrap();
            storage.load().await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        Ok(())
    }

    #[async_std::test]
    async fn test_revert() -> std::io::Result<()> {
        let (mut stored, mut loader, mut rng) = get_test_state("test_revert").await;

        // Make a change to one of the data structures, but revert it.
        let loaded = {
            let mut storage = AtomicWalletStorage::new(&mut loader, 1024).unwrap();
            storage.store_asset(&AssetInfo::native()).await.unwrap();
            storage.revert().await;
            // Make sure committing after a revert does not commit the reverted changes.
            storage.commit().await;
            storage.load().await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        // Change multiple data structures and revert.
        let loaded = {
            let mut storage = AtomicWalletStorage::new(&mut loader, 1024).unwrap();

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
            storage.store_asset(&AssetInfo::native()).await.unwrap();
            storage
                .store_key(&RoleKeyPair::Auditor(AuditorKeyPair::generate(&mut rng)))
                .await
                .unwrap();
            storage
                .store_key(&RoleKeyPair::Freezer(FreezerKeyPair::generate(&mut rng)))
                .await
                .unwrap();
            storage
                .store_key(&RoleKeyPair::User(user_key.clone()))
                .await
                .unwrap();
            storage
                .store_transaction(TransactionHistoryEntry {
                    time: Local::now(),
                    asset: AssetCode::native(),
                    kind: TransactionKind::<cap::Ledger>::send(),
                    sender: Some(user_key.address()),
                    receivers: vec![],
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

            // Commit after revert should be a no-op.
            storage.commit().await;
            storage.load().await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        Ok(())
    }
}
