// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! # The Seahorse cryptographic keystore library
//!
//! This crate provides a ledger-agnostic toolkit for building cryptographic keystores for
//! implementations of the [jf_cap] protocol.
//!
//! The main types that users of this crate will interact with are [Keystore] and [KeystoreBackend].
//! The former represents the generic keystore interface that this crate provides, including basic
//! keystore functionality like generating and viewing keys or sending and receiving assets. The
//! latter represents the interface to a specific ledger that the user must provide in order to
//! instantiate the ledger-agnostic [Keystore] interface for their particular system.
//!
//! Users should also be familiar with [reef], which provides traits to adapt a particular CAP
//! ledger to the ledger-agnostic interfaces defined here.
pub mod accounts;
pub mod assets;
pub mod cli;
pub mod encryption;
pub mod events;
pub mod hd;
pub mod io;
mod key_scan;
pub mod key_value_store;
pub mod ledger_state;
pub mod loader;
pub mod persistence;
pub mod reader;
pub mod records;
mod secret;
pub mod sparse_merkle_tree;
mod state;
#[cfg(any(test, bench, feature = "testing"))]
pub mod testing;
pub mod transactions;
pub mod txn_builder;

use crate::sparse_merkle_tree::SparseMerkleTree;
pub use crate::{
    assets::{Asset, AssetEditor, Assets, Icon, MintInfo},
    txn_builder::RecordAmount,
};
pub use jf_cap;
pub use reef;

use crate::{
    accounts::{Account, Accounts},
    assets::VerifiedAssetLibrary,
    encryption::Cipher,
    events::{EventIndex, EventSource, LedgerEvent},
    hd::KeyTree,
    key_scan::{receive_history_entry, BackgroundKeyScan, ScanOutputs},
    loader::KeystoreLoader,
    persistence::AtomicKeystoreStorage,
    records::{Record, Records},
    state::{
        KeystoreSharedState, KeystoreSharedStateReadGuard, KeystoreSharedStateRwLock,
        KeystoreSharedStateWriteGuard,
    },
    transactions::{Transaction, TransactionParams, Transactions},
    ledger_state::LedgerState,
    txn_builder::*,
};
use async_scoped::AsyncScope;
use async_std::task::sleep;
use async_trait::async_trait;
use atomic_store::{
    error::PersistenceError as ASPersistenceError, load_store::LoadStore, AtomicStore,
    AtomicStoreLoader,
};
use core::fmt::Debug;
use futures::{channel::oneshot, prelude::*, stream::Stream};
use jf_cap::{
    errors::TxnApiError,
    freeze::FreezeNote,
    keys::{
        FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair, UserPubKey, ViewerKeyPair,
        ViewerPubKey,
    },
    mint::MintNote,
    structs::{
        AssetCode, AssetDefinition, AssetPolicy, FreezeFlag, Nullifier, ReceiverMemo,
        RecordCommitment, RecordOpening,
    },
    transfer::TransferNote,
    MerkleLeafProof, MerklePath, MerkleTree, TransactionNote, VerKey,
};
use jf_primitives::aead;
use key_set::ProverKeySet;
use primitive_types::U256;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reef::{
    traits::{
        Block as _, NullifierSet as _, Transaction as _, TransactionKind as _,
        ValidationError as _, Validator as _,
    },
    TransactionKind, *,
};
use serde::{de::DeserializeOwned, Serialize};
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::iter::repeat;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum KeystoreError<L: Ledger> {
    UndefinedAsset {
        asset: AssetCode,
    },
    InvalidBlock {
        source: ValidationError<L>,
    },
    NullifierAlreadyPublished {
        nullifier: Nullifier,
    },
    BadMerkleProof {
        commitment: RecordCommitment,
        uid: u64,
    },
    TimedOut {},
    Cancelled {},
    CryptoError {
        source: TxnApiError,
    },
    InvalidAddress {
        address: UserAddress,
    },
    InconsistentAsset {
        expected: AssetDefinition,
    },
    AssetNotViewable {
        asset: AssetDefinition,
    },
    AssetNotFreezable {
        asset: AssetDefinition,
    },
    AssetNotMintable {
        asset: AssetDefinition,
    },
    ClientConfigError {
        source: <surf::Client as TryFrom<surf::Config>>::Error,
    },
    PersistenceError {
        source: atomic_store::error::PersistenceError,
    },
    IoError {
        source: std::io::Error,
    },
    BincodeError {
        source: bincode::Error,
    },
    EncryptionError {
        source: encryption::Error,
    },
    MnemonicError {
        source: bip0039::Error,
    },
    KeyError {
        source: argon2::Error,
    },
    KeyValueStoreError {
        source: crate::key_value_store::KeyValueStoreError,
    },
    NoSuchAccount {
        address: UserAddress,
    },
    CannotDecryptMemo {},
    TransactionError {
        source: crate::txn_builder::TransactionError,
    },
    UserKeyExists {
        pub_key: UserPubKey,
    },
    /// Attempted to load an asset library with an invalid signature.
    AssetVerificationError,
    #[snafu(display("{}", msg))]
    Failed {
        msg: String,
    },
    InvalidFreezerKey {
        key: FreezerPubKey,
    },
    InvalidViewerKey {
        key: ViewerPubKey,
    },
    ScanNotFound,
}

impl<L: Ledger> From<ASPersistenceError> for KeystoreError<L> {
    fn from(source: ASPersistenceError) -> Self {
        Self::PersistenceError { source }
    }
}

impl<L: Ledger> From<crate::txn_builder::TransactionError> for KeystoreError<L> {
    fn from(source: crate::txn_builder::TransactionError) -> Self {
        Self::TransactionError { source }
    }
}

impl<L: Ledger> From<bincode::Error> for KeystoreError<L> {
    fn from(source: bincode::Error) -> Self {
        Self::BincodeError { source }
    }
}

/// The interface required by the keystore from a specific network/ledger implementation.
///
/// This trait is the adapter for ledger-specific plugins into the ledger-agnostic [Keystore]
/// implementation. It provides an interface for the ledger-agnostic keystore to communicate with
/// remote network participants for a particular ledger. Implementing this trait for your specific
/// ledger enables the use of the full generic [Keystore] interface with your ledger.
#[async_trait]
pub trait KeystoreBackend<'a, L: Ledger>: Send {
    /// Notifications about ledger state changes.
    ///
    /// The keystore must be able to subscribe to a stream of events from the backend. These events
    /// occur whenever the ledger state changes, including new blocks being committed and owner
    /// memos being published. The backend may also include events when blocks are rejected. This is
    /// not required, but it can help the keystore report failures more quickly (if a rejection is not
    /// reported, the rejected transaction will eventually be considered timed out).
    ///
    /// Each event yielded by the stream must be tagged with an [EventSource] indicating where the
    /// event came from. Implementations of [KeystoreBackend] may provide events from multiple sources
    /// (for example, block events from a network query service and memo events from a centralized
    /// memo store) or they may aggregate all events into a single stream from a single source.
    type EventStream: 'a + Stream<Item = (LedgerEvent<L>, EventSource)> + Unpin + Send;

    /// Create a new keystore.
    ///
    /// This method should query the current state of the network (or at least some past state) and
    /// create a [LedgerState] consistent with that state. It must also persist the initial state by
    /// interacting with the storage layer directly.
    async fn create(&mut self) -> Result<LedgerState<'a, L>, KeystoreError<L>>;

    /// Subscribe to the asynchronous ledgerevent stream.
    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream;

    /// Find the public encryption key associated with the given address.
    ///
    /// Users in CAP are identified by addresses, but sending to a user also requires access to
    /// their public encryption key, for encrypting owner memos. This information must be published
    /// in some way, and accessed by the backend in this method.
    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, KeystoreError<L>>;

    /// Publish an encryption key so that other keystores can access it using [KeystoreBackend::get_public_key].
    async fn register_user_key(&mut self, pub_key: &UserKeyPair) -> Result<(), KeystoreError<L>>;

    /// Get a ledger state from which to start a scan.
    ///
    /// The backend must return the Merkle frontier at a time earlier than the `from` index, but it
    /// is not required to record the state at every event index, it may return an earlier Merkle
    /// frontier, such as the initial frontier. For this reason, the event index corresponding to
    /// the returned frontier is also returned.
    async fn get_initial_scan_state(
        &self,
        from: EventIndex,
    ) -> Result<(MerkleTree, EventIndex), KeystoreError<L>>;

    /// Determine whether a nullifier is spent and obtain a proof.
    ///
    /// `nullifiers` is a local cache of nullifiers. It may not contain a status or proof for every
    /// relevant nullifier. This function should check if `nullifier` is represented in
    /// `nullifiers` and query the network only if it is not. Optionally, this function may add the
    /// proof to the cache after obtaining a proof from the network.
    async fn get_nullifier_proof(
        &self,
        nullifiers: &mut NullifierSet<L>,
        nullifier: Nullifier,
    ) -> Result<(bool, NullifierProof<L>), KeystoreError<L>>;

    /// Submit a transaction to a validator.
    async fn submit(
        &mut self,
        note: reef::Transaction<L>,
        info: Transaction<L>,
    ) -> Result<(), KeystoreError<L>>;

    /// Record a finalized transaction.
    ///
    /// If successful, `txn_id` contains the block ID and index of the committed transaction.
    ///
    /// This function is optional and does nothing by default. The backend can override it to
    /// perform cleanup or post-processing on completed transactions.
    async fn finalize(&mut self, _txn: Transaction<L>, _txn_id: Option<(u64, u64)>)
    where
        L: 'static,
    {
    }
}

/// Transient state derived from the persistent [LedgerState].
pub struct KeystoreModel<
    'a,
    L: Ledger,
    Backend: KeystoreBackend<'a, L>,
    Meta: Serialize + DeserializeOwned + Send,
> {
    backend: Backend,
    atomic_store: AtomicStore,
    persistence: AtomicKeystoreStorage<'a, L, Meta>,
    assets: Assets,
    records: Records,
    transactions: Transactions<L>,
    /// Viewing accounts.
    viewing_accounts: Accounts<L, ViewerKeyPair>,
    /// Freezing accounts.
    freezing_accounts: Accounts<L, FreezerKeyPair>,
    /// Sending accounts, for spending owned records and receiving new records.
    ///
    /// Each public key in this set also includes a [UserAddress], which can be used to sign
    /// outgoing transactions, as well as an encryption public key used by other users to encrypt
    /// owner memos when sending records to this keystore.
    sending_accounts: Accounts<L, UserKeyPair>,
    viewer_key_stream: hd::KeyTree,
    user_key_stream: hd::KeyTree,
    freezer_key_stream: hd::KeyTree,
    rng: ChaChaRng,
    _marker: std::marker::PhantomData<&'a ()>,
    _marker2: std::marker::PhantomData<L>,
}

impl<'a, L: Ledger, Backend: KeystoreBackend<'a, L>, Meta: Serialize + DeserializeOwned + Send>
    KeystoreModel<'a, L, Backend, Meta>
{
    /// Access the persistent storage layer
    pub fn persistence(&self) -> &AtomicKeystoreStorage<'a, L, Meta> {
        &self.persistence
    }

    /// Access the persistent storage layer
    pub fn persistence_mut(&mut self) -> &mut AtomicKeystoreStorage<'a, L, Meta> {
        &mut self.persistence
    }

    /// Get the mutable assets.
    pub fn assets_mut(&mut self) -> &mut Assets {
        &mut self.assets
    }

    /// Get the list of assets.
    pub fn assets(&self) -> Vec<Asset> {
        self.assets.iter().collect()
    }

    /// Get an asset
    pub fn asset(&self, code: &AssetCode) -> Result<Asset, KeystoreError<L>> {
        self.assets.get(code)
    }

    /// Get the mutable viewing accounts.
    pub fn viewing_accounts_mut(&mut self) -> &mut Accounts<L, ViewerKeyPair> {
        &mut self.viewing_accounts
    }

    /// Get the mutable freezing accounts.
    pub fn freezing_accounts_mut(&mut self) -> &mut Accounts<L, FreezerKeyPair> {
        &mut self.freezing_accounts
    }

    /// Get the mutable sending accounts.
    pub fn sending_accounts_mut(&mut self) -> &mut Accounts<L, UserKeyPair> {
        &mut self.sending_accounts
    }
}

/// Import an unverified asset.
///
/// Note that this function cannot be used to import verified assets. Verified assets can only be
/// imported using [verify_assets], conditional on a signature check.
pub fn import_asset<'a, L: Ledger, Meta: Serialize + DeserializeOwned + Send>(
    model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
    asset: Asset,
) -> Result<(), KeystoreError<L>> {
    assert!(!asset.verified());
    model
        .assets
        .create_internal(
            asset.definition().clone(),
            asset.mint_info(),
            asset.verified(),
        )?
        .update_internal(asset)?
        .save()?;
    Ok(())
}

/// Load a verified asset library with its trusted signer.
pub fn verify_assets<'a, L: Ledger, Meta: Serialize + DeserializeOwned + Send>(
    model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
    trusted_signer: &VerKey,
    library: VerifiedAssetLibrary,
) -> Result<Vec<AssetDefinition>, KeystoreError<L>> {
    model.assets.verify_assets(trusted_signer, library)
}

// Trait used to indicate that an abstract return type captures a reference with the lifetime 'a.
// See https://stackoverflow.com/questions/50547766/how-can-i-get-impl-trait-to-use-the-appropriate-lifetime-for-a-mutable-reference
pub trait Captures<'a> {}
impl<'a, T: ?Sized> Captures<'a> for T {}

#[derive(Clone, Debug)]
struct EventSummary<L: Ledger> {
    updated_txns: Vec<(TransactionUID<L>, TransactionStatus)>,
    spent_nullifiers: Vec<(Nullifier, u64)>,
    rejected_nullifiers: Vec<Nullifier>,
    // Fee nullifiers of transactions which were retired immediately upon being received.
    retired_nullifiers: Vec<Nullifier>,
    received_memos: Vec<(ReceiverMemo, u64)>,
}

impl<L: Ledger> Default for EventSummary<L> {
    fn default() -> Self {
        Self {
            updated_txns: Default::default(),
            spent_nullifiers: Default::default(),
            rejected_nullifiers: Default::default(),
            retired_nullifiers: Default::default(),
            received_memos: Default::default(),
        }
    }
}

/// The generic CAP keystore implementation.
///
/// It is a soundness requirement that the destructor of a [Keystore] run when the [Keystore] is
/// dropped. Therefore, [std::mem::forget] must not be used to forget a [Keystore] without running its
/// destructor.
pub struct Keystore<
    'a,
    Backend: KeystoreBackend<'a, L>,
    L: Ledger,
    Meta: Serialize + DeserializeOwned + Send,
> {
    // Data shared between the main thread and the event handling thread:
    //  * the trusted, persistent keystore state
    //  * the trusted, ephemeral keystore model
    //  * promise completion handles for futures returned by sync(), indexed by the timestamp at
    //    which the corresponding future is supposed to complete. Handles are added in sync() (main
    //    thread) and removed and completed in the event thread
    mutex: Arc<KeystoreSharedStateRwLock<'a, L, Backend, Meta>>,
    // Handle for the background tasks running the event handling loop and retroactive ledger scans.
    // When dropped, this handle will cancel the tasks.
    task_scope: AsyncScope<'a, ()>,
}

#[derive(Clone)]
pub struct EncryptingResourceAdapter<T> {
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

    fn load(&self, stream: &[u8]) -> Result<Self::ParamType, ASPersistenceError> {
        let ciphertext = bincode::deserialize(stream)
            .map_err(|source| ASPersistenceError::BincodeDe { source })?;
        let plaintext =
            self.cipher
                .decrypt(&ciphertext)
                .map_err(|err| ASPersistenceError::OtherLoad {
                    inner: Box::new(err),
                })?;
        bincode::deserialize(&plaintext).map_err(|source| ASPersistenceError::BincodeDe { source })
    }

    fn store(&mut self, param: &Self::ParamType) -> Result<Vec<u8>, ASPersistenceError> {
        let plaintext = bincode::serialize(param)
            .map_err(|source| ASPersistenceError::BincodeSer { source })?;
        let ciphertext =
            self.cipher
                .encrypt(&plaintext)
                .map_err(|err| ASPersistenceError::OtherStore {
                    inner: Box::new(err),
                })?;
        bincode::serialize(&ciphertext).map_err(|source| ASPersistenceError::BincodeSer { source })
    }
}

pub struct KeystoreResources<
    'a,
    L: 'static + Ledger,
    Meta: 'a + Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq,
> {
    atomic_store: AtomicStore,
    persistence: AtomicKeystoreStorage<'a, L, Meta>,
    assets: Assets,
    transactions: Transactions<L>,
    records: Records,
    viewing_accounts: Accounts<L, ViewerKeyPair>,
    freezing_accounts: Accounts<L, FreezerKeyPair>,
    sending_accounts: Accounts<L, UserKeyPair>,
}

impl<
        'a,
        L: 'static + Ledger,
        Meta: 'a + Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq,
    > KeystoreResources<'a, L, Meta>
{
    async fn commit(&mut self) -> Result<(), KeystoreError<L>> {
        self.persistence.commit().await;
        self.assets.commit()?;
        self.transactions.commit()?;
        self.records.commit()?;
        self.viewing_accounts.commit()?;
        self.freezing_accounts.commit()?;
        self.sending_accounts.commit()?;
        self.atomic_store.commit_version()?;
        Ok(())
    }
}

// Fun fact: replacing `std::pin::Pin` with `Pin` and adding `use std::pin::Pin` causes the compiler
// to panic where this type alias is used in `Keystore::new`. As a result, the type alias `BoxFuture`
// from `futures::future` does not work, so we define our own.
type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// `SendFuture` trait is needed for the cape repo to compile when calling key generation functions,
// `generate_viewing_account`, `generate_freezing_account`, and `generate_sending_account`.
//
// Workaround:
// 1. Wrap code of the key generation functions with `async move` to fix the implementation "not
// general enough" error.
// 2. Add a function lifetime `'l` and capture the lifetime `'a` of `self` with the `Captures` trait
// to avoid conflicting lifetime requirements.
// 3. Wrap the return type with `Box<dyn>` to resolve the failure during "building vtable
// representation", and add the `SendFuture` trait to combine `Future` and `Captures` since `dyn`
// can only take one non-auto trait.
//
// Related issues:
// https://github.com/rust-lang/rust/issues/89657, https://github.com/rust-lang/rust/issues/90691.
pub trait SendFuture<'a, T>: Future<Output = T> + Captures<'a> + Send {}
impl<'a, T, F: Future<Output = T> + Captures<'a> + Send> SendFuture<'a, T> for F {}

impl<
        'a,
        L: 'static + Ledger,
        Backend: 'a + KeystoreBackend<'a, L> + Send + Sync,
        Meta: 'a + Serialize + DeserializeOwned + Send + Sync + Clone + PartialEq,
    > Keystore<'a, Backend, L, Meta>
{
    pub fn create_stores(
        loader: &mut impl KeystoreLoader<L, Meta = Meta>,
    ) -> Result<KeystoreResources<'a, L, Meta>, KeystoreError<L>> {
        let mut atomic_loader = AtomicStoreLoader::load(&loader.location(), "keystore").unwrap();
        let file_fill_size = 1024;
        let persistence = AtomicKeystoreStorage::new(loader, &mut atomic_loader, file_fill_size)?;
        let adaptor = persistence.encrypting_storage_adapter::<()>();
        let assets = Assets::new(&mut atomic_loader, adaptor.cast(), file_fill_size)?;
        let transactions = Transactions::new(&mut atomic_loader, adaptor.cast(), file_fill_size)?;
        let records = Records::new(&mut atomic_loader, adaptor.cast(), file_fill_size)?;
        let viewing_accounts = Accounts::new(
            &mut atomic_loader,
            adaptor.cast(),
            "viewing",
            file_fill_size,
        )?;
        let freezing_accounts = Accounts::new(
            &mut atomic_loader,
            adaptor.cast(),
            "freezing",
            file_fill_size,
        )?;
        let sending_accounts = Accounts::new(
            &mut atomic_loader,
            adaptor.cast(),
            "sending",
            file_fill_size,
        )?;
        let atomic_store = AtomicStore::open(atomic_loader)?;
        Ok(KeystoreResources {
            atomic_store,
            persistence,
            assets,
            transactions,
            records,
            viewing_accounts,
            freezing_accounts,
            sending_accounts,
        })
    }

    // This function suffers from github.com/rust-lang/rust/issues/89657, in which, if we define it
    // as an async function, the compiler loses track of the fact that the resulting opaque Future
    // implements Send, even though it does. Unfortunately, the workaround used for some other
    // functions in this module (c.f. `submit_elaborated_transaction`) where we manually desugar the
    // function signature to explicitly return `impl Future + Send` triggers a separate and possibly
    // unrelated compiler bug, which results in a panic during compilation.
    //
    // Fortunately, there is a different workaround which does work. The idea is the same: to
    // manually write out the opaque return type so that we can explicitly add the `Send` bound. The
    // difference is that we use dynamic type erasure (Pin<Box<dyn Future>>) instead of static type
    // erasure. I don't know why this doesn't crash the compiler, but it doesn't.
    pub fn new(
        mut backend: Backend,
        loader: &mut impl KeystoreLoader<L, Meta = Meta>,
    ) -> BoxFuture<'a, Result<Keystore<'a, Backend, L, Meta>, KeystoreError<L>>> {
        let mut resources = Self::create_stores(loader).unwrap();
        Box::pin(async move {
            let state = if resources.persistence.exists() {
                resources.persistence.load().await?
            } else {
                let state: LedgerState<'a, L> = backend.create().await?;
                resources.persistence.create(&state).await?;
                state
            };
            resources.commit().await?;
            Self::new_impl(backend, resources, state).await
        })
    }

    #[cfg(any(test, bench, feature = "testing"))]
    pub fn with_state_and_keys(
        backend: Backend,
        loader: &mut (impl 'a + KeystoreLoader<L, Meta = Meta>),
        state: LedgerState<'a, L>,
        viewing_key: Option<(ViewerKeyPair, String)>,
        freezing_key: Option<(FreezerKeyPair, String)>,
        sending_key: Option<(UserKeyPair, String)>,
    ) -> BoxFuture<'a, Result<Keystore<'a, Backend, L, Meta>, KeystoreError<L>>> {
        let mut resources = Self::create_stores(loader).unwrap();
        if let Some((key, description)) = viewing_key {
            resources
                .viewing_accounts
                .create(key, None)
                .unwrap()
                .with_description(description)
                .save()
                .unwrap();
        }
        if let Some((key, description)) = freezing_key {
            resources
                .freezing_accounts
                .create(key, None)
                .unwrap()
                .with_description(description)
                .save()
                .unwrap();
        }
        if let Some((key, description)) = sending_key {
            resources
                .sending_accounts
                .create(key, None)
                .unwrap()
                .with_description(description)
                .save()
                .unwrap();
        }
        Box::pin(async move {
            resources.persistence.create(&state).await?;
            resources.commit().await?;
            Self::new_impl(backend, resources, state).await
        })
    }

    async fn new_impl(
        backend: Backend,
        resources: KeystoreResources<'a, L, Meta>,
        state: LedgerState<'a, L>,
    ) -> Result<Keystore<'a, Backend, L, Meta>, KeystoreError<L>> {
        let mut events = backend.subscribe(state.now(), None).await;
        let mut key_scans = vec![];
        for account in resources.viewing_accounts.iter() {
            if let Some(scan) = &account.scan() {
                key_scans.push((
                    scan.address(),
                    backend.subscribe(scan.next_event(), None).await,
                ));
            }
        }
        let key_tree = resources.persistence.key_stream();
        let mut model = KeystoreModel {
            backend,
            atomic_store: resources.atomic_store,
            persistence: resources.persistence,
            assets: resources.assets,
            transactions: resources.transactions,
            records: resources.records,
            viewing_accounts: resources.viewing_accounts,
            freezing_accounts: resources.freezing_accounts,
            sending_accounts: resources.sending_accounts,
            viewer_key_stream: key_tree.derive_sub_tree("viewer".as_bytes()),
            freezer_key_stream: key_tree.derive_sub_tree("freezer".as_bytes()),
            user_key_stream: key_tree.derive_sub_tree("user".as_bytes()),
            rng: ChaChaRng::from_entropy(),
            _marker: Default::default(),
            _marker2: Default::default(),
        };
        // Ensure the native asset type is always recognized.
        model.assets_mut().create_native()?;

        let mutex = Arc::new(KeystoreSharedStateRwLock::new(
            state,
            model,
            key_scans.iter().map(|(key, _)| key.clone()),
        ));
        let mut scope = unsafe {
            // Creating an AsyncScope is considered unsafe because `std::mem::forget` is allowed
            // in safe code, and forgetting an AsyncScope can allow its inner futures to
            // continue to be scheduled to run after the lifetime of the scope ends, since
            // normally the destructor of the scope ensures that its futures are driven to
            // completion before its lifetime ends.
            //
            // Since we are immediately going to store `scope` in the resulting `Keystore`, its
            // lifetime will be the same as the `Keystore`, and its destructor will run as long as
            // no one calls `forget` on the `Keystore` -- which no one should ever have any reason
            // to.
            AsyncScope::create()
        };

        // Start the event loop.
        {
            let mutex = mutex.clone();
            scope.spawn_cancellable(
                async move {
                    while let Some((event, source)) = events.next().await {
                        while let Err(err) = mutex
                            .write()
                            .await
                            .update(|state| update_ledger(event.clone(), source, state).boxed())
                            .await
                        {
                            tracing::error!("error while scanning ledger, retrying: {}", err);
                            // Sleep a little bit before retrying, so that if the error is
                            // persistent, we don't obnoxiously spam the logs or hog the mutex.
                            sleep(Duration::from_secs(5)).await;
                        }
                    }
                },
                || (),
            );
        };

        let mut keystore = Self {
            mutex,
            task_scope: scope,
        };

        // Spawn background tasks for any scans which were in progress when the keystore was last
        // shut down.
        for (key, events) in key_scans {
            keystore.spawn_key_scan(key, events).await;
        }

        Ok(keystore)
    }

    /// Access the shared state directly.
    pub async fn write(&self) -> KeystoreSharedStateWriteGuard<'_, 'a, L, Backend, Meta> {
        self.mutex.write().await
    }

    /// Access the shared state directly.
    pub async fn read(&self) -> KeystoreSharedStateReadGuard<'_, 'a, L, Backend, Meta> {
        self.mutex.read().await
    }

    /// Get the viewing public keys.
    pub async fn viewing_pub_keys(&self) -> Vec<ViewerPubKey> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.viewing_accounts.iter_pub_keys().collect()
    }

    /// Get the freezing public keys.
    pub async fn freezing_pub_keys(&self) -> Vec<FreezerPubKey> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.freezing_accounts.iter_pub_keys().collect()
    }

    /// Get the sending addresses.
    pub async fn sending_addresses(&self) -> Vec<UserAddress> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.sending_accounts.iter_pub_keys().collect()
    }

    /// Get the sending keys.
    pub async fn sending_keys(&self) -> Vec<UserKeyPair> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.sending_accounts.iter_keys().collect()
    }

    /// Get the viewing account by the public key.
    pub async fn viewing_account(
        &self,
        pub_key: &ViewerPubKey,
    ) -> Result<Account<L, ViewerKeyPair>, KeystoreError<L>> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.viewing_accounts.get(pub_key)
    }

    /// Get the freezing account by the public key.
    pub async fn freezing_account(
        &self,
        pub_key: &FreezerPubKey,
    ) -> Result<Account<L, FreezerKeyPair>, KeystoreError<L>> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.freezing_accounts.get(pub_key)
    }

    /// Get the sending account by the address.
    pub async fn sending_account(
        &self,
        address: &UserAddress,
    ) -> Result<Account<L, UserKeyPair>, KeystoreError<L>> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.sending_accounts.get(address)
    }

    /// Compute the spendable balance of the given asset type owned by all addresses.
    pub async fn balance(&self, asset: &AssetCode) -> U256 {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        state.balance(
            model,
            model.sending_accounts.iter_pub_keys(),
            asset,
            FreezeFlag::Unfrozen,
        )
    }

    /// Compute the spendable balance of the given asset type owned by the given address.
    pub async fn balance_breakdown(&self, address: &UserAddress, asset: &AssetCode) -> U256 {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        match model.sending_accounts.get(address) {
            Ok(account) => {
                state.balance_breakdown(model, &account.pub_key(), asset, FreezeFlag::Unfrozen)
            }
            _ => U256::zero(),
        }
    }

    /// Compute the balance frozen records of the given asset type owned by the given address.
    pub async fn frozen_balance_breakdown(&self, address: &UserAddress, asset: &AssetCode) -> U256 {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        match model.sending_accounts.get(address) {
            Ok(account) => {
                state.balance_breakdown(model, &account.pub_key(), asset, FreezeFlag::Frozen)
            }
            _ => U256::zero(),
        }
    }

    /// List records owned or viewable by this keystore.
    pub async fn records(&self) -> Vec<Record> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.records.iter().collect::<Vec<_>>()
    }

    /// List assets discovered or imported by this keystore.
    pub async fn assets(&self) -> Vec<Asset> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.assets()
    }

    /// Get details about an asset type using its code.
    pub async fn asset(&self, code: AssetCode) -> Option<Asset> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.asset(&code).ok()
    }

    /// List past transactions involving this keystore.
    #[allow(clippy::type_complexity)]
    pub fn transaction_history<'l>(
        &'l self,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<Vec<Transaction<L>>, KeystoreError<L>>> + 'l>>
    {
        Box::pin(async move {
            let KeystoreSharedState { model, .. } = &*self.read().await;
            let mut history = model.transactions.iter().collect::<Vec<_>>();
            history.sort_by_key(|txn| *txn.created_time());
            Ok(history)
        })
    }

    /// Basic transfer without customization.
    ///
    /// To add transfer size requirement, call [Keystore::build_transfer] with a specified
    /// `xfr_size_requirement`.
    ///
    /// `sender`
    /// * If provided, only this address will be used to transfer the asset.
    /// * Otherwise, all the owned addresses can be used for the transfer.
    ///
    pub async fn transfer(
        &mut self,
        sender: Option<&UserAddress>,
        asset: &AssetCode,
        receivers: &[(UserPubKey, impl Clone + Into<RecordAmount>)],
        fee: impl Into<RecordAmount>,
    ) -> Result<TransactionUID<L>, KeystoreError<L>> {
        let receivers = receivers
            .iter()
            .map(|(addr, amount)| (addr.clone(), amount.clone().into(), false))
            .collect::<Vec<_>>();
        let (note, info) = self
            .build_transfer(sender, asset, &receivers, fee.into(), vec![], None)
            .await?;
        self.submit_cap(TransactionNote::Transfer(Box::new(note)), info)
            .await
    }

    /// Build a transfer with full customization.
    ///
    /// `receivers`: list of (receiver address, amount, burn)
    pub async fn build_transfer(
        &mut self,
        sender: Option<&UserAddress>,
        asset: &AssetCode,
        receivers: &[(UserPubKey, impl Clone + Into<RecordAmount>, bool)],
        fee: impl Into<RecordAmount>,
        bound_data: Vec<u8>,
        xfr_size_requirement: Option<(usize, usize)>,
    ) -> Result<(TransferNote, TransactionParams<L>), KeystoreError<L>> {
        // Convert amounts to `RecordAmount`.
        let fee = fee.into();
        let receivers = receivers
            .iter()
            .map(|(key, amt, burn)| (key.clone(), amt.clone().into(), *burn))
            .collect::<Vec<_>>();

        self.write()
            .await
            .update(|KeystoreSharedState { state, model, .. }| {
                async move {
                    let sender_key_pairs = match sender {
                        Some(addr) => {
                            vec![model.sending_accounts.get(addr)?.key().clone()]
                        }
                        None => model.sending_accounts.iter_keys().collect(),
                    };
                    let spec = TransferSpec {
                        sender_key_pairs: &sender_key_pairs,
                        asset,
                        receivers: &receivers,
                        fee,
                        bound_data,
                        xfr_size_requirement,
                    };
                    state.build_transfer(model, spec)
                }
                .boxed()
            })
            .await
    }

    /// Submit a transaction to be validated.
    ///
    /// This function allows any kind of transaction to be submitted, even ledger-specific
    /// transaction types that are not part of the base CAP protocol.
    pub async fn submit(
        &mut self,
        txn: reef::Transaction<L>,
        info: TransactionParams<L>,
    ) -> Result<TransactionUID<L>, KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { state, model, .. }| {
                state
                    .submit_elaborated_transaction(model, txn, Some(info))
                    .boxed()
            })
            .await
    }

    /// Submit a CAP transaction to be validated.
    pub async fn submit_cap(
        &mut self,
        txn: TransactionNote,
        info: TransactionParams<L>,
    ) -> Result<TransactionUID<L>, KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { state, model, .. }| {
                state.submit_transaction(model, txn, info).boxed()
            })
            .await
    }

    /// Define a new asset and store secret info for minting.
    pub async fn define_asset(
        &mut self,
        name: String,
        description: &[u8],
        policy: AssetPolicy,
    ) -> Result<AssetDefinition, KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { state, model, .. }| {
                state.define_asset(model, name, description, policy)
            })
            .await
    }

    /// Import an asset.
    ///
    /// Note that this function cannot be used to import verified assets. If the `verified` flag is
    /// set on `asset`, it will simply be ignored. Verified assets can only be imported using
    /// [Keystore::verify_assets], conditional on a signature check.
    pub async fn import_asset(&mut self, asset: Asset) -> Result<(), KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { model, .. }| async move { import_asset(model, asset) })
            .await
    }

    /// Load a verified asset library from a file or byte stream.
    ///
    /// `trusted_signer` must be the public key of an entity trusted by this application to verify
    /// assets. It must also be the public key which was used to sign `library`.
    ///
    /// If successful, the asset definitions loaded from `library` are returned and their codes are
    /// added to this keystore's set of verified asset codes. Note that assets loaded from a
    /// verified library are not persisted (unless the same assets are imported as unverified using
    /// [Keystore::import_asset]) in order to preserve the verified library as the single source of
    /// truth about verified assets. Therefore, this function must be called each time a keystore
    /// is created or opened in order to ensure that the verified assets show up in the keystore's
    /// verified set.
    pub async fn verify_assets(
        &mut self,
        trusted_signer: &VerKey,
        library: VerifiedAssetLibrary,
    ) -> Result<Vec<AssetDefinition>, KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { model, .. }| async move {
                verify_assets(model, trusted_signer, library)
            })
            .await
    }

    /// Add a viewing key to the keystore's key set.
    pub fn add_viewing_account<'l>(
        &'l mut self,
        viewing_key: ViewerKeyPair,
        description: String,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<(), KeystoreError<L>>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            self.write()
                .await
                .update(|KeystoreSharedState { state, model, .. }| {
                    state.add_viewing_account(model, Some(viewing_key), description)
                })
                .await?;
            Ok(())
        })
    }

    /// Generate a new viewing key and add it to the keystore's key set.
    pub fn generate_viewing_account<'l>(
        &'l mut self,
        description: String,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<ViewerPubKey, KeystoreError<L>>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            self.write()
                .await
                .update(|KeystoreSharedState { state, model, .. }| async move {
                    Ok(state
                        .add_viewing_account(model, None, description)
                        .await?
                        .pub_key())
                })
                .await
        })
    }

    /// Add a freezing key to the keystore's key set.
    pub fn add_freezing_account<'l>(
        &'l mut self,
        freeze_key: FreezerKeyPair,
        description: String,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<(), KeystoreError<L>>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            self.write()
                .await
                .update(|KeystoreSharedState { state, model, .. }| {
                    state.add_freezing_account(model, Some(freeze_key), description)
                })
                .await?;
            Ok(())
        })
    }

    /// Generate a new freezing key and add it to the keystore's key set.
    pub fn generate_freezing_account<'l>(
        &'l mut self,
        description: String,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<FreezerPubKey, KeystoreError<L>>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            self.write()
                .await
                .update(|KeystoreSharedState { state, model, .. }| async move {
                    Ok(state
                        .add_freezing_account(model, None, description)
                        .await?
                        .pub_key())
                })
                .await
        })
    }

    /// Add a sending key to the keystore's key set.
    ///
    /// Since this key was not generated by this keystore, it may have already been used and thus may
    /// own existing records. The keystore will start a scan of the ledger in the background to find
    /// records owned by this key. The scan will start from the event specified by `scan_from`.
    pub fn add_sending_account<'l>(
        &'l mut self,
        user_key: UserKeyPair,
        description: String,
        scan_from: EventIndex,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<(), KeystoreError<L>>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            let (user_key, events) = self
                .write()
                .await
                .update(
                    |KeystoreSharedState {
                         state,
                         model,
                         pending_key_scans,
                         ..
                     }| async move {
                        let (user_key, events) = state
                            .add_sending_account(
                                model,
                                Some(user_key),
                                description,
                                Some(scan_from),
                            )
                            .await?;
                        // Register the key scan in `pending_key_scans` so that `await_key_scan`
                        // will work.
                        pending_key_scans.insert(user_key.address(), vec![]);
                        Ok((user_key, events))
                    },
                )
                .await?;

            if let Some(events) = events {
                // Start a background task to scan for records belonging to the new key.
                self.spawn_key_scan(user_key.address(), events).await;
            }

            Ok(())
        })
    }

    /// Generate a new sending key and add it to the keystore's key set.
    ///
    /// Keys are generated deterministically based on the mnemonic phrase used to load the keystore.
    /// If this is a recovery of an HD keystore from a mnemonic phrase, `scan_from` can be used to
    /// initiate a background scan of the ledger from the given event index to find records already
    /// belonging to the new key.
    pub fn generate_sending_account<'l>(
        &'l mut self,
        description: String,
        scan_from: Option<EventIndex>,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<UserPubKey, KeystoreError<L>>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            let (user_key, events) = {
                self.write()
                    .await
                    .update(
                        |KeystoreSharedState {
                             state,
                             model,
                             pending_key_scans,
                             ..
                         }| async move {
                            let (user_key, events) = state
                                .add_sending_account(model, None, description, scan_from)
                                .await?;
                            // Register the key scan in `pending_key_scans` so that `await_key_scan`
                            // will work.
                            pending_key_scans.insert(user_key.address(), vec![]);
                            Ok((user_key, events))
                        },
                    )
                    .await?
            };

            if let Some(events) = events {
                // Start a background task to scan for records belonging to the new key.
                self.spawn_key_scan(user_key.address(), events).await;
            }

            Ok(user_key.pub_key())
        })
    }

    /// Manually add an encrypted record.
    ///
    /// This can be used to access assets more quickly than waiting for a ledger scan when
    /// recovering a keystore.
    pub async fn import_memo(
        &mut self,
        memo: ReceiverMemo,
        comm: RecordCommitment,
        uid: u64,
        proof: MerklePath,
    ) -> Result<(), KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { state, model, .. }| {
                state.import_memo(model, memo, comm, uid, proof)
            })
            .await
    }

    /// Create a mint note that assigns an asset to an owner.
    pub async fn build_mint(
        &mut self,
        minter: Option<&UserAddress>,
        fee: impl Into<RecordAmount>,
        asset_code: &AssetCode,
        amount: impl Into<RecordAmount>,
        receiver: UserPubKey,
    ) -> Result<(MintNote, TransactionParams<L>), KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { state, model, .. }| {
                state.build_mint(
                    model,
                    minter,
                    fee.into(),
                    asset_code,
                    amount.into(),
                    receiver,
                )
            })
            .await
    }

    /// Build and submit a mint transaction.
    ///
    /// See [Keystore::build_mint].
    pub async fn mint(
        &mut self,
        minter: Option<&UserAddress>,
        fee: impl Into<RecordAmount>,
        asset_code: &AssetCode,
        amount: impl Into<RecordAmount>,
        receiver: UserPubKey,
    ) -> Result<TransactionUID<L>, KeystoreError<L>> {
        let (note, info) = self
            .build_mint(minter, fee.into(), asset_code, amount.into(), receiver)
            .await?;
        self.submit_cap(TransactionNote::Mint(Box::new(note)), info)
            .await
    }

    /// Build a transaction to freeze at least `amount` of a particular asset owned by a given user.
    ///
    /// In order to freeze an asset, this keystore must be a viewer of that asset type, and it must
    /// have observed enough transactions to determine that the target user owns at least `amount`
    /// of that asset.
    ///
    /// Freeze transactions do not currently support change, so the amount frozen will be at least
    /// `amount` but might be more, depending on the distribution of the freezable records we have
    /// for the target user.
    ///
    /// Some of these restrictions will be rolled back in the future:
    /// * An API can be provided for freezing without being a viewer, if a freezable record
    ///   opening is provided to us out of band by a viewer.
    /// * [Keystore::build_freeze] uses the same allocation scheme for input records as
    ///   [Keystore::build_transfer], which tries to minimize fragmentation. But freeze transactions
    ///   do not increase fragmentation because they have no change output, so we could use a
    ///   different allocation scheme that tries to minimize change, which would limit the amount we
    ///   can over-freeze, and would guarantee that we freeze the exact amount if it is possible to
    ///   make exact change with the freezable records we have.
    pub async fn build_freeze(
        &mut self,
        freezer: Option<&UserAddress>,
        fee: impl Into<RecordAmount>,
        asset: &AssetCode,
        amount: impl Into<U256>,
        owner: UserAddress,
    ) -> Result<(FreezeNote, TransactionParams<L>), KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { state, model, .. }| {
                state.build_freeze(
                    model,
                    freezer,
                    fee.into(),
                    asset,
                    amount.into(),
                    owner,
                    FreezeFlag::Frozen,
                )
            })
            .await
    }

    /// Build an submit a freeze transaction.
    ///
    /// See [Keystore::build_freeze].    
    pub async fn freeze(
        &mut self,
        freezer: Option<&UserAddress>,
        fee: impl Into<RecordAmount>,
        asset: &AssetCode,
        amount: impl Into<U256>,
        owner: UserAddress,
    ) -> Result<TransactionUID<L>, KeystoreError<L>> {
        let (note, info) = self
            .build_freeze(freezer, fee.into(), asset, amount.into(), owner)
            .await?;
        self.submit_cap(TransactionNote::Freeze(Box::new(note)), info)
            .await
    }

    /// Build a transaction to unfreeze at least `amount` of a particular asset owned by a given user.
    ///
    /// In order to unfreeze, this keystore must have previously been used to freeze at least `amount`
    /// of the target's assets.
    pub async fn build_unfreeze(
        &mut self,
        freezer: Option<&UserAddress>,
        fee: impl Into<RecordAmount>,
        asset: &AssetCode,
        amount: impl Into<U256>,
        owner: UserAddress,
    ) -> Result<(FreezeNote, TransactionParams<L>), KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { state, model, .. }| {
                state.build_freeze(
                    model,
                    freezer,
                    fee.into(),
                    asset,
                    amount.into(),
                    owner,
                    FreezeFlag::Unfrozen,
                )
            })
            .await
    }

    /// Build and submit an unfreeze transaction.
    ///
    /// See [Keystore::build_unfreeze].
    pub async fn unfreeze(
        &mut self,
        freezer: Option<&UserAddress>,
        fee: impl Into<RecordAmount>,
        asset: &AssetCode,
        amount: impl Into<U256>,
        owner: UserAddress,
    ) -> Result<TransactionUID<L>, KeystoreError<L>> {
        let (note, info) = self
            .build_unfreeze(freezer, fee.into(), asset, amount.into(), owner)
            .await?;
        self.submit_cap(TransactionNote::Freeze(Box::new(note)), info)
            .await
    }

    /// Get the status of a transaction.
    pub async fn transaction_status(
        &self,
        uid: &TransactionUID<L>,
    ) -> Result<TransactionStatus, KeystoreError<L>> {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        Ok(model.transactions.get(uid)?.status())
    }

    /// A future which completes when the transaction is finalized (committed or rejected).
    /// Works only for transactions we submitted
    pub async fn await_transaction(
        &self,
        uid: &TransactionUID<L>,
    ) -> Result<TransactionStatus, KeystoreError<L>> {
        // Check the status of the transaction. `res` will be `Ok(status)` if the transaction has
        // already completed, or `Err(receiver)` with a `oneshot::Receiver` to wait on if the
        // transaction is not ready yet.
        let res = {
            self.write()
                .await
                .update(
                    |KeystoreSharedState {
                         model,
                         txn_subscribers,
                         ..
                     }| async move {
                        let status = model.transactions.get(uid)?.status();
                        if status.is_final() {
                            Ok(Ok(status))
                        } else {
                            let (sender, receiver) = oneshot::channel();
                            txn_subscribers
                                .entry(uid.clone())
                                .or_insert_with(Vec::new)
                                .push(sender);
                            Ok(Err(receiver))
                        }
                    },
                )
                .await?
        };
        match res {
            Ok(status) => Ok(status),
            Err(receiver) => receiver.await.map_err(|_| KeystoreError::<L>::Cancelled {}),
        }
    }

    /// A future which completes when the keystore has processed events at least including `t`.
    pub async fn sync(&self, t: EventIndex) -> Result<(), KeystoreError<L>> {
        // Check the current event index. `receiver` will be `None` if the event index `t` has
        // already passed, or `Some(receiver)` with a `oneshot::Receiver` to wait on if `t` is in
        // the future.
        let receiver = {
            self.write()
                .await
                .update(
                    |KeystoreSharedState {
                         state,
                         sync_handles,
                         ..
                     }| async move {
                        // It's important that we do the comparison this way (now >= t) rather than
                        // comparing now < t and switching the branches of the `if`. This is because
                        // the partial order of EventIndex tells us when _all_ event streams in
                        // `now` are at an index >= t, which is the terminating condition for
                        // `sync()`: it should wait until _all_ event streams have been processed at
                        // least to time `t`.
                        if state.now() >= t {
                            Ok(None)
                        } else {
                            let (sender, receiver) = oneshot::channel();
                            sync_handles.push((t, sender));
                            Ok(Some(receiver))
                        }
                    },
                )
                .await?
        };
        match receiver {
            Some(receiver) => receiver.await.map_err(|_| KeystoreError::Cancelled {}),
            None => Ok(()),
        }
    }

    /// The index of the most recently processed event.
    pub async fn now(&self) -> EventIndex {
        self.read().await.state.now()
    }

    /// A future which completes when the keystore has processed at least as many events as `peer`.
    pub async fn sync_with_peer(&self, peer: &Self) -> Result<(), KeystoreError<L>> {
        self.sync(peer.now().await).await
    }

    /// A future which completes when there are no more in-progress ledger scans for `address`.
    pub async fn await_key_scan(&self, address: &UserAddress) -> Result<(), KeystoreError<L>> {
        let receiver = {
            self.write()
                .await
                .update(
                    |KeystoreSharedState {
                         pending_key_scans, ..
                     }| async move {
                        let senders = match pending_key_scans.get_mut(address) {
                            Some(senders) => senders,
                            // If there is not an in-progress scan for this key, return immediately.
                            None => return Ok(None),
                        };
                        let (sender, receiver) = oneshot::channel();
                        senders.push(sender);
                        Ok(Some(receiver))
                    },
                )
                .await?
        };
        match receiver {
            Some(receiver) => receiver.await.map_err(|_| KeystoreError::Cancelled {}),
            None => Ok(()),
        }
    }

    async fn spawn_key_scan(
        &mut self,
        address: UserAddress,
        mut events: impl 'a + Stream<Item = (LedgerEvent<L>, EventSource)> + Unpin + Send,
    ) {
        let mutex = self.mutex.clone();
        self.task_scope.spawn_cancellable(
            async move {
                let mut finished = false;
                while !finished {
                    let (next_event, source) = events.next().await.unwrap();
                    loop {
                        match mutex
                            .write()
                            .await
                            .update(|state| {
                                update_key_scan(&address, next_event.clone(), source, state).boxed()
                            })
                            .await
                        {
                            Ok(f) => {
                                finished = f;
                                break;
                            }
                            Err(err) => {
                                tracing::error!("error during key scan, retrying: {}", err);
                                // Sleep a little bit before retrying, so that if the error is
                                // persistent, we don't obnoxiously spam the logs or hog the mutex.
                                sleep(Duration::from_secs(5)).await;
                            }
                        }
                    }
                }
            },
            || (),
        );
    }

    /// Insert an asset for testing purposes.
    #[cfg(any(test, feature = "testing"))]
    pub async fn insert_asset(&mut self, asset: Asset) -> Result<(), KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { model, .. }| async move {
                model.assets_mut().insert(asset)?.save()?;
                Ok(())
            })
            .await
    }

    /// Create an asset for testing purposes.
    #[cfg(any(test, feature = "testing"))]
    pub async fn create_asset(
        &mut self,
        definition: AssetDefinition,
        name: Option<String>,
        description: Option<String>,
        icon: Option<Icon>,
        mint_info: Option<MintInfo>,
    ) -> Result<(), KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { model, .. }| async move {
                model
                    .assets_mut()
                    .create(definition, mint_info)?
                    .set_name(name)
                    .set_description(description)
                    .set_icon(icon)
                    .save::<L>()?;
                Ok(())
            })
            .await
    }

    /// Create a native asset for testing purposes.
    #[cfg(any(test, feature = "testing"))]
    pub async fn create_native_asset(
        &mut self,
        icon: Option<Icon>,
    ) -> Result<(), KeystoreError<L>> {
        self.write()
            .await
            .update(|KeystoreSharedState { model, .. }| async move {
                model
                    .assets_mut()
                    .create_native()?
                    .set_icon(icon)
                    .save::<L>()?;
                Ok(())
            })
            .await
    }
}

async fn update_ledger<
    'a,
    L: 'static + Ledger,
    Backend: KeystoreBackend<'a, L>,
    Meta: Send + DeserializeOwned + Serialize,
>(
    event: LedgerEvent<L>,
    source: EventSource,
    shared_state: &mut KeystoreSharedState<'a, L, Backend, Meta>,
) -> Result<(), KeystoreError<L>> {
    let KeystoreSharedState {
        state,
        model,
        sync_handles,
        txn_subscribers,
        ..
    } = shared_state;
    // handle an event
    let summary = state.handle_event(model, event, source).await?;
    for (txn_uid, status) in summary.updated_txns {
        // signal any await_transaction() futures which should complete due to a
        // transaction having been completed.
        if status.is_final() {
            for sender in txn_subscribers.remove(&txn_uid).into_iter().flatten() {
                // It is ok to ignore errors here; they just mean the receiver
                // has disconnected.
                sender.send(status).ok();
            }
        }
    }

    // Keep all the sync() futures whose index is still in the future, and
    // signal the rest.
    let (sync_handles_to_keep, sync_handles_to_signal) = std::mem::take(sync_handles)
        .into_iter()
        .partition(|(index, _)| *index > state.now());
    *sync_handles = sync_handles_to_keep;
    for (_, handle) in sync_handles_to_signal {
        handle.send(()).ok();
    }
    Ok(())
}

async fn update_key_scan<
    'a,
    L: 'static + Ledger,
    Backend: KeystoreBackend<'a, L>,
    Meta: Send + DeserializeOwned + Serialize,
>(
    address: &UserAddress,
    event: LedgerEvent<L>,
    source: EventSource,
    shared_state: &mut KeystoreSharedState<'a, L, Backend, Meta>,
) -> Result<bool, KeystoreError<L>> {
    let KeystoreSharedState {
        state,
        model,
        pending_key_scans,
        ..
    } = shared_state;

    let finished = match model
        .sending_accounts
        .get_mut(address)
        .unwrap()
        .update_scan(event, source, state.record_mt.commitment())
        .await
    {
        Ok((mut editor, scan_info)) => {
            editor.save()?;
            match scan_info {
                Some((key, ScanOutputs { records, history })) => {
                    if let Err(err) = state.add_records(model, &key, records).await {
                        tracing::error!("Error saving records from key scan {}: {}", address, err);
                    }
                    for (uid, t) in history {
                        model.transactions.create(uid, t)?;
                    }

                    // Signal anyone waiting for a notification that this scan finished.
                    for sender in pending_key_scans.remove(address).into_iter().flatten() {
                        // Ignore errors, it just means the receiving end of the channel has been
                        // dropped.
                        sender.send(()).ok();
                    }

                    true
                }
                None => false,
            }
        }
        _ => false,
    };

    model.persistence.store_snapshot(state).await?;
    Ok(finished)
}

pub fn new_key_pair() -> UserKeyPair {
    UserKeyPair::generate(&mut ChaChaRng::from_entropy())
}
