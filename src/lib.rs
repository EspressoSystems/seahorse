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
pub mod accounts_refactor;
pub mod assets;
pub mod cli;
pub mod encryption;
pub mod events;
pub mod hd;
pub mod io;
mod key_scan;
pub mod key_value_store;
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
    accounts::{Account, AccountInfo},
    assets::{AssetsStore, VerifiedAssetLibrary},
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
    txn_builder::*,
};
use arbitrary::Arbitrary;
use async_scoped::AsyncScope;
use async_std::task::sleep;
use async_trait::async_trait;
use atomic_store::{
    error::PersistenceError as ASPersistenceError, load_store::LoadStore, AppendLog, AtomicStore,
    AtomicStoreLoader,
};
use core::fmt::Debug;
use espresso_macros::ser_test;
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
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

/// The number of keys of each type which have been generated.
///
/// This is used to generate a unique identifier for each new key of each type.
#[ser_test(arbitrary, ark(false))]
#[derive(Arbitrary, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStreamState {
    pub viewer: u64,
    pub freezer: u64,
    pub user: u64,
}

/// The data that determines a keystore.
///
/// This struct is where the keystore keeps its keys, assets, and records, as well as any information
/// about the current ledger state needed to build transactions.
#[derive(Debug, Clone)]
pub struct KeystoreState<'a, L: Ledger> {
    // For persistence, the fields in this struct are grouped into three categories based on how
    // they can be efficiently saved to disk:
    // 1. Static data, which never changes once a keystore is created, and so can be written to a
    //    single, static file.
    // 2. Dynamic data, which changes frequently and requires some kind of persistent snapshotting.
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Static data
    //
    // proving key set. The proving keys are ordered by number of outputs first and number of inputs
    // second, because the keystore is less flexible with respect to number of outputs. If we are
    // building a transaction and find we have too many inputs we can always generate a merge
    // transaction to defragment, but if the user requests a transaction with N independent outputs,
    // there is nothing we can do to decrease that number. So when searching for an appropriate
    // proving key, we will want to find a key with enough outputs first, and then worry about the
    // number of inputs.
    //
    // We keep the prover keys in an Arc because they are large, constant, and depend only on the
    // universal parameters of the system. This allows sharing them, which drastically decreases the
    // memory requirements of applications that create multiple keystores. This is not very realistic
    // for real applications, but it is very important for tests and costs little.
    //
    /// Proving keys.
    ///
    /// These are the keys used to generate Plonk proofs. There is one key for each transaction
    /// type (mint, freezes with varying numbers of input records, and transfers with varying
    /// numbers of input and output records). The supported transaction types must match the
    /// transaction types supported by the verifying keys maintained by validators.
    ///
    /// These keys are constructed when the keystore is created, and they never change afterwards.
    pub proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Dynamic state
    //
    /// Transaction building state.
    ///
    /// Everything we need to know about the state of the ledger in order to build transactions.
    pub txn_state: TransactionState<L>,
    /// HD key generation state.
    pub key_state: KeyStreamState,
    /// Viewing keys.
    pub viewing_accounts: HashMap<ViewerPubKey, Account<L, ViewerKeyPair>>,
    /// Freezing keys.
    pub freezing_accounts: HashMap<FreezerPubKey, Account<L, FreezerKeyPair>>,
    /// Sending keys, for spending owned records and receiving new records.
    ///
    /// Each public key in this set also includes a [UserAddress], which can be used to sign
    /// outgoing transactions, as well as an encryption public key used by other users to encrypt
    /// owner memos when sending records to this keystore.
    pub sending_accounts: HashMap<UserAddress, Account<L, UserKeyPair>>,
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
    /// create a [KeystoreState] consistent with that state. It must also persist the initial state by
    /// interacting with the storage layer directly.
    async fn create(&mut self) -> Result<KeystoreState<'a, L>, KeystoreError<L>>;

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

/// Transient state derived from the persistent [KeystoreState].
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
    rng: ChaChaRng,
    viewer_key_stream: hd::KeyTree,
    user_key_stream: hd::KeyTree,
    freezer_key_stream: hd::KeyTree,
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

impl<'a, L: 'static + Ledger> KeystoreState<'a, L> {
    fn key_pairs(&self) -> Vec<UserKeyPair> {
        self.sending_accounts
            .values()
            .map(|account| account.key.clone())
            .collect::<Vec<_>>()
    }

    pub fn pub_keys(&self) -> Vec<UserPubKey> {
        self.sending_accounts
            .values()
            .map(|account| account.key.pub_key())
            .collect()
    }

    pub fn balance_for_key<Meta: Serialize + DeserializeOwned + Send>(
        &self,
        model: &KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        asset: &AssetCode,
        pub_key: &UserPubKey,
        frozen: FreezeFlag,
    ) -> U256 {
        let spendable = model
            .records
            .get_spendable::<L>(asset, &pub_key.address(), frozen);
        if let Some(records) = spendable {
            records
                .filter(move |record| !record.on_hold(self.txn_state.block_height()))
                .fold(U256::zero(), |sum, record| sum + record.amount())
        } else {
            U256::zero()
        }
    }

    pub fn balance<Meta: Serialize + DeserializeOwned + Send>(
        &self,
        model: &KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        asset: &AssetCode,
        frozen: FreezeFlag,
    ) -> U256 {
        let mut balance = U256::zero();
        for pub_key in self.pub_keys() {
            balance += self.balance_for_key(model, asset, &pub_key, frozen);
        }
        balance
    }

    pub fn balance_breakdown<Meta: Serialize + DeserializeOwned + Send>(
        &self,
        model: &KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        address: &UserAddress,
        asset: &AssetCode,
        frozen: FreezeFlag,
    ) -> U256 {
        match self.sending_accounts.get(address) {
            Some(account) => self.balance_for_key(model, asset, &account.key.pub_key(), frozen),
            None => U256::zero(),
        }
    }

    // Inform the Transactions database that we have received memos for the given record UIDs. Return a list of
    // the transactions that are completed as a result.
    pub fn received_memos(
        &mut self,
        uids: impl Iterator<Item = u64>,
        transactions: &mut Transactions<L>,
    ) -> Vec<TransactionUID<L>> {
        let mut completed = Vec::new();
        for uid in uids {
            if let Ok(txn) = transactions.with_memo_id_mut(uid) {
                let mut txn = txn.remove_pending_uid(uid);
                let transaction = txn.save().unwrap();
                if transaction.pending_uids().is_empty() {
                    completed.push((*txn).uid().clone());
                }
            }
        }
        completed
    }

    async fn handle_event<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        event: LedgerEvent<L>,
        source: EventSource,
    ) -> Result<EventSummary<L>, KeystoreError<L>> {
        self.txn_state.now += EventIndex::from_source(source, 1);
        let mut summary = EventSummary::default();
        match event {
            LedgerEvent::Commit {
                block,
                block_id,
                state_comm,
            } => {
                // Don't trust the network connection that provided us this event; validate it
                // against our local mirror of the ledger and bail out if it is invalid.
                let mut uids = match self.txn_state.validator.validate_and_apply(block.clone()) {
                    Ok(uids) => {
                        if state_comm != self.txn_state.validator.commit() {
                            // Received a block which validates, but our state commitment does not
                            // match that of the event source. Since the block validates, we will
                            // accept it, but this must indicate that the event source is lying or
                            // mistaken about the state commitment. This would be a good time to
                            // switch to a different query server or something, but for now we'll
                            // just log the problem.
                            tracing::error!("received valid block with invalid state commitment");
                        }

                        // Get a list of new uids and whether we want to remember them in our record
                        // Merkle tree. Initially, set `remember` to false for all uids, to maximize
                        // sparseness. If any of the consumers of this block (for example, the
                        // viewer component, or the owner of this keystore) care about a uid, they
                        // will set its `remember` flag to true.
                        uids.into_iter().map(|uid| (uid, false)).collect::<Vec<_>>()
                    }
                    Err(val_err) => {
                        //todo !jeb.bearer handle this case more robustly. If we get here, it means
                        // the event stream has lied to us, so recovery is quite tricky and may
                        // require us to fail over to a different query service.
                        panic!("received invalid block: {:?}, {:?}", block, val_err);
                    }
                };

                // Update our full copies of sparse validator data structures to be consistent with
                // the validator state.
                for txn in block.txns() {
                    let nullifiers = txn.input_nullifiers();
                    // Remove spent records.
                    for n in &nullifiers {
                        if let Ok(record) = model.records.delete_by_nullifier::<L>(n) {
                            self.txn_state.forget_merkle_leaf(record.uid());
                        }
                    }
                }
                // Insert new records.
                self.txn_state.append_merkle_leaves(
                    block
                        .txns()
                        .into_iter()
                        .flat_map(|txn| txn.output_commitments()),
                );
                // Update nullifier set
                let nullifier_proofs = block
                    .txns()
                    .into_iter()
                    .flat_map(|txn| txn.proven_nullifiers())
                    .collect::<Vec<_>>();
                if self
                    .txn_state
                    .nullifiers
                    .multi_insert(&nullifier_proofs)
                    .is_err()
                {
                    //todo !jeb.bearer handle this case more robustly. If we get here, it means the
                    // event stream has lied to us, so recovery is quite tricky and may require us
                    // to fail over to a different query service.
                    panic!("received block with invalid nullifier proof");
                }

                for (txn_id, txn) in block.txns().into_iter().enumerate() {
                    // Split the uids corresponding to this transaction off the front of `uids`.
                    let mut this_txn_uids = uids;
                    uids = this_txn_uids.split_off(txn.output_len());
                    assert_eq!(this_txn_uids.len(), txn.output_len());

                    // If this transaction contains record openings for all of its outputs,
                    // consider it retired immediately, do not wait for memos.
                    let retired = txn.output_openings().is_some();

                    // Add the spent nullifiers to the summary. Map each nullifier to one of the
                    // output UIDs of the same transaction, so that we can tell when the memos
                    // arrive for the transaction which spent this nullifier (completing the
                    // transaction's life cycle) by looking at the UIDs attached to the memos.
                    // TODO !keyao Stop identifying transactions by input nullifier and instead use hashes.
                    // (https://github.com/SpectrumXYZ/cape/issues/275.)
                    if !txn.input_nullifiers().is_empty() {
                        summary.spent_nullifiers.extend(
                            txn.input_nullifiers()
                                .into_iter()
                                .zip(repeat(this_txn_uids[0].0)),
                        );
                        if retired {
                            summary.retired_nullifiers.push(txn.input_nullifiers()[0]);
                        }
                    }

                    // Different concerns within the keystore consume transactions in different ways.
                    // Now we give each concern a chance to consume this transaction, performing any
                    // processing they need to do and possibly setting the `remember` flag for
                    // output records they care about.
                    //
                    // This is a transaction we submitted and have been
                    // awaiting confirmation.
                    let mut self_published = false;
                    if let Some(pending) = self
                        .clear_pending_transaction(
                            model,
                            &txn,
                            Some((block_id, txn_id as u64, &mut this_txn_uids)),
                        )
                        .await
                    {
                        let status = if retired {
                            TransactionStatus::Retired
                        } else {
                            TransactionStatus::AwaitingMemos
                        };
                        summary.updated_txns.push((pending.uid().clone(), status));
                        model
                            .transactions
                            .get_mut(pending.uid())
                            .unwrap()
                            .add_pending_uids(
                                &this_txn_uids
                                    .iter()
                                    .zip(pending.memos().unwrap().memos.iter())
                                    .filter_map(|((uid, _), memo)| memo.as_ref().map(|_| *uid))
                                    .into_iter()
                                    .collect::<Vec<u64>>(),
                            )
                            .set_status(status)
                            .save()
                            .unwrap();
                        model
                            .backend
                            .finalize(pending, Some((block_id, txn_id as u64)))
                            .await;
                        self_published = true;
                    }

                    // This is someone else's transaction but we can view it.
                    self.view_transaction(model, &txn, &mut this_txn_uids)
                        .await?;

                    // If this transaction has record openings attached, check if they are for us
                    // and add them immediately, without waiting for memos.
                    if let Err(err) = self
                        .receive_attached_records(
                            model,
                            &txn,
                            &mut this_txn_uids,
                            !self_published,
                            // Only add to history if we didn't send this same transaction
                        )
                        .await
                    {
                        tracing::error!(
                            "Error saving records attached to transaction {}:{}: {}",
                            block_id,
                            txn_id,
                            err
                        );
                    }

                    // Prune the record Merkle tree of records we don't care about.
                    for (uid, remember) in this_txn_uids {
                        if !remember {
                            self.txn_state.forget_merkle_leaf(uid);
                        }
                    }
                }

                // Some transactions may have expired when we stepped the validator state. Remove
                // them from our pending transaction data structures.
                //
                // This maintains the invariant that everything in `pending_transactions` must
                // correspond to an on-hold record, because everything which corresponds to a record
                // whose hold just expired will be removed from the set now.
                match model
                    .transactions
                    .remove_expired(self.txn_state.block_height())
                {
                    Ok(txns) => {
                        for txn in txns {
                            summary
                                .updated_txns
                                .push((txn.uid().clone(), TransactionStatus::Rejected));
                            model.backend.finalize(txn, None).await;
                        }
                    }
                    Err(err) => {
                        println!(
                            "Error removing expired transaction from storage.  Block: {},  Error: {}",
                            block_id, err
                        );
                    }
                }
            }
            LedgerEvent::Memos {
                outputs,
                transaction,
            } => {
                let completed =
                    self.received_memos(outputs.iter().map(|info| info.2), &mut model.transactions);
                let self_published = !completed.is_empty();
                summary.updated_txns.extend(
                    completed
                        .into_iter()
                        .map(|txn_uid| (txn_uid, TransactionStatus::Retired))
                        .collect::<Vec<_>>(),
                );

                summary
                    .received_memos
                    .extend(outputs.iter().map(|(memo, _, uid, _)| (memo.clone(), *uid)));
                for account in self.sending_accounts.values().cloned().collect::<Vec<_>>() {
                    let records = self
                        .try_open_memos(
                            model,
                            &account.key,
                            &outputs,
                            transaction.clone(),
                            !self_published,
                        )
                        .await?;
                    if let Err(err) = self.add_records(model, &account.key, records).await {
                        tracing::error!("error saving received records: {}", err);
                    }
                }
            }
            LedgerEvent::Reject { block, error } => {
                for mut txn in block.txns() {
                    summary
                        .rejected_nullifiers
                        .append(&mut txn.input_nullifiers());
                    if let Some(pending) = self.clear_pending_transaction(model, &txn, None).await {
                        // Try to resubmit if the error is recoverable.
                        let uid = pending.uid();
                        if error.is_bad_nullifier_proof() {
                            if self.update_nullifier_proofs(model, &mut txn).await.is_ok()
                                && self
                                    .submit_elaborated_transaction(model, txn, None)
                                    .await
                                    .is_ok()
                            {
                                // The transaction has been successfully resubmitted. It is still in
                                // the same state (pending) so we don't need to add it to
                                // `updated_txns`.
                            } else {
                                // If we failed to resubmit, then the rejection is final.
                                summary
                                    .updated_txns
                                    .push((uid.clone(), TransactionStatus::Rejected));
                                model.backend.finalize(pending, None).await;
                            }
                        } else {
                            summary
                                .updated_txns
                                .push((uid.clone(), TransactionStatus::Rejected));
                            model.backend.finalize(pending, None).await;
                        }
                    }
                }
            }
        };

        model.persistence.store_snapshot(self).await?;
        Ok(summary)
    }

    async fn try_open_memos<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        key_pair: &UserKeyPair,
        memos: &[(ReceiverMemo, RecordCommitment, u64, MerklePath)],
        transaction: Option<(u64, u64, TransactionHash<L>, TransactionKind<L>)>,
        add_to_history: bool,
    ) -> Result<Vec<(RecordOpening, u64, MerklePath)>, KeystoreError<L>> {
        let mut records = Vec::new();
        for (memo, comm, uid, proof) in memos {
            if let Ok(record_opening) = memo.decrypt(key_pair, comm, &[]) {
                if !record_opening.is_dummy() {
                    // If this record is for us (i.e. its corresponding memo decrypts under
                    // our key) and not a dummy, then add it to our owned records.
                    records.push((record_opening, *uid, proof.clone()));
                }
            }
        }

        if add_to_history && !records.is_empty() {
            if let Some((_block_id, _txn_id, hash, kind)) = transaction {
                self.add_receive_history(
                    model,
                    kind,
                    hash,
                    &records
                        .iter()
                        .map(|(ro, _, _)| ro.clone())
                        .collect::<Vec<_>>(),
                )
                .await?;
            }
        }

        Ok(records)
    }

    async fn receive_attached_records<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        txn: &reef::Transaction<L>,
        uids: &mut [(u64, bool)],
        add_to_history: bool,
    ) -> Result<(), KeystoreError<L>> {
        let records = txn.output_openings().into_iter().flatten().zip(uids);
        let mut my_records = vec![];
        for (ro, (uid, remember)) in records {
            if let Some(account) = self.sending_accounts.get(&ro.pub_key.address()).cloned() {
                // If this record is for us, add it to the keystore and include it in the
                // list of received records for created a received transaction history
                // entry.
                *remember = true;
                // Add the asset type if it is not already in the asset library.
                model.assets_mut().create(ro.asset_def.clone(), None)?;
                // Mark the account receiving the records used.
                self.sending_accounts
                    .get_mut(&account.key.address())
                    .unwrap()
                    .used = true;
                // Add the record.
                model.records.create::<L>(
                    *uid,
                    ro.clone(),
                    account.key.nullify(
                        ro.asset_def.policy_ref().freezer_pub_key(),
                        *uid,
                        &RecordCommitment::from(&ro),
                    ),
                )?;
                my_records.push(ro);
            } else if let Some(account) = self
                .freezing_accounts
                .get(ro.asset_def.policy_ref().freezer_pub_key())
                .cloned()
            {
                // If this record is not for us, but we can freeze it, then this
                // becomes like an view. Add the record to our collection of freezable
                // records, but do not include it in the history entry.
                *remember = true;
                // Add the asset type if it is not already in the asset library.
                model.assets_mut().create(ro.asset_def.clone(), None)?;
                // Mark the freezing account which is tracking the record used.
                self.freezing_accounts
                    .get_mut(&account.key.pub_key())
                    .unwrap()
                    .used = true;
                // Add the record.
                model.records.create::<L>(
                    *uid,
                    ro.clone(),
                    account
                        .key
                        .nullify(&ro.pub_key.address(), *uid, &RecordCommitment::from(&ro)),
                )?;
            }
        }

        if add_to_history && !my_records.is_empty() {
            self.add_receive_history(model, txn.kind(), txn.hash().clone(), &my_records)
                .await?;
        }

        Ok(())
    }

    async fn add_receive_history<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        kind: TransactionKind<L>,
        hash: TransactionHash<L>,
        records: &[RecordOpening],
    ) -> Result<(), KeystoreError<L>> {
        let uid = TransactionUID::<L>(hash);
        let history = receive_history_entry(kind, records);
        model.transactions.create(uid, history)?;
        Ok(())
    }

    async fn add_records<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        key_pair: &UserKeyPair,
        records: Vec<(RecordOpening, u64, MerklePath)>,
    ) -> Result<(), KeystoreError<L>> {
        for (record, uid, proof) in records {
            let comm = RecordCommitment::from(&record);
            if !self
                .txn_state
                .remember_merkle_leaf(uid, &MerkleLeafProof::new(comm.to_field_element(), proof))
            {
                return Err(KeystoreError::BadMerkleProof {
                    commitment: comm,
                    uid,
                });
            }

            // Add the asset type if it is not already in the asset library.
            model.assets_mut().create(record.asset_def.clone(), None)?;

            // Mark the account receiving the record as used.
            self.sending_accounts
                .get_mut(&key_pair.address())
                .unwrap()
                .used = true;
            // Save the record.
            model.records.create::<L>(
                uid,
                record.clone(),
                key_pair.nullify(
                    record.asset_def.policy_ref().freezer_pub_key(),
                    uid,
                    &RecordCommitment::from(&record),
                ),
            )?;
        }
        Ok(())
    }

    async fn import_memo<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        memo: ReceiverMemo,
        comm: RecordCommitment,
        uid: u64,
        proof: MerklePath,
    ) -> Result<(), KeystoreError<L>> {
        for account in self.sending_accounts.values().cloned().collect::<Vec<_>>() {
            let records = self
                .try_open_memos(
                    model,
                    &account.key,
                    &[(memo.clone(), comm, uid, proof.clone())],
                    None,
                    false,
                )
                .await?;
            if !records.is_empty() {
                return self.add_records(model, &account.key, records).await;
            }
        }

        Err(KeystoreError::<L>::CannotDecryptMemo {})
    }

    async fn clear_pending_transaction<'t, Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        txn: &reef::Transaction<L>,
        res: Option<CommittedTxn<'t>>,
    ) -> Option<Transaction<L>> {
        let now = self.txn_state.block_height();
        let pending = model
            .transactions
            .get(&TransactionUID::<L>(txn.hash()))
            .ok();
        for nullifier in txn.input_nullifiers() {
            if let Ok(record) = model.records.with_nullifier_mut::<L>(&nullifier) {
                if pending.is_some() {
                    // If we started this transaction, all of its inputs should have been on hold,
                    // to preserve the invariant that all input nullifiers of all pending
                    // transactions are on hold.
                    assert!(record.on_hold(now));

                    if res.is_none() {
                        // If the transaction was not accepted for any reason, its nullifiers have
                        // not been spent, so remove the hold we placed on them.
                        record.unhold().save::<L>().ok();
                    }
                } else {
                    // This isn't even our transaction.
                    assert!(!record.on_hold(now));
                }
            }
        }

        // If this was a successful transaction, add all of its frozen/unfrozen outputs to our
        // freezable database (for freeze/unfreeze transactions).
        if let Some((_, _, uids)) = res {
            if let Some(pending) = &pending {
                if pending.kind().clone() == TransactionKind::<L>::freeze()
                    || pending.kind().clone() == TransactionKind::<L>::unfreeze()
                {
                    // the first uid corresponds to the fee change output, which is not one of the
                    // `freeze_outputs`, so we skip that one
                    for ((uid, remember), ro) in uids.iter_mut().zip(pending.outputs()).skip(1) {
                        let key_pair = &self.freezing_accounts
                            [ro.asset_def.policy_ref().freezer_pub_key()]
                        .key;
                        model
                            .records
                            .create::<L>(
                                *uid,
                                ro.clone(),
                                key_pair.nullify(
                                    &ro.pub_key.address(),
                                    *uid,
                                    &RecordCommitment::from(ro),
                                ),
                                // TODO Error handling
                            )
                            .ok();
                        *remember = true;
                    }
                }
            }
        }
        pending
    }

    async fn view_transaction<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        txn: &reef::Transaction<L>,
        uids: &mut [(u64, bool)],
    ) -> Result<(), KeystoreError<L>> {
        // Try to decrypt viewer memos.
        let mut viewable_assets = HashMap::new();
        for asset in model.assets.iter() {
            if self
                .viewing_accounts
                .contains_key(asset.definition().policy_ref().viewer_pub_key())
            {
                viewable_assets.insert(asset.code(), asset.definition().clone());
            }
        }
        if let Ok(memo) = txn.open_viewing_memo(
            &viewable_assets,
            &self
                .viewing_accounts
                .iter()
                .map(|(pub_key, account)| (pub_key.clone(), account.key.clone()))
                .collect(),
        ) {
            // Mark the viewing account used.
            self.viewing_accounts
                .get_mut(memo.asset.policy_ref().viewer_pub_key())
                .unwrap()
                .used = true;

            //todo !jeb.bearer eventually, we will probably want to save all the viewing memos for
            // the whole transaction (inputs and outputs) regardless of whether any of the outputs
            // are freezeable, just for general viewing purposes.

            // the first uid corresponds to the fee change output, which has no view memo, so skip
            // that one
            for ((uid, remember), output) in uids.iter_mut().skip(1).zip(memo.outputs) {
                let pub_key = match output.user_address {
                    Some(address) => Some(match model.backend.get_public_key(&address).await {
                        Ok(key) => key,
                        // If the address isn't found in the backend, it may not be registered. In
                        // this case, use the address and a default encryption key to construct a
                        // public key. The encryption key is only a placeholder since it won't be
                        // used to compute the record commitment.
                        Err(_) => UserPubKey::new(address, aead::EncKey::default()),
                    }),
                    None => None,
                };
                if let (Some(pub_key), Some(amount), Some(blind)) =
                    (pub_key, output.amount, output.blinding_factor)
                {
                    // If the viewing memo contains all the information we need to potentially freeze
                    // this record, save it in our database for later freezing.
                    if let Some(account) = self
                        .freezing_accounts
                        .get_mut(memo.asset.policy_ref().freezer_pub_key())
                    {
                        // Mark the freezing account that is tracking the record used.
                        account.used = true;

                        let record_opening = RecordOpening {
                            amount,
                            asset_def: memo.asset.clone(),
                            pub_key,
                            freeze_flag: FreezeFlag::Unfrozen,
                            blind,
                        };
                        model.records.create::<L>(
                            *uid,
                            record_opening.clone(),
                            account.key.nullify(
                                &record_opening.pub_key.address(),
                                *uid,
                                &RecordCommitment::from(&record_opening),
                            ),
                        )?;
                        *remember = true;
                    }
                }
            }
        }
        Ok(())
    }

    async fn update_nullifier_proofs<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        txn: &mut reef::Transaction<L>,
    ) -> Result<(), KeystoreError<L>> {
        let mut proofs = Vec::new();
        for n in txn.input_nullifiers() {
            let (spent, proof) = model
                .backend
                .get_nullifier_proof(&mut self.txn_state.nullifiers, n)
                .await?;
            if spent {
                return Err(KeystoreError::<L>::NullifierAlreadyPublished { nullifier: n });
            }
            proofs.push(proof);
        }
        txn.set_proofs(proofs);
        Ok(())
    }

    // This function ran into the same mystifying compiler behavior as
    // `submit_elaborated_transaction`, where the default async desugaring loses track of the `Send`
    // impl for the result type. As with the other function, this can be fixed by manually
    // desugaring the type signature.
    fn define_asset<'b, Meta: Serialize + DeserializeOwned + Send + Send>(
        &'b mut self,
        model: &'b mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        name: String,
        description: &'b [u8],
        policy: AssetPolicy,
    ) -> impl 'b + Captures<'a> + Future<Output = Result<AssetDefinition, KeystoreError<L>>> + Send
    where
        'a: 'b,
    {
        async move {
            let (seed, definition) =
                self.txn_state
                    .define_asset(&mut model.rng, description, policy)?;
            let mint_info = MintInfo {
                seed,
                description: description.to_vec(),
            };

            model
                .assets_mut()
                .create(definition.clone(), Some(mint_info.clone()))?
                .with_name(name)
                .with_description(mint_info.fmt_description())
                .save()?;

            // If the asset is viewable/freezable, mark the appropriate viewing/freezing accounts
            // `used`.
            let policy = definition.policy_ref();
            if policy.is_viewer_pub_key_set() {
                if let Some(account) = self.viewing_accounts.get_mut(policy.viewer_pub_key()) {
                    account.used = true;
                }
            }
            if policy.is_freezer_pub_key_set() {
                if let Some(account) = self.freezing_accounts.get_mut(policy.freezer_pub_key()) {
                    account.used = true;
                }
            }
            model.persistence.store_snapshot(self).await?;
            Ok(definition)
        }
    }

    // Add a new user key and set up a scan of the ledger to import records belonging to this key.
    //
    // `user_key` can be provided to add an arbitrary key, not necessarily derived from this
    // keystore's deterministic key stream. Otherwise, the next key in the key stream will be derived
    // and added.
    //
    // If `scan_from` is provided, a new ledger scan will be created and the corresponding event
    // stream will be returned. Note that the caller is responsible for actually starting the task
    // which processes this scan, since the Keystore (not the KeystoreState) has the data structures
    // needed to manage tasks (the AsyncScope, mutexes, etc.).
    async fn add_user_key<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        user_key: Option<UserKeyPair>,
        description: String,
        scan_from: Option<EventIndex>,
    ) -> Result<
        (
            UserKeyPair,
            Option<impl 'a + Stream<Item = (LedgerEvent<L>, EventSource)> + Send + Unpin>,
        ),
        KeystoreError<L>,
    > {
        let user_key = match user_key {
            Some(user_key) => {
                if self.sending_accounts.contains_key(&user_key.address()) {
                    // For other key types, adding a key that already exists is a no-op. However,
                    // because of the background ledger scans associated with user keys, we want to
                    // report an error, since the user may have attempted to add the same key with
                    // two different `scan_from` parameters, and we have not actually started the
                    // second scan in this case.
                    return Err(KeystoreError::<L>::UserKeyExists {
                        pub_key: user_key.pub_key(),
                    });
                }
                user_key
            }
            None => {
                // It is possible that we already have some of the keys that will be yielded by the
                // deterministic key stream. For example, the user could create a second keystore with
                // the same mnemonic, generate some keys, and then manually add those keys to this
                // keystore. If `user_key` is not provided, this function is required to generate a
                // new key, so keep incrementing the key stream state and generating keys until we
                // find one that is new.
                loop {
                    let user_key = model
                        .user_key_stream
                        .derive_user_key_pair(&self.key_state.user.to_le_bytes());
                    self.key_state.user += 1;
                    if !self.sending_accounts.contains_key(&user_key.address()) {
                        break user_key;
                    }
                }
            }
        };

        let (scan, events) = if let Some(scan_from) = scan_from {
            // Get the stream of events for the background scan worker task to process.
            let (frontier, next_event) = model.backend.get_initial_scan_state(scan_from).await?;
            let events = model.backend.subscribe(next_event, None).await;

            // Create a background scan of the ledger to import records belonging to this key.
            let scan = BackgroundKeyScan::new(
                user_key.clone(),
                next_event,
                scan_from,
                self.txn_state.now,
                SparseMerkleTree::sparse(frontier),
            );
            (Some(scan), Some(events))
        } else {
            (None, None)
        };

        let mut account = Account::new(user_key.clone(), description);
        account.scan = scan;

        // Add the new account to our set of accounts and update our persistent data structures and
        // remote services.
        self.sending_accounts.insert(user_key.address(), account);
        model.persistence.store_snapshot(self).await?;
        // If we successfully updated our data structures, register the key with the
        // network. The storage transaction will revert if this fails.
        model.backend.register_user_key(&user_key).await?;
        Ok((user_key, events))
    }

    async fn add_viewing_key<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        viewing_key: ViewerKeyPair,
        description: String,
    ) -> Result<(), KeystoreError<L>> {
        if self.viewing_accounts.contains_key(&viewing_key.pub_key()) {
            return Ok(());
        }

        self.viewing_accounts.insert(
            viewing_key.pub_key(),
            Account::new(viewing_key.clone(), description),
        );
        model.persistence.store_snapshot(self).await?;
        Ok(())
    }

    async fn add_freeze_key<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        freeze_key: FreezerKeyPair,
        description: String,
    ) -> Result<(), KeystoreError<L>> {
        if self.freezing_accounts.contains_key(&freeze_key.pub_key()) {
            return Ok(());
        }

        self.freezing_accounts
            .insert(freeze_key.pub_key(), Account::new(freeze_key, description));
        model.persistence.store_snapshot(self).await?;

        Ok(())
    }

    fn build_transfer<'k, Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        spec: TransferSpec<'k>,
    ) -> Result<(TransferNote, TransactionParams<L>), KeystoreError<L>> {
        self.txn_state
            .transfer(
                &mut model.records,
                spec,
                &self.proving_keys.xfr,
                &mut model.rng,
            )
            .context(TransactionSnafu)
    }

    async fn build_mint<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        minter: Option<&UserAddress>,
        fee: RecordAmount,
        asset_code: &AssetCode,
        amount: RecordAmount,
        receiver: UserPubKey,
    ) -> Result<(MintNote, TransactionParams<L>), KeystoreError<L>> {
        let asset = model
            .assets
            .get::<L>(asset_code)
            .map_err(|_| KeystoreError::<L>::UndefinedAsset { asset: *asset_code })?;
        let MintInfo { seed, description } =
            asset
                .mint_info()
                .ok_or(KeystoreError::<L>::AssetNotMintable {
                    asset: asset.definition().clone(),
                })?;
        let sending_keys = match minter {
            Some(addr) => vec![self.account_key_pair(addr)?.clone()],
            None => self.key_pairs(),
        };
        self.txn_state
            .mint(
                &mut model.records,
                &sending_keys,
                &self.proving_keys.mint,
                fee,
                &(asset.definition().clone(), seed, description),
                amount,
                receiver,
                &mut model.rng,
            )
            .context(TransactionSnafu)
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_freeze<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        fee_address: Option<&UserAddress>,
        fee: RecordAmount,
        asset: &AssetCode,
        amount: U256,
        owner: UserAddress,
        outputs_frozen: FreezeFlag,
    ) -> Result<(FreezeNote, TransactionParams<L>), KeystoreError<L>> {
        let asset = model
            .assets
            .get::<L>(asset)
            .map_err(|_| KeystoreError::<L>::UndefinedAsset { asset: *asset })?
            .definition()
            .clone();
        let freeze_key = match self
            .freezing_accounts
            .get(asset.policy_ref().freezer_pub_key())
        {
            Some(account) => &account.key,
            None => return Err(KeystoreError::<L>::AssetNotFreezable { asset }),
        };
        let sending_keys = match fee_address {
            Some(addr) => vec![self.account_key_pair(addr)?.clone()],
            None => self.key_pairs(),
        };

        self.txn_state
            .freeze_or_unfreeze(
                &mut model.records,
                &sending_keys,
                freeze_key,
                &self.proving_keys.freeze,
                fee,
                &asset,
                amount,
                owner,
                outputs_frozen,
                &mut model.rng,
            )
            .context(TransactionSnafu)
    }

    async fn submit_transaction<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        note: TransactionNote,
        info: TransactionParams<L>,
    ) -> Result<TransactionUID<L>, KeystoreError<L>> {
        let mut nullifier_pfs = Vec::new();
        for n in note.nullifiers() {
            let (spent, proof) = model
                .backend
                .get_nullifier_proof(&mut self.txn_state.nullifiers, n)
                .await?;
            if spent {
                return Err(KeystoreError::<L>::NullifierAlreadyPublished { nullifier: n });
            }
            nullifier_pfs.push(proof);
        }

        let txn = reef::Transaction::<L>::cap(note, nullifier_pfs);
        self.submit_elaborated_transaction(model, txn, Some(info))
            .await
    }

    // For reasons that are not clearly understood, the default async desugaring for this function
    // loses track of the fact that the result type implements Send, which causes very confusing
    // error messages farther up the call stack (apparently at the point where this function is
    // monomorphized) which do not point back to this location. This is likely due to a bug in type
    // inference, or at least a deficiency around async sugar combined with a bug in diagnostics.
    //
    // As a work-around, we do the desugaring manually so that we can explicitly specify that the
    // return type implements Send. The return type also captures a reference with lifetime 'a,
    // which is different from (but related to) the lifetime 'b of the returned Future, and
    // `impl 'a + 'b + ...` does not work, so we use the work-around described at
    // https://stackoverflow.com/questions/50547766/how-can-i-get-impl-trait-to-use-the-appropriate-lifetime-for-a-mutable-reference
    // to indicate the captured lifetime using the Captures trait.
    fn submit_elaborated_transaction<'b, Meta: Serialize + DeserializeOwned + Send + Send>(
        &'b mut self,
        model: &'b mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        txn: reef::Transaction<L>,
        info: Option<TransactionParams<L>>,
    ) -> impl 'b + Captures<'a> + Future<Output = Result<TransactionUID<L>, KeystoreError<L>>> + Send
    where
        'a: 'b,
    {
        async move {
            let stored_txn = if let Some(mut info) = info {
                let now = self.txn_state.block_height();
                let timeout = now + (L::record_root_history() as u64);
                let uid = TransactionUID(txn.hash());
                for nullifier in txn.input_nullifiers() {
                    // hold the record corresponding to this nullifier until the transaction is committed,
                    // rejected, or expired.
                    if let Ok(record) = model.records.with_nullifier_mut::<L>(&nullifier) {
                        assert!(!(*record).on_hold(now));
                        record.hold_until(timeout).save::<L>()?;
                    }
                }
                info.timeout = Some(timeout);
                let stored_txn = model.transactions.create(uid, info)?;
                model.persistence.store_snapshot(self).await?;
                stored_txn.clone()
            } else {
                model.transactions.get(&TransactionUID::<L>(txn.hash()))?
            };
            let uid = stored_txn.uid().clone();
            // If we succeeded in creating and persisting the pending transaction, submit it to the
            // validators.
            model.backend.submit(txn.clone(), stored_txn).await?;
            Ok(uid)
        }
    }

    fn account_key_pair(
        &'_ self,
        address: &UserAddress,
    ) -> Result<&'_ UserKeyPair, KeystoreError<L>> {
        match self.sending_accounts.get(address) {
            Some(account) => Ok(&account.key),
            None => Err(KeystoreError::<L>::NoSuchAccount {
                address: address.clone(),
            }),
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

// Fun fact: replacing `std::pin::Pin` with `Pin` and adding `use std::pin::Pin` causes the compiler
// to panic where this type alias is used in `Keystore::new`. As a result, the type alias `BoxFuture`
// from `futures::future` does not work, so we define our own.
type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// `SendFuture` trait is needed for the cape repo to compile when calling key generation functions,
// `generate_viewing_key`, `generate_freeze_key`, and `generate_user_key`.
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
    #[allow(clippy::type_complexity)]
    pub fn create_stores(
        loader: &mut impl KeystoreLoader<L, Meta = Meta>,
    ) -> Result<
        (
            AtomicStore,
            AtomicKeystoreStorage<'a, L, Meta>,
            Assets,
            Transactions<L>,
            Records,
        ),
        KeystoreError<L>,
    > {
        let mut atomic_loader = AtomicStoreLoader::load(&loader.location(), "keystore").unwrap();
        let file_fill_size = 1024;
        let persistence = AtomicKeystoreStorage::new(loader, &mut atomic_loader, file_fill_size)?;
        let adaptor = persistence.encrypting_storage_adapter::<()>();
        let assets = Assets::new::<L>(AssetsStore::new(AppendLog::load(
            &mut atomic_loader,
            adaptor.cast(),
            "keystore_assets",
            file_fill_size,
        )?)?)?;
        let transactions = Transactions::new(&mut atomic_loader, adaptor.cast(), file_fill_size)?;
        let records = Records::new(&mut atomic_loader, adaptor.cast(), file_fill_size)?;
        let atomic_store = AtomicStore::open(atomic_loader)?;
        Ok((atomic_store, persistence, assets, transactions, records))
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
        let (mut atomic_store, mut persistence, mut assets, mut transactions, mut records) =
            Self::create_stores(loader).unwrap();
        Box::pin(async move {
            let state = if persistence.exists() {
                persistence.load().await?
            } else {
                let state: KeystoreState<'a, L> = backend.create().await?;
                persistence.create(&state).await?;
                state
            };
            persistence.commit().await;
            assets.commit()?;
            transactions.commit()?;
            records.commit()?;
            atomic_store.commit_version()?;
            Self::new_impl(
                backend,
                atomic_store,
                persistence,
                assets,
                transactions,
                records,
                state,
            )
            .await
        })
    }

    #[cfg(any(test, bench, feature = "testing"))]
    pub fn with_state(
        backend: Backend,
        loader: &mut (impl 'a + KeystoreLoader<L, Meta = Meta>),
        state: KeystoreState<'a, L>,
    ) -> BoxFuture<'a, Result<Keystore<'a, Backend, L, Meta>, KeystoreError<L>>> {
        let (mut atomic_store, mut persistence, mut assets, mut transactions, mut records) =
            Self::create_stores(loader).unwrap();
        Box::pin(async move {
            persistence.create(&state).await?;
            persistence.commit().await;
            assets.commit()?;
            transactions.commit()?;
            atomic_store.commit_version()?;
            Self::new_impl(
                backend,
                atomic_store,
                persistence,
                assets,
                transactions,
                records,
                state,
            )
            .await
        })
    }

    async fn new_impl(
        backend: Backend,
        atomic_store: AtomicStore,
        persistence: AtomicKeystoreStorage<'a, L, Meta>,
        assets: Assets,
        transactions: Transactions<L>,
        records: Records,
        state: KeystoreState<'a, L>,
    ) -> Result<Keystore<'a, Backend, L, Meta>, KeystoreError<L>> {
        let mut events = backend.subscribe(state.txn_state.now, None).await;
        let mut key_scans = vec![];
        for account in state.viewing_accounts.values() {
            if let Some(scan) = &account.scan {
                key_scans.push((
                    scan.address(),
                    backend.subscribe(scan.next_event(), None).await,
                ));
            }
        }
        let key_tree = persistence.key_stream();
        let mut model = KeystoreModel {
            backend,
            atomic_store,
            persistence,
            assets,
            records,
            transactions,
            rng: ChaChaRng::from_entropy(),
            viewer_key_stream: key_tree.derive_sub_tree("viewer".as_bytes()),
            freezer_key_stream: key_tree.derive_sub_tree("freezer".as_bytes()),
            user_key_stream: key_tree.derive_sub_tree("user".as_bytes()),
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

    /// List sending keys.
    pub async fn pub_keys(&self) -> Vec<UserPubKey> {
        let KeystoreSharedState { state, .. } = &*self.read().await;
        state.pub_keys()
    }

    /// List viewing keys.
    pub async fn viewer_pub_keys(&self) -> Vec<ViewerPubKey> {
        let KeystoreSharedState { state, .. } = &*self.read().await;
        state.viewing_accounts.keys().cloned().collect()
    }

    /// List freezing keys.
    pub async fn freezer_pub_keys(&self) -> Vec<FreezerPubKey> {
        let KeystoreSharedState { state, .. } = &*self.read().await;
        state.freezing_accounts.keys().cloned().collect()
    }

    /// Get sending private key
    pub async fn get_user_private_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserKeyPair, KeystoreError<L>> {
        let KeystoreSharedState { state, .. } = &*self.read().await;
        match state.sending_accounts.get(address) {
            Some(account) => Ok(account.key.clone()),
            None => Err(KeystoreError::<L>::InvalidAddress {
                address: address.clone(),
            }),
        }
    }

    /// Get freezing private key
    pub async fn get_freezer_private_key(
        &self,
        pub_key: &FreezerPubKey,
    ) -> Result<FreezerKeyPair, KeystoreError<L>> {
        let KeystoreSharedState { state, .. } = &*self.read().await;
        match state.freezing_accounts.get(pub_key) {
            Some(account) => Ok(account.key.clone()),
            None => Err(KeystoreError::<L>::InvalidFreezerKey {
                key: pub_key.clone(),
            }),
        }
    }

    /// Get viewing private key
    pub async fn get_viewer_private_key(
        &self,
        pub_key: &ViewerPubKey,
    ) -> Result<ViewerKeyPair, KeystoreError<L>> {
        let KeystoreSharedState { state, .. } = &*self.read().await;
        match state.viewing_accounts.get(pub_key) {
            Some(account) => Ok(account.key.clone()),
            None => Err(KeystoreError::<L>::InvalidViewerKey {
                key: pub_key.clone(),
            }),
        }
    }

    /// Get information about a sending account.
    pub async fn sending_account(
        &self,
        address: &UserAddress,
    ) -> Result<AccountInfo<UserKeyPair>, KeystoreError<L>> {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        let account = state.sending_accounts.get(address).cloned().ok_or(
            KeystoreError::<L>::InvalidAddress {
                address: address.clone(),
            },
        )?;
        let records = model
            .records
            .iter()
            .filter(|rec| {
                rec.record_opening().pub_key.address() == *address
                    && rec.record_opening().amount > 0u64.into()
            })
            .collect::<Vec<_>>();
        let assets = records
            .iter()
            .map(|rec| {
                model
                    .assets
                    .get::<L>(&rec.record_opening().asset_def.code)
                    .unwrap()
            })
            .collect();
        Ok(AccountInfo::new(account, assets, records))
    }

    /// Get information about a viewing account.
    pub async fn viewing_account(
        &self,
        address: &ViewerPubKey,
    ) -> Result<AccountInfo<ViewerKeyPair>, KeystoreError<L>> {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        let account = state.viewing_accounts.get(address).cloned().ok_or(
            KeystoreError::<L>::InvalidViewerKey {
                key: address.clone(),
            },
        )?;
        let records = model
            .records
            .iter()
            .filter(|rec| {
                rec.record_opening().asset_def.policy_ref().viewer_pub_key() == address
                    && rec.record_opening().amount > 0u64.into()
            })
            .collect::<Vec<_>>();
        let assets = records
            .iter()
            // Get assets which are currently viewable.
            .map(|rec| {
                model
                    .assets
                    .get::<L>(&rec.record_opening().asset_def.code)
                    .unwrap()
            })
            // Get known assets which list this key as a viewer.
            .chain(
                model
                    .assets
                    .iter()
                    .filter(|asset| asset.definition().policy_ref().viewer_pub_key() == address),
            )
            // Deduplicate
            .map(|asset| (asset.code(), asset))
            .collect::<HashMap<_, _>>()
            .into_values()
            .collect();
        Ok(AccountInfo::new(account, assets, records))
    }

    /// Get information about a freezing account.
    pub async fn freezing_account(
        &self,
        address: &FreezerPubKey,
    ) -> Result<AccountInfo<FreezerKeyPair>, KeystoreError<L>> {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        let account = state.freezing_accounts.get(address).cloned().ok_or(
            KeystoreError::<L>::InvalidFreezerKey {
                key: address.clone(),
            },
        )?;
        let records = model
            .records
            .iter()
            .filter(|rec| {
                rec.record_opening()
                    .asset_def
                    .policy_ref()
                    .freezer_pub_key()
                    == address
                    && rec.record_opening().amount > 0u64.into()
                    && rec.record_opening().freeze_flag == FreezeFlag::Unfrozen
            })
            .collect::<Vec<_>>();
        let assets = records
            .iter()
            // Get assets which are currently freezable.
            .map(|rec| {
                model
                    .assets
                    .get::<L>(&rec.record_opening().asset_def.code)
                    .unwrap()
            })
            // Get known assets which list this key as a freezer.
            .chain(
                model
                    .assets
                    .iter()
                    .filter(|asset| asset.definition().policy_ref().freezer_pub_key() == address),
            )
            // Deduplicate
            .map(|asset| (asset.code(), asset))
            .collect::<HashMap<_, _>>()
            .into_values()
            .collect();
        Ok(AccountInfo::new(account, assets, records))
    }

    /// Compute the spendable balance of the given asset type owned by all addresses.
    pub async fn balance(&self, asset: &AssetCode) -> U256 {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        state.balance(model, asset, FreezeFlag::Unfrozen)
    }

    /// Compute the spendable balance of the given asset type owned by the given address.
    pub async fn balance_breakdown(&self, account: &UserAddress, asset: &AssetCode) -> U256 {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        state.balance_breakdown(model, account, asset, FreezeFlag::Unfrozen)
    }

    /// List records owned or viewable by this keystore.
    pub async fn records(&self) -> impl Iterator<Item = Record> + '_ {
        let KeystoreSharedState { model, .. } = &*self.read().await;
        model.records.iter().collect::<Vec<_>>().into_iter()
    }

    /// Compute the balance frozen records of the given asset type owned by the given address.
    pub async fn frozen_balance_breakdown(&self, account: &UserAddress, asset: &AssetCode) -> U256 {
        let KeystoreSharedState { state, model, .. } = &*self.read().await;
        state.balance_breakdown(model, account, asset, FreezeFlag::Frozen)
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
                            vec![state.account_key_pair(addr)?.clone()]
                        }
                        None => state.key_pairs(),
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
    pub fn add_viewing_key<'l>(
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
                    state.add_viewing_key(model, viewing_key, description)
                })
                .await
        })
    }

    /// Generate a new viewing key and add it to the keystore's key set.
    pub fn generate_viewing_key<'l>(
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
                    let viewing_key = model
                        .viewer_key_stream
                        .derive_viewer_key_pair(&state.key_state.viewer.to_le_bytes());
                    state.key_state.viewer += 1;
                    state
                        .add_viewing_key(model, viewing_key.clone(), description)
                        .await?;
                    Ok(viewing_key.pub_key())
                })
                .await
        })
    }

    /// Add a freezing key to the keystore's key set.
    pub fn add_freeze_key<'l>(
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
                    state.add_freeze_key(model, freeze_key, description)
                })
                .await
        })
    }

    /// Generate a new freezing key and add it to the keystore's key set.
    pub fn generate_freeze_key<'l>(
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
                    let freeze_key = model
                        .freezer_key_stream
                        .derive_freezer_key_pair(&state.key_state.freezer.to_le_bytes());
                    state.key_state.freezer += 1;
                    state
                        .add_freeze_key(model, freeze_key.clone(), description)
                        .await?;
                    Ok(freeze_key.pub_key())
                })
                .await
        })
    }

    /// Add a sending key to the keystore's key set.
    ///
    /// Since this key was not generated by this keystore, it may have already been used and thus may
    /// own existing records. The keystore will start a scan of the ledger in the background to find
    /// records owned by this key. The scan will start from the event specified by `scan_from`.
    pub fn add_user_key<'l>(
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
                            .add_user_key(model, Some(user_key), description, Some(scan_from))
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
    pub fn generate_user_key<'l>(
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
                                .add_user_key(model, None, description, scan_from)
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
                        if state.txn_state.now >= t {
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
        self.read().await.state.txn_state.now
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
        .partition(|(index, _)| *index > state.txn_state.now);
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

    let finished = if let Some((key, ScanOutputs { records, history })) = state
        .sending_accounts
        .get_mut(address)
        .unwrap()
        .update_scan(event, source, state.txn_state.record_mt.commitment())
        .await
    {
        if let Err(err) = state.add_records(model, &key, records).await {
            tracing::error!("Error saving records from key scan {}: {}", address, err);
        }
        for (uid, t) in history {
            model.transactions.create(uid, t)?;
        }

        // Signal anyone waiting for a notification that this scan finished.
        for sender in pending_key_scans.remove(address).into_iter().flatten() {
            // Ignore errors, it just means the receiving end of the channel has
            // been dropped.
            sender.send(()).ok();
        }

        true
    } else {
        false
    };

    model.persistence.store_snapshot(state).await?;
    Ok(finished)
}

pub fn new_key_pair() -> UserKeyPair {
    UserKeyPair::generate(&mut ChaChaRng::from_entropy())
}
