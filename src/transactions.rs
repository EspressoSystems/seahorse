// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The transaction module.
//!
//! This module defines [Transaction], [TransactionEditor], and [Transactions], which provide CURD (create, read,
//! update, and delete) operations, with the use of [KeyValueStore] to control the transactions resource.

use crate::{
    key_value_store::*, AssetCode, EncryptingResourceAdapter, KeystoreError, Ledger, RecordAmount,
    TransactionHash, TransactionKind, TransactionReceipt, TransactionStatus, TransactionUID,
};
use atomic_store::{AppendLog, AtomicStoreLoader};
use chrono::{DateTime, Local};
use jf_cap::{
    keys::UserAddress,
    structs::{ReceiverMemo, RecordOpening},
    Signature,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};

/// A Transaction<L>with its UID as the primary key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction<L: Ledger> {
    /// Identifier for the Transaction, also the primary key in storage
    uid: TransactionUID<L>,
    /// Time when this transaction will expire if it's not completed, None if we recieved it
    timeout: Option<u64>,
    /// Hash which appears in the commited block for this transaction
    hash: Option<TransactionHash<L>>,
    status: TransactionStatus,
    /// The uids of the outputs of this transaction for which memos have not yet been posted.
    pending_uids: HashSet<u64>,
    /// A receiver memo for each output, except for burned outputs.
    memos: Vec<Option<ReceiverMemo>>,
    sig: Signature,
    inputs: Vec<RecordOpening>,
    outputs: Vec<RecordOpening>,
    /// Time when this transaction was created in the transaction builder or time when it was received
    time: DateTime<Local>,
    /// The asset we are transacting
    asset: AssetCode,
    /// Describes the operation this transaction is performing (e.g Mint, Freeze, or Send)
    kind: TransactionKind<L>,
    /// Addresses used to build this transaction.
    ///
    /// If we sent this transaction, `senders` records the addresses of the spending keys used to
    /// submit it. If we received this transaction from someone else, we may not know who the
    /// senders are and this field may be empty.
    senders: Vec<UserAddress>,
    // Receivers and corresponding amounts.
    receivers: Vec<(UserAddress, RecordAmount)>,
    /// Amount of change included in the transaction from the fee.
    ///
    /// Every transaction includes a fee, but the record used to pay the fee may be larger than the
    /// actual fee. In this case, one of the outputs of the transaction will contain change from the
    /// fee, which the transaction sender receives when the transaction is finalized.
    ///
    /// Note that `None` indicates that the amount of change is unknown, not that there is no
    /// change, which would be indicated by `Some(0)`. The amount of change may be unknown if, for
    /// example, this is a transaction we received from someone else, in which case we may not know
    /// how much of a fee they paid and how much change they expect to get.
    fee_change: Option<RecordAmount>,
    /// Amount of change included in the transaction in the asset being transferred.
    ///
    /// For non-native transfers, the amount of the asset being transferred which is consumed by the
    /// transaction may exceed the amount that the sender wants to transfer, due to the way discrete
    /// record amounts break down. In this case, one of the outputs of the transaction will contain
    /// change from the fee, which the transaction sender receives when the transaction is
    /// finalized.
    ///
    /// For native transfers, the transfer inputs and the fee input get mixed together, so there is
    /// only one change output, which accounts for both the fee change and the asset change. In
    /// this case, the total amount of change will be reflected in `fee_change` and `asset_change`
    /// will be `Some(0)`.
    ///
    /// Note that `None` indicates that the amount of change is unknown, not that there is no
    /// change, which would be indicated by `Some(0)`. The amount of change may be unknown if, for
    /// example, this is a transaction we received from someone else, and we do not hold the
    /// necessary viewing keys to inspect the change outputs of the transaction.
    asset_change: Option<RecordAmount>,
    /// If we sent this transaction, a receipt to track its progress.
    receipt: Option<TransactionReceipt<L>>,
}

impl<L: Ledger> Transaction<L> {
    #![allow(dead_code)]
    pub fn uid(&self) -> &TransactionUID<L> {
        &self.uid
    }
    pub fn timeout(&self) -> Option<u64> {
        self.timeout
    }
    pub fn memos(&self) -> &Vec<Option<ReceiverMemo>> {
        &self.memos
    }
    pub fn sig(&self) -> &Signature {
        &self.sig
    }
    pub fn inputs(&self) -> &Vec<RecordOpening> {
        &self.inputs
    }
    pub fn outputs(&self) -> &Vec<RecordOpening> {
        &self.outputs
    }
    pub fn time(&self) -> &DateTime<Local> {
        &self.time
    }
    pub fn asset(&self) -> &AssetCode {
        &self.asset
    }
    pub fn kind(&self) -> &TransactionKind<L> {
        &self.kind
    }
    pub fn senders(&self) -> &Vec<UserAddress> {
        &self.senders
    }
    pub fn receivers(&self) -> &Vec<(UserAddress, RecordAmount)> {
        &self.receivers
    }
    pub fn fee_change(&self) -> &Option<RecordAmount> {
        &self.fee_change
    }
    pub fn asset_change(&self) -> &Option<RecordAmount> {
        &self.asset_change
    }
    pub fn receipt(&self) -> &Option<TransactionReceipt<L>> {
        &self.receipt
    }
}

type TransactionsStore<L> = KeyValueStore<TransactionUID<L>, Transaction<L>>;

/// An editor to create or update the transaction or transactions store.
pub struct TransactionEditor<'a, L: Ledger + Serialize + DeserializeOwned> {
    transaction: Transaction<L>,
    store: &'a mut Transactions<L>,
}

impl<'a, L: Ledger + Serialize + DeserializeOwned> TransactionEditor<'a, L> {
    /// Create a transaction editor.
    fn new(store: &'a mut Transactions<L>, transaction: Transaction<L>) -> Self {
        Self { transaction, store }
    }

    pub fn set_status(mut self, status: TransactionStatus) -> Self {
        self.transaction.status = status;
        self
    }

    pub fn clear_timeout(mut self) -> Self {
        self.transaction.timeout = None;
        self
    }

    /// Add fee change record to the transaction once it is certain
    pub fn with_fee_change(mut self, amount: RecordAmount) -> Self {
        self.transaction.fee_change = Some(amount);
        self
    }

    /// Add asset change record to the transaction once it is certain
    pub fn with_asset_change(mut self, amount: RecordAmount) -> Self {
        self.transaction.asset_change = Some(amount);
        self
    }

    /// Add the transaction receipt when it is recieved
    pub fn with_receipt(mut self, receipt: TransactionReceipt<L>) -> Self {
        self.transaction.receipt = Some(receipt);
        self
    }

    /// Add the transaction hash, should be called after this transaction is committed
    pub fn with_hash(mut self, hash: TransactionHash<L>) -> Self {
        self.transaction.hash = Some(hash);
        self
    }

    /// Add the UIDs of memos we are waiting on to complete the transaction
    pub fn add_pending_uids(mut self, uids: &[u64]) -> Self {
        for uid in uids {
            self.transaction.pending_uids.insert(*uid);
        }
        self
    }
    /// remove a UID of a memo we were waiting because it was received
    pub fn remove_pending_uid(mut self, uid: u64) -> Self {
        self.transaction.pending_uids.remove(&uid);
        self
    }

    /// Save the transaction to the store.
    ///
    /// Returns the stored transaction.
    pub fn save(&mut self) -> Result<Transaction<L>, KeystoreError<L>> {
        self.store.store(&self.transaction.uid, &self.transaction)?;
        Ok(self.transaction.clone())
    }
}

impl<'a, L: Ledger + Serialize + DeserializeOwned> Deref for TransactionEditor<'a, L> {
    type Target = Transaction<L>;

    fn deref(&self) -> &Transaction<L> {
        &self.transaction
    }
}

impl<'a, L: Ledger + Serialize + DeserializeOwned> DerefMut for TransactionEditor<'a, L> {
    fn deref_mut(&mut self) -> &mut Transaction<L> {
        &mut self.transaction
    }
}

pub struct TransactionParams<L: Ledger> {
    pub uid: TransactionUID<L>,
    pub timeout: Option<u64>,
    pub status: TransactionStatus,
    pub memos: Vec<Option<ReceiverMemo>>,
    pub sig: Signature,
    pub inputs: Vec<RecordOpening>,
    pub outputs: Vec<RecordOpening>,
    pub time: DateTime<Local>,
    pub asset: AssetCode,
    pub kind: TransactionKind<L>,
    pub senders: Vec<UserAddress>,
    pub receivers: Vec<(UserAddress, RecordAmount)>,
}

/// Transactions stored in an transactions store.
pub struct Transactions<L: Ledger + Serialize + DeserializeOwned> {
    /// A key-value store for transactions.
    store: TransactionsStore<L>,
    txn_by_hash: PersistableHashMap<TransactionHash<L>, TransactionUID<L>>,
    expiring_txns: PersistableBTreeMultiMap<u64, TransactionUID<L>>,
    /// Maps pending memo UIDs to the Transaction<L>they come from
    uids_awaiting_memos: PersistableHashMap<u64, TransactionUID<L>>,
}

impl<L: Ledger + Serialize + DeserializeOwned> Transactions<L> {
    #![allow(dead_code)]

    /// Load a transactions store.
    pub fn new(
        loader: &mut AtomicStoreLoader,
        adaptor: EncryptingResourceAdapter<(TransactionUID<L>, Option<Transaction<L>>)>,
        fill_size: u64,
    ) -> Result<Self, KeystoreError<L>> {
        let log = AppendLog::load(loader, adaptor, "keystore_transactions", fill_size)?;
        let store = TransactionsStore::<L>::new(log)?;
        let mut transactions = Self {
            store,
            txn_by_hash: Persistable::new(),
            expiring_txns: Persistable::new(),
            uids_awaiting_memos: Persistable::new(),
        };
        transactions.reload();
        Ok(transactions)
    }

    /// Reload from disc to, rebuilds the indices
    pub fn reload(&mut self) {
        self.txn_by_hash = Persistable::new();
        self.expiring_txns = Persistable::new();
        self.uids_awaiting_memos = Persistable::new();
        for txn in self.store.iter() {
            if txn.hash.is_some() {
                self.txn_by_hash
                    .insert((txn.hash.as_ref().unwrap().clone(), txn.uid().clone()));
            }
            if let Some(timeout) = txn.timeout() {
                self.expiring_txns.insert((timeout, txn.uid().clone()));
            }
            for pending in &txn.pending_uids {
                self.uids_awaiting_memos
                    .insert((*pending, txn.uid().clone()));
            }
        }
    }

    fn store(
        &mut self,
        uid: &TransactionUID<L>,
        txn: &Transaction<L>,
    ) -> Result<(), KeystoreError<L>> {
        self.store.store(uid, txn)?;
        self.reload();
        Ok(())
    }

    /// Iterate through the transactions.
    pub fn iter(&self) -> impl Iterator<Item = Transaction<L>> + '_ {
        self.store.iter().cloned()
    }

    /// Get the transaction by the uid from the store.
    pub fn get(&self, uid: &TransactionUID<L>) -> Result<Transaction<L>, KeystoreError<L>> {
        Ok(self.store.load(uid)?)
    }

    /// Get a mutable transaction editor by the uid from the store.
    pub fn get_mut(
        &mut self,
        uid: &TransactionUID<L>,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = self.get(uid)?;
        Ok(TransactionEditor::new(self, txn))
    }

    /// Get a Transaction with the id of a memo, will return the transaction which is awaiting the memo
    pub fn with_memo_id(&self, id: u64) -> Result<Transaction<L>, KeystoreError<L>> {
        let uid = self
            .uids_awaiting_memos
            .index()
            .get(&id)
            .ok_or(KeyValueStoreError::KeyNotFound)?;
        Ok(self.get(uid).unwrap())
    }

    /// Same as with_memo_id but return a TransactionEditor
    pub fn with_memo_id_mut(
        &mut self,
        id: u64,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = self.with_memo_id(id)?;
        Ok(TransactionEditor::new(self, txn))
    }

    /// Get a Transaction for a given TransactionHash
    pub fn with_hash(&self, hash: &TransactionHash<L>) -> Result<Transaction<L>, KeystoreError<L>> {
        let uid = self
            .txn_by_hash
            .index()
            .get(hash)
            .ok_or(KeyValueStoreError::KeyNotFound)?;
        Ok(self.get(uid).unwrap())
    }

    /// Get a TransactionEditor for a given TransactionHash
    pub fn with_hash_mut(
        &mut self,
        hash: &TransactionHash<L>,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = self.with_hash(hash)?;
        Ok(TransactionEditor::new(self, txn))
    }

    /// Get all the transactions timing out at the provided time.  
    pub fn with_timeout(
        &self,
        timeout: u64,
    ) -> Result<impl Iterator<Item = Transaction<L>> + '_, KeystoreError<L>> {
        let uids = self
            .expiring_txns
            .index()
            .get(&timeout)
            .ok_or(KeyValueStoreError::KeyNotFound)?;

        Ok(uids.iter().map(move |uid| self.get(uid).unwrap()))
    }

    /// Remove a transaction from the pending index when it is known to have timed out
    pub async fn remove_expired(&mut self, timeout: u64) -> Result<(), KeystoreError<L>> {
        if let Some(expiring_uids) = self
            .expiring_txns
            .index()
            .clone()
            .get_mut(&timeout)
            .cloned()
        {
            for uid in expiring_uids.iter() {
                let editor = self.get_mut(uid)?;
                editor
                    .set_status(TransactionStatus::Rejected)
                    .clear_timeout()
                    .save()?;
                self.expiring_txns.remove((timeout, uid.clone()));
            }
        }
        Ok(())
    }

    /// Commit the store version.
    pub fn commit(&mut self) -> Result<(), KeystoreError<L>> {
        self.txn_by_hash.commit();
        self.expiring_txns.commit();
        self.uids_awaiting_memos.commit();
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert(&mut self) -> Result<(), KeystoreError<L>> {
        self.txn_by_hash.revert();
        self.expiring_txns.revert();
        self.uids_awaiting_memos.revert();
        Ok(self.store.revert_version()?)
    }

    /// Create an Transaction.
    ///
    /// When we first create a transaction it won't know all of it's values until
    /// specific events happen on chain.  When the block for this transaction commited
    /// We will learn it's Hash, Recept, and PendingUIDs as well as be certain of the
    /// Fee and Asset Change records.
    ///
    /// Returns the editor for the created transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        params: TransactionParams<L>,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = Transaction::<L> {
            uid: params.uid,
            timeout: params.timeout,
            hash: None,
            status: params.status,
            pending_uids: HashSet::new(),
            memos: params.memos,
            sig: params.sig,
            inputs: params.inputs,
            outputs: params.outputs,
            time: params.time,
            asset: params.asset,
            kind: params.kind,
            senders: params.senders,
            receivers: params.receivers,
            fee_change: None,
            asset_change: None,
            receipt: None,
        };
        if let Some(timeout) = params.timeout {
            self.expiring_txns.insert((timeout, txn.uid().clone()));
        }

        let mut editor = TransactionEditor::new(self, txn);
        editor.save()?;
        Ok(editor)
    }

    /// Deletes an transaction from the store.
    ///
    /// Returns the deleted transaction.
    pub fn delete(&mut self, uid: &TransactionUID<L>) -> Result<Transaction<L>, KeystoreError<L>> {
        let txn = self.store.delete(uid)?;
        // Rebuild the indices
        self.reload();
        Ok(txn)
    }
}
