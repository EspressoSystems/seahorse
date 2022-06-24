// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The trasaction module.
//!
//! This module defines [Transaction], [TransactionEditor], and [Transactions], which provide CURD (create, read,
//! update, and delete) operations, with the use of [KeyValueStore] to control the transactions resource.

use crate::{
    key_value_store::*, AssetCode, KeystoreError, Ledger, RecordAmount, TransactionHash,
    TransactionKind, TransactionReceipt, TransactionUID,
};
use chrono::{DateTime, Local};
use jf_cap::{
    keys::UserAddress,
    structs::{ReceiverMemo, RecordOpening},
    Signature,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::{Deref, DerefMut};

/// A Transaction<L>with its UID as the primary key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction<L: Ledger> {
    /// Identifier for the Transaction, also the primary key in storage
    uid: TransactionUID<L>,
    /// Time when this transaction will expire if it's not completed
    timeout: u64,
    /// Hash which appears in the commited block for this transaction
    hash: Option<TransactionHash<L>>,

    // The uids of the outputs of this transaction for which memos have not yet been posted.
    pending_uids: HashSet<u64>,

    /// The accounts sending the transaction.
    accounts: Vec<UserAddress>,
    /// A receiver memo for each output, except for burned outputs.
    memos: Vec<Option<ReceiverMemo>>,
    sig: Signature,
    /// If the transaction is a freeze, the expected frozen/unfrozen outputs.
    freeze_outputs: Vec<RecordOpening>,
    inputs: Vec<RecordOpening>,
    outputs: Vec<RecordOpening>,

    /// Time when this transaction was created in the transaction builder
    time: DateTime<Local>,
    /// The transaction we are transacting
    transaction: AssetCode,
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
    /// Amount of change included in the transaction in the transaction being transferred.
    ///
    /// For non-native transfers, the amount of the transaction being transferred which is consumed by the
    /// transaction may exceed the amount that the sender wants to transfer, due to the way discrete
    /// record amounts break down. In this case, one of the outputs of the transaction will contain
    /// change from the fee, which the transaction sender receives when the transaction is
    /// finalized.
    ///
    /// For native transfers, the transfer inputs and the fee input get mixed together, so there is
    /// only one change output, which accounts for both the fee change and the transfer change. In
    /// this case, the total amount of change will be reflected in `fee_change` and `transaction_change`
    /// will be `Some(0)`.
    ///
    /// Note that `None` indicates that the amount of change is unknown, not that there is no
    /// change, which would be indicated by `Some(0)`. The amount of change may be unknown if, for
    /// example, this is a transaction we received from someone else, and we do not hold the
    /// necessary viewing keys to inspect the change outputs of the transaction.
    transaction_change: Option<RecordAmount>,
    /// If we sent this transaction, a receipt to track its progress.
    receipt: Option<TransactionReceipt<L>>,
}

impl<L: Ledger> Transaction<L> {
    #![allow(dead_code)]
    pub fn uid(&self) -> &TransactionUID<L> {
        &self.uid
    }
    pub fn timeout(&self) -> u64 {
        self.timeout
    }
    pub fn memos(&self) -> &Vec<Option<ReceiverMemo>> {
        &self.memos
    }
    pub fn accounts(&self) -> &Vec<UserAddress> {
        &self.accounts
    }
    pub fn sig(&self) -> &Signature {
        &self.sig
    }
    pub fn freeze_outputs(&self) -> &Vec<RecordOpening> {
        &self.freeze_outputs
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
    pub fn transaction(&self) -> &AssetCode {
        &self.transaction
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
    pub fn transaction_change(&self) -> &Option<RecordAmount> {
        &self.transaction_change
    }
    pub fn receipt(&self) -> &Option<TransactionReceipt<L>> {
        &self.receipt
    }
}

type TransactionsStore<L> = KeyValueStore<TransactionUID<L>, Transaction<L>>;

/// An editor to create or update the transaction or transactions store.
pub struct TransactionEditor<'a, L: Ledger + Serialize + DeserializeOwned> {
    transaction: Transaction<L>,
    store: &'a mut TransactionsStore<L>,
}

impl<'a, L: Ledger + Serialize + DeserializeOwned> TransactionEditor<'a, L> {
    /// Create a transaction editor.
    fn new(store: &'a mut TransactionsStore<L>, transaction: Transaction<L>) -> Self {
        Self { transaction, store }
    }

    /// Add fee change record to the transaction once it is certain
    pub fn with_fee_change(mut self, amount: RecordAmount) -> Self {
        self.transaction.fee_change = Some(amount);
        self
    }

    /// Add transaction change record to the transaction once it is certain
    pub fn with_transaction_change(mut self, amount: RecordAmount) -> Self {
        self.transaction.transaction_change = Some(amount);
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

/// Transactions stored in an transactions store.
pub struct Transactions<L: Ledger + Serialize + DeserializeOwned> {
    /// A key-value store for transactions.
    store: TransactionsStore<L>,
    txn_by_hash: HashMap<TransactionHash<L>, TransactionUID<L>>,
    expiring_txns: BTreeMap<u64, HashSet<TransactionUID<L>>>,
    /// Maps pending memo UIDs to the Transaction<L>they come from
    uids_awaiting_memos: HashMap<u64, TransactionUID<L>>,
}

impl<L: Ledger + Serialize + DeserializeOwned> Transactions<L> {
    #![allow(dead_code)]

    /// Load a transactions store.
    pub fn new(store: TransactionsStore<L>) -> Result<Self, KeystoreError<L>> {
        let txn_by_hash = store
            .iter()
            .filter(|txn| txn.hash.is_some())
            .map(|txn| (txn.hash.as_ref().unwrap().clone(), txn.uid().clone()))
            .collect();
        let mut expiring_txns = BTreeMap::new();
        let mut uids_awaiting_memos = HashMap::new();
        for txn in store.iter() {
            expiring_txns
                .entry(txn.timeout())
                .or_insert_with(HashSet::default)
                .insert(txn.uid().clone());
            for pending in &txn.pending_uids {
                uids_awaiting_memos.insert(*pending, txn.uid().clone());
            }
        }
        Ok(Self {
            store,
            txn_by_hash,
            expiring_txns,
            uids_awaiting_memos,
        })
    }

    /// Iterate through the transactions.
    pub fn iter(&self) -> impl Iterator<Item = Transaction<L>> + '_ {
        self.store.iter().cloned()
    }

    /// Get the transaction by the uid from the store.
    pub fn get(&self, uid: &TransactionUID<L>) -> Result<Transaction<L>, KeystoreError<L>> {
        Ok(self.store.load(uid)?)
    }

    /// Get a mutable transaction editor by the code from the store.
    pub fn get_mut(
        &mut self,
        uid: &TransactionUID<L>,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = self.get(uid)?;
        Ok(TransactionEditor::new(&mut self.store, txn))
    }

    /// Get a Transaction with the id of a memo, will return the transaction which is awaiting the memo
    pub fn with_memo_id(&self, id: u64) -> Result<Transaction<L>, KeystoreError<L>> {
        let uid = self
            .uids_awaiting_memos
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
        Ok(TransactionEditor::new(&mut self.store, txn))
    }

    /// Get a Transaction for a given TransactionHash
    pub fn with_hash(&self, hash: &TransactionHash<L>) -> Result<Transaction<L>, KeystoreError<L>> {
        let uid = self
            .txn_by_hash
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
        Ok(TransactionEditor::new(&mut self.store, txn))
    }

    /// Get all the transactions timing out at the provided time.  There is no mutable way to get this
    /// Collection because we should only be editting one thing at a time
    pub fn with_timeout(&self, timeout: u64) -> Result<Vec<Transaction<L>>, KeystoreError<L>> {
        let uids = self
            .expiring_txns
            .get(&timeout)
            .ok_or(KeyValueStoreError::KeyNotFound)?;

        Ok(uids.iter().map(|uid| self.get(uid).unwrap()).collect())
    }

    /// Commit the store version.
    pub fn commit(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.revert_version()?)
    }

    /// Add a transaction hash to the index and update the stored transaction with this has
    pub fn insert_hash(
        &mut self,
        hash: TransactionHash<L>,
        uid: &TransactionUID<L>,
    ) -> Result<(), KeystoreError<L>> {
        let editor = self.get_mut(uid)?;
        editor.with_hash(hash.clone()).save()?;
        self.txn_by_hash.insert(hash, uid.clone());
        Ok(())
    }

    /// Add a list of Memo ids a transaction is waiting for.  We update the index and the stored transaction
    pub fn add_pending_uids(
        &mut self,
        txn_uid: &TransactionUID<L>,
        pending_uids: Vec<u64>,
    ) -> Result<(), KeystoreError<L>> {
        let txn_editor = self.get_mut(txn_uid)?;
        txn_editor.add_pending_uids(&pending_uids).save()?;
        for uid in pending_uids {
            self.uids_awaiting_memos.insert(uid, txn_uid.clone());
        }

        Ok(())
    }

    /// Remove pending memo ids from the index and the stored transactions which were awaiting those ids
    pub async fn remove_pending_memo_uids(
        &mut self,
        pending_uids: Vec<u64>,
    ) -> Result<(), KeystoreError<L>> {
        for uid in pending_uids {
            if let Some(txn_uid) = self.uids_awaiting_memos.remove(&uid) {
                let txn_editor = self.get_mut(&txn_uid)?;
                txn_editor.remove_pending_uid(uid).save()?;
            }
        }

        Ok(())
    }

    /// Remove a transaction from the pending index when it is known to have timed out
    pub async fn remove_pending_txn(&mut self, timeout: u64, uid: &TransactionUID<L>) {
        if let Some(expiring) = self.expiring_txns.get_mut(&timeout) {
            expiring.remove(uid);
            if expiring.is_empty() {
                self.expiring_txns.remove(&timeout);
            }
        }
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
        uid: TransactionUID<L>,
        timeout: u64,
        accounts: Vec<UserAddress>,
        memos: Vec<Option<ReceiverMemo>>,
        sig: Signature,
        freeze_outputs: Vec<RecordOpening>,
        inputs: Vec<RecordOpening>,
        outputs: Vec<RecordOpening>,
        time: DateTime<Local>,
        transaction: AssetCode,
        kind: TransactionKind<L>,
        senders: Vec<UserAddress>,
        receivers: Vec<(UserAddress, RecordAmount)>,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = Transaction::<L> {
            uid,
            timeout,
            hash: None,
            pending_uids: HashSet::new(), //pending_uids
            accounts,
            memos,
            sig,
            /// If the transaction is a freeze, the expected frozen/unfrozen outputs.
            freeze_outputs,
            inputs,
            outputs,
            time,
            transaction,
            kind,
            senders,
            receivers,
            fee_change: None,         // fee_change
            transaction_change: None, // transaction_change
            receipt: None,            // receipt
        };
        self.expiring_txns
            .entry(timeout)
            .or_insert_with(HashSet::default)
            .insert(txn.uid().clone());
        let mut editor = TransactionEditor::new(&mut self.store, txn);
        editor.save()?;
        Ok(editor)
    }

    /// Deletes an transaction from the store.
    ///
    /// Returns the deleted transaction.
    pub fn delete(&mut self, code: &TransactionUID<L>) -> Result<Transaction<L>, KeystoreError<L>> {
        Ok(self.store.delete(code)?)
    }
}
