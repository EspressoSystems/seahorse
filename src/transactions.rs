// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The assets module.
//!
//! This module defines [Transaction], [TransactionEditor], and [Transactions], which provide CURD (create, read,
//! update, and delete) operations, with the use of [KeyValueStore] to control the assets resource.

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
    uid: TransactionUID<L>,
    // PendingTransaction
    timeout: u64,
    pub hash: Option<TransactionHash<L>>,

    // TransactionAwaitingMemo
    // The uids of the outputs of this transaction for which memos have not yet been posted.
    pub pending_uids: HashSet<u64>,

    // TransactionInfo
    /// The accounts sending the transaction.
    accounts: Vec<UserAddress>,
    /// A receiver memo for each output, except for burned outputs.
    memos: Vec<Option<ReceiverMemo>>,
    sig: Signature,
    /// If the transaction is a freeze, the expected frozen/unfrozen outputs.
    freeze_outputs: Vec<RecordOpening>,
    inputs: Vec<RecordOpening>,
    outputs: Vec<RecordOpening>,

    // TransactionHistoryEntry
    time: DateTime<Local>,
    asset: AssetCode,
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
    pub fee_change: Option<RecordAmount>,
    /// Amount of change included in the transaction in the asset being transferred.
    ///
    /// For non-native transfers, the amount of the asset being transferred which is consumed by the
    /// transaction may exceed the amount that the sender wants to transfer, due to the way discrete
    /// record amounts break down. In this case, one of the outputs of the transaction will contain
    /// change from the fee, which the transaction sender receives when the transaction is
    /// finalized.
    ///
    /// For native transfers, the transfer inputs and the fee input get mixed together, so there is
    /// only one change output, which accounts for both the fee change and the transfer change. In
    /// this case, the total amount of change will be reflected in `fee_change` and `asset_change`
    /// will be `Some(0)`.
    ///
    /// Note that `None` indicates that the amount of change is unknown, not that there is no
    /// change, which would be indicated by `Some(0)`. The amount of change may be unknown if, for
    /// example, this is a transaction we received from someone else, and we do not hold the
    /// necessary viewing keys to inspect the change outputs of the transaction.
    pub asset_change: Option<RecordAmount>,
    /// If we sent this transaction, a receipt to track its progress.
    pub receipt: Option<TransactionReceipt<L>>,
}

impl<L: Ledger> Transaction<L> {
    #![allow(dead_code)]
    pub fn uid(&self) -> &TransactionUID<L> {
        &self.uid
    }
    pub fn timeout(&self) -> u64 {
        self.timeout
    }
    /// Get the reciever memos.
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
    store: &'a mut TransactionsStore<L>,
}

impl<'a, L: Ledger + Serialize + DeserializeOwned> TransactionEditor<'a, L> {
    /// Create a transaction editor.
    fn new(store: &'a mut TransactionsStore<L>, transaction: Transaction<L>) -> Self {
        Self { transaction, store }
    }

    pub fn with_fee_change(mut self, amount: RecordAmount) -> Self {
        self.transaction.fee_change = Some(amount);
        self
    }

    pub fn with_asset_change(mut self, amount: RecordAmount) -> Self {
        self.transaction.asset_change = Some(amount);
        self
    }

    pub fn with_receipt(mut self, receipt: TransactionReceipt<L>) -> Self {
        self.transaction.receipt = Some(receipt);
        self
    }

    pub fn with_hash(mut self, hash: TransactionHash<L>) -> Self {
        self.transaction.hash = Some(hash);
        self
    }

    pub fn add_pending_uids(mut self, uids: &Vec<u64>) -> Self {
        for uid in uids {
            self.transaction.pending_uids.insert(*uid);
        }
        self
    }
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
    /// Maps pending UIDs to the Transaction<L>they come from
    uids_awaiting_memos: HashMap<u64, TransactionUID<L>>,
}

impl<L: Ledger + Serialize + DeserializeOwned> Transactions<L> {
    #![allow(dead_code)]

    /// Load an assets store.
    ///
    /// None of the loaded assets will be verified until `verify_assets` is called.
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

    /// Iterate through the assets.
    pub fn iter(&self) -> impl Iterator<Item = Transaction<L>> + '_ {
        self.store.iter().cloned()
    }

    /// Get the asset by the code from the store.
    pub fn get(&self, uid: &TransactionUID<L>) -> Result<Transaction<L>, KeystoreError<L>> {
        Ok(self.store.load(uid)?)
    }

    /// Get a mutable asset editor by the code from the store.
    pub fn get_mut(
        &mut self,
        uid: &TransactionUID<L>,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = self.get(uid)?;
        Ok(TransactionEditor::new(&mut self.store, txn))
    }

    pub fn with_memo_id(&self, id: u64) -> Result<Transaction<L>, KeystoreError<L>> {
        let uid = self
            .uids_awaiting_memos
            .get(&id)
            .ok_or(KeyValueStoreError::KeyNotFound)?;
        Ok(self.get(uid).unwrap())
    }

    pub fn with_memo_id_mut(
        &mut self,
        id: u64,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = self.with_memo_id(id)?;
        Ok(TransactionEditor::new(&mut self.store, txn))
    }

    pub fn with_hash(&self, hash: &TransactionHash<L>) -> Result<Transaction<L>, KeystoreError<L>> {
        let uid = self
            .txn_by_hash
            .get(&hash)
            .ok_or(KeyValueStoreError::KeyNotFound)?;
        Ok(self.get(uid).unwrap())
    }

    pub fn with_hash_mut(
        &mut self,
        hash: &TransactionHash<L>,
    ) -> Result<TransactionEditor<'_, L>, KeystoreError<L>> {
        let txn = self.with_hash(hash)?;
        Ok(TransactionEditor::new(&mut self.store, txn))
    }

    /// Get all the transactions timing out at the provided time.  There is no mutable way to get this
    /// Collection because we should only be edditing one thing at a time
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
    pub async fn remove_pending_uids(
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

    pub async fn remove_pending(
        &mut self,
        timeout: u64,
        uid: &TransactionUID<L>,
    ) -> Result<(), KeystoreError<L>> {
        if let Some(expiring) = self.expiring_txns.get_mut(&timeout) {
            expiring.remove(uid);
            if expiring.is_empty() {
                self.expiring_txns.remove(&timeout);
            }
        }
        Ok(())
    }

    /// Create an unverified asset.
    ///
    /// If the store doesn't have an asset with the same code, adds the created asset to the store.
    /// Otherwise, updates the exisiting asset.
    ///
    /// Returns the editor for the created asset.
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
        asset: AssetCode,
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
            asset,
            kind,
            senders,
            receivers,
            fee_change: None,   // fee_change
            asset_change: None, // asset_change
            receipt: None,      // receipt
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
