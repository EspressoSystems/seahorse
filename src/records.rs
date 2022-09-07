// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The records module.
//!
//! This module defines [Record], [RecordsEditor], and [Records], which provide CURD (create, read,
//! update, and delete) operations, with the use of [KeyValueStore] to control the transactions resource.

use crate::{
    key_value_store::*, AssetCode, EncryptingResourceAdapter, KeystoreError, Ledger, RecordAmount,
};
use atomic_store::{AppendLog, AtomicStoreLoader};
use chrono::{DateTime, Local};
use jf_cap::{
    keys::UserAddress,
    structs::{AssetDefinition, FreezeFlag, Nullifier, RecordOpening},
};
use net::UserPubKey;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, Deserialize, Serialize)]
/// A Record with it's uid (u64) as the key
pub struct Record {
    /// All the information required to create commitments/proofs for this record
    ro: RecordOpening,
    /// Identifier for this record and its primary key in storage
    uid: u64,
    /// The nullifier that represent the consumption of this asset record
    nullifier: Nullifier,
    /// if Some(t), this record is on hold until the validator timestamp surpasses `t`, because this
    /// record has been used as an input to a transaction that is not yet confirmed.
    hold_until: Option<u64>,
    /// The time when the record was created.
    created_time: DateTime<Local>,
    /// The last time when the record was last modified.
    modified_time: DateTime<Local>,
}

impl Record {
    pub fn uid(&self) -> u64 {
        self.uid
    }
    pub fn record_opening(&self) -> &RecordOpening {
        &self.ro
    }

    pub fn amount(&self) -> RecordAmount {
        self.ro.amount.into()
    }

    pub fn asset_definition(&self) -> &AssetDefinition {
        &self.ro.asset_def
    }
    pub fn asset_code(&self) -> AssetCode {
        self.asset_definition().code
    }

    pub fn pub_key(&self) -> &UserPubKey {
        &self.ro.pub_key
    }

    pub fn freeze_flag(&self) -> FreezeFlag {
        self.ro.freeze_flag
    }

    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    pub fn on_hold(&self, now: u64) -> bool {
        matches!(self.hold_until, Some(t) if t > now)
    }

    pub fn created_time(&self) -> DateTime<Local> {
        self.created_time
    }

    pub fn modified_time(&self) -> DateTime<Local> {
        self.modified_time
    }
}

/// An editor to update a record or records store
pub struct RecordEditor<'a> {
    record: Record,
    store: &'a mut Records,
}
impl<'a> RecordEditor<'a> {
    #![allow(dead_code)]
    /// Create a record editor.
    fn new(store: &'a mut Records, record: Record) -> Self {
        Self { record, store }
    }

    /// Update when this record will be on hold until if it is pending
    /// Set this when the record is part of a transaction that isn't confirmed
    pub(crate) fn hold_until(mut self, until: u64) -> Self {
        self.record.hold_until = Some(until);
        self
    }

    /// Update the record to no longer be on hold
    pub(crate) fn unhold(mut self) -> Self {
        self.record.hold_until = None;
        self
    }

    /// Save the record to the store.
    ///
    /// Returns the stored record.
    pub fn save<L: Ledger>(&mut self) -> Result<Record, KeystoreError<L>> {
        self.store.store(self.record.uid, &self.record)?;
        self.record.modified_time = Local::now();
        Ok(self.record.clone())
    }
}

impl<'a> Deref for RecordEditor<'a> {
    type Target = Record;

    fn deref(&self) -> &Record {
        &self.record
    }
}

impl<'a> DerefMut for RecordEditor<'a> {
    fn deref_mut(&mut self) -> &mut Record {
        &mut self.record
    }
}

type RecordsStore = KeyValueStore<u64, Record>;

pub struct Records {
    store: RecordsStore,
    /// Record (size, uid) indexed by asset type, owner, and freeze status, for easy allocation as
    /// transfer or freeze inputs. The records for each asset are ordered by increasing size, which
    /// makes it easy to implement a worst-fit allocator that minimizes fragmentation.
    asset_records:
        PersistableHashMapBTreeMultiMap<(AssetCode, UserAddress, FreezeFlag), (RecordAmount, u64)>,
    /// Record uids indexed by nullifier, for easy removal when confirmed as transfer inputs
    nullifier_records: PersistableHashMap<Nullifier, u64>,
}

impl Records {
    #![allow(dead_code)]

    pub fn new<L: Ledger>(
        loader: &mut AtomicStoreLoader,
        adaptor: EncryptingResourceAdapter<(u64, Option<Record>)>,
        fill_size: u64,
    ) -> Result<Self, KeystoreError<L>> {
        let log = AppendLog::load(loader, adaptor, "keystore_records", fill_size)?;
        let store = RecordsStore::new(log)?;
        let mut records = Self {
            store,
            asset_records: PersistableMap::new(),
            nullifier_records: PersistableMap::new(),
        };
        for record in records.store.iter() {
            let ro = &record.ro;
            records.asset_records.insert((
                (
                    ro.asset_def.code,
                    ro.pub_key.address().clone(),
                    ro.freeze_flag,
                ),
                (record.ro.amount.into(), record.uid),
            ));
            records
                .nullifier_records
                .insert((record.nullifier, record.uid));
        }
        records.asset_records.commit();
        records.nullifier_records.commit();
        Ok(records)
    }

    /// Create a Record
    ///
    /// Returns an editor to the newly created Record
    pub fn create<L: Ledger>(
        &mut self,
        uid: u64,
        ro: RecordOpening,
        nullifier: Nullifier,
    ) -> Result<RecordEditor<'_>, KeystoreError<L>> {
        let time = Local::now();
        let record = Record {
            ro,
            uid,
            nullifier,
            hold_until: None,
            created_time: time,
            modified_time: time,
        };
        let ro = &record.ro;
        self.asset_records.insert((
            (ro.asset_def.code, ro.pub_key.address(), ro.freeze_flag),
            (record.ro.amount.into(), record.uid),
        ));
        self.nullifier_records
            .insert((record.nullifier, record.uid));
        let mut editor = RecordEditor::new(self, record);
        editor.save()?;
        Ok(editor)
    }

    fn store<L: Ledger>(&mut self, uid: u64, record: &Record) -> Result<(), KeystoreError<L>> {
        self.store.store(&uid, record)?;
        Ok(())
    }

    /// Returns an Iterator to all the Records in the store
    pub fn iter(&self) -> impl Iterator<Item = Record> + '_ {
        self.store.iter().cloned()
    }

    /// Get a record from a uid from the store
    pub fn get<L: Ledger>(&self, uid: u64) -> Result<Record, KeystoreError<L>> {
        Ok(self.store.load(&uid)?)
    }

    /// get a Record Editor by uid from storage
    pub fn get_mut<L: Ledger>(&mut self, uid: u64) -> Result<RecordEditor, KeystoreError<L>> {
        let record = self.store.load(&uid)?;
        Ok(RecordEditor::new(self, record))
    }

    /// Get a Record from a Nullifier
    pub fn with_nullifier<L: Ledger>(
        &self,
        nullifier: &Nullifier,
    ) -> Result<Record, KeystoreError<L>> {
        let uid = self
            .nullifier_records
            .index()
            .get(nullifier)
            .ok_or(KeyValueStoreError::KeyNotFound)?;
        self.get(*uid)
    }
    /// Get a RecordEditor from a Nullifier
    pub fn with_nullifier_mut<L: Ledger>(
        &mut self,
        nullifier: &Nullifier,
    ) -> Result<RecordEditor, KeystoreError<L>> {
        let uid = *self
            .nullifier_records
            .index()
            .get(nullifier)
            .ok_or(KeyValueStoreError::KeyNotFound)?;
        self.get_mut(uid)
    }

    /// Get records associated with an asset and account which are either frozen or unfrozen
    /// Useful for finding records for transaction inputs
    pub fn get_spendable<L: Ledger>(
        &self,
        asset: &AssetCode,
        owner: &UserAddress,
        frozen: FreezeFlag,
    ) -> Option<impl Iterator<Item = Record> + '_> {
        let unspent_records = self
            .asset_records
            .index()
            .get(&(*asset, owner.clone(), frozen));
        unspent_records.map(|records| {
            records
                .iter()
                .rev()
                .map(move |(_, uid)| self.get::<L>(*uid).unwrap())
        })
    }

    /// Get one record with the exact amount or return None.  
    pub fn get_spendable_with_amount<L: Ledger>(
        &self,
        asset: &AssetCode,
        owner: &UserAddress,
        frozen: FreezeFlag,
        amount: RecordAmount,
        now: u64,
    ) -> Result<Option<Record>, KeystoreError<L>> {
        if let Some(unspent_records) =
            self.asset_records
                .index()
                .get(&(*asset, owner.clone(), frozen))
        {
            let exact_matches = unspent_records.range((amount, 0)..(amount + 1u64.into(), 0));
            for (match_amount, uid) in exact_matches {
                assert_eq!(*match_amount, amount);
                let record = self.get(*uid)?;
                assert_eq!(record.amount(), amount);
                if record.on_hold(now) {
                    continue;
                }
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Commit the store version.
    pub fn commit<L: Ledger>(&mut self) -> Result<(), KeystoreError<L>> {
        self.asset_records.commit();
        self.nullifier_records.commit();
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert<L: Ledger>(&mut self) -> Result<(), KeystoreError<L>> {
        self.asset_records.revert();
        self.nullifier_records.revert();
        Ok(self.store.revert_version()?)
    }

    /// Deletes an record from the store.
    ///
    /// Returns the deleted record.
    pub fn delete<L: Ledger>(&mut self, uid: u64) -> Result<Record, KeystoreError<L>> {
        let record = self.store.delete(&uid)?;
        // Remove the record from  indices
        self.asset_records.remove(&(
            (
                record.asset_definition().code,
                record.pub_key().address(),
                record.freeze_flag(),
            ),
            (record.amount(), record.uid()),
        ));
        self.nullifier_records
            .remove(&(record.nullifier, record.uid));
        Ok(record)
    }

    pub fn delete_by_nullifier<L: Ledger>(
        &mut self,
        nullifier: &Nullifier,
    ) -> Result<Record, KeystoreError<L>> {
        let uid = *self
            .nullifier_records
            .index()
            .get(nullifier)
            .ok_or(KeyValueStoreError::KeyNotFound)?;
        self.delete(uid)
    }
}
