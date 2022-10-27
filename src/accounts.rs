// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The accounts module.
//!
//! This module defines [Account], [AccountEditor], and [Accounts], which provide CURD (create, read,
//! update, and delete) operations, with the use of [KeyValueStore] to control the accounts resource.

use crate::{
    events::{EventSource, LedgerEvent},
    key_scan::{BackgroundKeyScan, KeyPair, ScanOutputs, ScanStatus},
    key_value_store::KeyValueStore,
    EncryptingResourceAdapter, KeystoreError,
};
use atomic_store::{AppendLog, AtomicStoreLoader};
use chrono::{DateTime, Local};
use derivative::Derivative;
use jf_cap::{
    keys::{FreezerKeyPair, UserKeyPair, ViewerKeyPair},
    MerkleCommitment,
};
use reef::Ledger;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, Derivative, Deserialize, Serialize)]
#[serde(bound = "Key: DeserializeOwned + Serialize")]
pub struct Account<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> {
    /// The account key.
    key: Key,
    /// Optional index into the HD key stream.
    ///
    /// `None` means the key is imported, not an HD key.
    index: Option<usize>,
    /// The account description.
    pub description: String,
    /// Whether the account is used.
    used: bool,
    /// Optional ledger scan.
    scan: Option<BackgroundKeyScan<L, Key>>,
    /// The time when the account was created.
    created_time: DateTime<Local>,
    /// The last time when the account was modified.
    modified_time: DateTime<Local>,
}

impl<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> Account<L, Key> {
    /// Get the account key.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Get the account public key.
    pub fn pub_key(&self) -> Key::PubKey {
        self.key.pub_key()
    }

    /// Get the optional index into the HD key stream.
    pub fn index(&self) -> Option<usize> {
        self.index
    }

    /// Get the account description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Check whether the account is used.
    pub fn used(&self) -> bool {
        self.used
    }

    /// Get the optional ledger scan.
    pub fn scan(&self) -> Option<&BackgroundKeyScan<L, Key>> {
        self.scan.as_ref()
    }

    /// Get the created time.
    pub fn created_time(&self) -> DateTime<Local> {
        self.created_time
    }

    /// Get the modified time.
    pub fn modified_time(&self) -> DateTime<Local> {
        self.modified_time
    }
}

pub type AccountsStore<L, Key, PubKey> = KeyValueStore<PubKey, Account<L, Key>>;

/// An editor to create or update the account or accounts store.
pub struct AccountEditor<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> {
    account: Account<L, Key>,
    store: &'a mut AccountsStore<L, Key, Key::PubKey>,
}

impl<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> AccountEditor<'a, L, Key> {
    /// Create an account editor.
    fn new(
        store: &'a mut AccountsStore<L, Key, Key::PubKey>,
        account: Account<L, Key>,
    ) -> AccountEditor<'a, L, Key> {
        Self { account, store }
    }

    /// Set the account description.
    pub(crate) fn with_description(mut self, description: String) -> Self {
        self.account.description = description;
        self
    }

    /// Set the account as used.
    pub fn set_used(mut self) -> Self {
        self.account.used = true;
        self
    }

    /// Set the optional ledger scan.
    pub(crate) fn set_scan(mut self, scan: Option<BackgroundKeyScan<L, Key>>) -> Self {
        self.account.scan = scan;
        self
    }

    /// Save the account to the store.
    ///
    /// Returns the stored account.
    pub fn save(&mut self) -> Result<Account<L, Key>, KeystoreError<L>> {
        self.store.store(&self.account.pub_key(), &self.account)?;
        self.account.modified_time = Local::now();
        Ok(self.account.clone())
    }
}

impl<'a, L: Ledger> AccountEditor<'a, L, ViewerKeyPair> {
    /// Update the ledger scan.
    ///
    /// Returns
    /// * `Err` if the scan isn't found, or
    /// * `Ok((self, scan_info))`, where `scan_info` contains the scanned information if and only
    /// if the scan is complete.
    pub(crate) async fn update_scan(
        mut self,
        event: LedgerEvent<L>,
        source: EventSource,
        records_commitment: MerkleCommitment,
    ) -> Result<
        (
            AccountEditor<'a, L, ViewerKeyPair>,
            Option<(ViewerKeyPair, ScanOutputs<L>)>,
        ),
        KeystoreError<L>,
    > {
        let mut scan = match self.account.scan.take() {
            Some(scan) => scan,
            None => return Err(KeystoreError::ScanNotFound),
        };
        scan.handle_event(event, source);
        // Check if the scan is complete.
        match scan.finalize(records_commitment) {
            ScanStatus::Finished {
                key,
                records,
                history,
            } => Ok((self, Some((key, ScanOutputs { records, history })))),
            ScanStatus::InProgress(scan) => {
                self.account.scan = Some(scan);
                Ok((self, None))
            }
        }
    }
}

impl<'a, L: Ledger> AccountEditor<'a, L, FreezerKeyPair> {
    /// Update the ledger scan.
    ///
    /// Returns
    /// * `Err` if the scan isn't found, or
    /// * `Ok((self, scan_info))`, where `scan_info` contains the scanned information if and only
    /// if the scan is complete.
    pub(crate) async fn update_scan(
        mut self,
        event: LedgerEvent<L>,
        source: EventSource,
        records_commitment: MerkleCommitment,
    ) -> Result<
        (
            AccountEditor<'a, L, FreezerKeyPair>,
            Option<(FreezerKeyPair, ScanOutputs<L>)>,
        ),
        KeystoreError<L>,
    > {
        let mut scan = match self.account.scan.take() {
            Some(scan) => scan,
            None => return Err(KeystoreError::ScanNotFound),
        };
        scan.handle_event(event, source);
        // Check if the scan is complete.
        match scan.finalize(records_commitment) {
            ScanStatus::Finished {
                key,
                records,
                history,
            } => Ok((self, Some((key, ScanOutputs { records, history })))),
            ScanStatus::InProgress(scan) => {
                self.account.scan = Some(scan);
                Ok((self, None))
            }
        }
    }
}

impl<'a, L: Ledger> AccountEditor<'a, L, UserKeyPair> {
    /// Update the ledger scan.
    ///
    /// Returns
    /// * `Err` if the scan isn't found, or
    /// * `Ok((self, scan_info))`, where `scan_info` contains the scanned information if and only
    /// if the scan is complete.
    pub(crate) async fn update_scan(
        mut self,
        event: LedgerEvent<L>,
        source: EventSource,
        records_commitment: MerkleCommitment,
    ) -> Result<
        (
            AccountEditor<'a, L, UserKeyPair>,
            Option<(UserKeyPair, ScanOutputs<L>)>,
        ),
        KeystoreError<L>,
    > {
        let mut scan = match self.account.scan.take() {
            Some(scan) => scan,
            None => return Err(KeystoreError::ScanNotFound),
        };
        scan.handle_event(event, source);
        // Check if the scan is complete.
        match scan.finalize(records_commitment) {
            ScanStatus::Finished {
                key,
                records,
                history,
            } => Ok((self, Some((key, ScanOutputs { records, history })))),
            ScanStatus::InProgress(scan) => {
                self.account.scan = Some(scan);
                Ok((self, None))
            }
        }
    }
}

impl<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> Deref for AccountEditor<'_, L, Key> {
    type Target = Account<L, Key>;

    fn deref(&self) -> &Account<L, Key> {
        &self.account
    }
}

impl<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> DerefMut
    for AccountEditor<'_, L, Key>
{
    fn deref_mut(&mut self) -> &mut Account<L, Key> {
        &mut self.account
    }
}

/// Accounts stored in an accounts store.
pub struct Accounts<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> {
    /// A key-value store for accounts.
    store: AccountsStore<L, Key, Key::PubKey>,

    /// The next index into the HD key stream.
    index: usize,
}

impl<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> Accounts<L, Key> {
    /// Load an accounts store.
    #[allow(clippy::type_complexity)]
    pub fn new(
        loader: &mut AtomicStoreLoader,
        adaptor: EncryptingResourceAdapter<(Key::PubKey, Option<Account<L, Key>>)>,
        pattern: &str,
        fill_size: u64,
    ) -> Result<Self, KeystoreError<L>> {
        let log = AppendLog::load(
            loader,
            adaptor,
            &format!("keystore_{}_accounts", pattern),
            fill_size,
        )?;
        let store = AccountsStore::<L, Key, Key::PubKey>::new(log)?;
        // The next index is `max_index + 1`, where `max_index` is the maximum index among all
        // accounts. If no account has an index, the next index will be 0.
        let index = match store.iter().filter_map(|account| account.index()).max() {
            Some(index) => index + 1,
            None => 0,
        };
        Ok(Self { store, index })
    }

    /// Iterate through the accounts.
    pub fn iter(&self) -> impl Iterator<Item = Account<L, Key>> + '_ {
        self.store.iter().cloned()
    }

    /// Iterate through the keys of all accounts.
    pub fn iter_keys(&self) -> impl Iterator<Item = Key> + '_ {
        self.iter().map(|account| account.key().clone())
    }

    /// Iterate through the public keys of all accounts.
    pub fn iter_pub_keys(&self) -> impl Iterator<Item = Key::PubKey> + '_ {
        self.iter().map(|account| account.pub_key())
    }

    /// Get the account by the public key from the store.
    pub fn get(&self, pub_key: &Key::PubKey) -> Result<Account<L, Key>, KeystoreError<L>> {
        Ok(self.store.load(pub_key)?)
    }

    /// Get a mutable account editor by the public key from the store.
    pub fn get_mut(
        &mut self,
        pub_key: &Key::PubKey,
    ) -> Result<AccountEditor<L, Key>, KeystoreError<L>> {
        let account = self.get(pub_key)?;
        Ok(AccountEditor::new(&mut self.store, account))
    }

    /// Get the index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Get and increment the index.
    pub fn next_index(&mut self) -> usize {
        let index = self.index;
        self.index += 1;
        index
    }

    /// Commit the store version.
    pub fn commit(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.revert_version()?)
    }

    /// Create an account with the default description.
    ///
    /// Returns the editor for the created account.
    pub fn create(
        &mut self,
        key: Key,
        index: Option<usize>,
    ) -> Result<AccountEditor<L, Key>, KeystoreError<L>> {
        let time = Local::now();
        let account = Account {
            key: key.clone(),
            description: key.pub_key().to_string(),
            used: false,
            scan: None,
            index,
            created_time: time,
            modified_time: time,
        };
        let mut editor = AccountEditor::new(&mut self.store, account);
        editor.save()?;
        Ok(editor)
    }

    /// Deletes an account from the store.
    ///
    /// Returns the deleted account.
    pub fn delete(&mut self, pub_key: &Key::PubKey) -> Result<Account<L, Key>, KeystoreError<L>> {
        Ok(self.store.delete(pub_key)?)
    }
}
