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
    key_scan::{BackgroundKeyScan, ScanOutputs, ScanStatus},
    key_value_store::KeyValueStore,
    KeystoreError,
};
use arbitrary::Arbitrary;
use chrono::{DateTime, Local};
use jf_cap::{
    keys::{FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair, ViewerKeyPair, ViewerPubKey},
    MerkleCommitment,
};
use reef::Ledger;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Display;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

/// Keys with a public part.
pub trait KeyPair: Clone + Send + Sync {
    type PubKey: Clone + DeserializeOwned + Display + Eq + Hash + Serialize;
    fn pub_key(&self) -> Self::PubKey;
}

impl KeyPair for ViewerKeyPair {
    type PubKey = ViewerPubKey;

    fn pub_key(&self) -> Self::PubKey {
        self.pub_key()
    }
}

impl KeyPair for FreezerKeyPair {
    type PubKey = FreezerPubKey;

    fn pub_key(&self) -> Self::PubKey {
        self.pub_key()
    }
}

impl KeyPair for UserKeyPair {
    // The PubKey here is supposed to be a conceptual "primary key" for looking up UserKeyPairs. We
    // typically want to look up UserKeyPairs by Address, not PubKey, because if we have a PubKey we
    // can always get an Address to do the lookup.
    type PubKey = UserAddress;

    fn pub_key(&self) -> Self::PubKey {
        self.address()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(bound = "Key: DeserializeOwned + Serialize")]
pub struct Account<L: Ledger, Key: KeyPair> {
    /// The account key.
    key: Key,
    /// The account description.
    pub description: String,
    /// Whether the account is used.
    used: bool,
    /// Optional ledger scan.
    scan: Option<BackgroundKeyScan<L>>,
    /// The time when the account was created.
    created_time: DateTime<Local>,
    /// The last time when the account was modified.
    modified_time: DateTime<Local>,
}

impl<L: Ledger, Key: KeyPair> Account<L, Key> {
    #![allow(dead_code)]

    /// Get the account key.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Get the account public key.
    pub fn pub_key(&self) -> Key::PubKey {
        self.key.pub_key()
    }

    /// Get the account description.
    pub fn description(&self) -> String {
        self.description.clone()
    }

    /// Check whether the account is used.
    pub fn used(&self) -> bool {
        self.used
    }

    /// Get the optional ledger scan.
    pub fn scan(&self) -> Option<BackgroundKeyScan<L>> {
        self.scan.clone()
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

impl<L: Ledger, Key: KeyPair> PartialEq<Self> for Account<L, Key> {
    fn eq(&self, other: &Self) -> bool {
        // We assume that the private keys are equal if the public keys are.
        self.key.pub_key() == other.key.pub_key()
            && self.description == other.description
            && self.used == other.used
            && self.scan == other.scan
            && self.created_time == other.created_time
            && self.modified_time == other.modified_time
    }
}

// impl<'a, L: Ledger> Arbitrary<'a> for Account<L, ViewerKeyPair>
// {
//     fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
//         Ok(Self {
//             key: u.arbitrary::<ArbitraryViewerKeyPair>()?.into(),
//             description: u.arbitrary()?,
//             used: u.arbitrary()?,
//             scan: u.arbitrary()?,
//             created_time: u.arbitrary()?,
//             modified_time: u.arbitrary()?,
//         })
//     }
// }

// impl<'a, L: Ledger> Arbitrary<'a> for Account<L, FreezerKeyPair>
// {
//     fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
//         Ok(Self {
//             key: u.arbitrary::<ArbitraryFreezerKeyPair>()?.into(),
//             description: u.arbitrary()?,
//             used: u.arbitrary()?,
//             scan: u.arbitrary()?,
//             created_time: u.arbitrary()?,
//             modified_time: u.arbitrary()?,
//         })
//     }
// }

// impl<'a, L: Ledger> Arbitrary<'a> for Account<L, UserKeyPair>
// {
//     fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
//         Ok(Self {
//             key: u.arbitrary::<ArbitraryUserKeyPair>()?.into(),
//             description: u.arbitrary()?,
//             used: u.arbitrary()?,
//             scan: u.arbitrary()?,
//             created_time: u.arbitrary()?,
//             modified_time: u.arbitrary()?,
//         })
//     }
// }

pub type AccountsStore<L, Key, PubKey> = KeyValueStore<PubKey, Account<L, Key>>;

/// An editor to create or update the account or accounts store.
pub struct AccountEditor<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> {
    account: Account<L, Key>,
    store: &'a mut AccountsStore<L, Key, Key::PubKey>,
}

impl<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> AccountEditor<'a, L, Key> {
    #![allow(dead_code)]

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
    pub(crate) fn set_scan(mut self, scan: Option<BackgroundKeyScan<L>>) -> Self {
        self.account.scan = scan;
        self
    }

    /// Set the ledger scan.
    pub(crate) fn with_scan(mut self, scan: BackgroundKeyScan<L>) -> Self {
        self.account.scan = Some(scan);
        self
    }

    /// Clear the leger scan.
    pub(crate) fn clear_scan(mut self) -> Self {
        self.account.scan = None;
        self
    }

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
            AccountEditor<'a, L, Key>,
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

    /// Save the account to the store.
    ///
    /// Returns the stored account.
    pub fn save(&mut self) -> Result<Account<L, Key>, KeystoreError<L>> {
        self.store.store(&self.account.pub_key(), &self.account)?;
        self.account.modified_time = Local::now();
        Ok(self.account.clone())
    }
}

impl<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> Deref
    for AccountEditor<'_, L, Key>
{
    type Target = Account<L, Key>;

    fn deref(&self) -> &Account<L, Key> {
        &self.account
    }
}

impl<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> DerefMut
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
}

impl<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> Accounts<L, Key> {
    #![allow(dead_code)]

    /// Load an accounts store.
    pub fn new(store: AccountsStore<L, Key, Key::PubKey>) -> Result<Self, KeystoreError<L>> {
        Ok(Self { store })
    }

    /// Iterate through the accounts.
    pub fn iter(&self) -> impl Iterator<Item = Account<L, Key>> + '_ {
        self.store.iter().cloned()
    }

    /// Get the keys of all accounts.
    pub fn keys(&self) -> Vec<Key> {
        self.iter().map(|account| account.key().clone()).collect()
    }

    /// Get the public keys of all accounts.
    pub fn pub_keys(&self) -> Vec<Key::PubKey> {
        self.iter().map(|account| account.pub_key()).collect()
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
    pub fn create(&mut self, key: Key) -> Result<AccountEditor<L, Key>, KeystoreError<L>> {
        let time = Local::now();
        let account = Account {
            key: key.clone(),
            description: key.pub_key().to_string(),
            used: false,
            scan: None,
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
