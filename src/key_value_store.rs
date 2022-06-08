// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The key-value store.
//!
//! This module defines [KeyValueStore], which provides interfaces to keystore resources (e.g.,
//! the assets resource) to create, read, update, and delete data.

use crate::{persistence::EncryptingResourceAdapter, KeystoreError, Ledger};
use atomic_store::AppendLog;
use serde::{de::DeserializeOwned, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::hash::Hash;

/// Errors happening during key-value store operations.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum KeyValueStoreError {
    KeyNotFound,
    PersistenceError {
        source: atomic_store::error::PersistenceError,
    },
}

impl From<atomic_store::error::PersistenceError> for KeyValueStoreError {
    fn from(source: atomic_store::error::PersistenceError) -> Self {
        Self::PersistenceError { source }
    }
}

impl<L: Ledger> From<KeyValueStoreError> for KeystoreError<L> {
    fn from(source: KeyValueStoreError) -> Self {
        KeystoreError::KeyValueStoreError { source }
    }
}

/// A storage for key-value pairs.
pub struct KeyValueStore<
    K: DeserializeOwned + Eq + Hash + Serialize,
    V: DeserializeOwned + Serialize,
> {
    store: AppendLog<EncryptingResourceAdapter<HashMap<K, V>>>,
    index: HashMap<K, V>,
}

impl<
        K: Clone + DeserializeOwned + Eq + Hash + Serialize,
        V: Clone + DeserializeOwned + Serialize,
    > KeyValueStore<K, V>
{
    /// Create a key-value store.
    pub fn new(
        store: AppendLog<EncryptingResourceAdapter<HashMap<K, V>>>,
    ) -> Result<Self, KeyValueStoreError> {
        let index = store.load_latest()?;
        Ok(Self { store, index })
    }

    /// Iterate through the index table.
    pub fn iter(&self) -> impl Iterator<Item = &V> {
        self.index.values()
    }

    /// Load the value associated with the key from the index table.
    pub fn load(&self, key: &K) -> Result<V, KeyValueStoreError> {
        self.index
            .get(key)
            .cloned()
            .ok_or(KeyValueStoreError::KeyNotFound)
    }

    /// Commit the store version.
    pub fn commit_version(&mut self) -> Result<(), KeyValueStoreError> {
        self.store.store_resource(&self.index)?;
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert_version(&mut self) -> Result<(), KeyValueStoreError> {
        self.store.store_resource(&self.index)?;
        Ok(self.store.revert_version()?)
    }

    /// Store a key-value pair to the index table and update the store version.
    pub fn store(&mut self, key: &K, value: &V) -> Result<(), KeyValueStoreError> {
        self.index.insert(key.clone(), value.clone());
        self.commit_version()?;
        Ok(())
    }

    /// Delete a key from the index table and update the store version.
    ///
    /// Returns the value associated with the deleted key.
    pub fn delete(&mut self, key: &K) -> Result<V, KeyValueStoreError> {
        let value = self
            .index
            .remove(key)
            .ok_or(KeyValueStoreError::KeyNotFound);
        self.revert_version()?;
        value
    }
}
