// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The key-value store.
//!
//! This module defines [KeyValueStore] and [Persistable], which provide interfaces to keystore
//! resources (e.g., assets and transactions) to create, read, update, and delete data.

use crate::{EncryptingResourceAdapter, KeystoreError, Ledger};
use atomic_store::AppendLog;
use serde::{de::DeserializeOwned, Serialize};
use snafu::Snafu;
use std::collections::{BTreeMap, HashMap, HashSet};
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
    store: AppendLog<EncryptingResourceAdapter<(K, Option<V>)>>,
    index: HashMap<K, V>,
}

impl<
        K: Clone + DeserializeOwned + Eq + Hash + Serialize,
        V: Clone + DeserializeOwned + Serialize,
    > KeyValueStore<K, V>
{
    /// Create a key-value store.
    pub fn new(
        store: AppendLog<EncryptingResourceAdapter<(K, Option<V>)>>,
    ) -> Result<Self, KeyValueStoreError> {
        let mut index = HashMap::new();
        for key_value in store.iter() {
            let (key, value) = key_value?;
            match value {
                Some(val) => index.insert(key, val),
                None => index.remove(&key),
            };
        }
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
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert_version(&mut self) -> Result<(), KeyValueStoreError> {
        Ok(self.store.revert_version()?)
    }

    /// Store a key-value pair to the index table and update the store version.
    pub fn store(&mut self, key: &K, value: &V) -> Result<(), KeyValueStoreError> {
        self.index.insert(key.clone(), value.clone());
        self.store
            .store_resource(&(key.clone(), Some(value.clone())))?;
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
        self.store.store_resource(&(key.clone(), None))?;
        value
    }
}

/// Changes for in-memory state.
pub enum IndexChange<C: Eq> {
    Add(C),
    Remove(C),
}

/// An interface for persisting in-memory state.
pub trait Persist<C> {
    /// Construct a persistable state.
    fn new() -> Self;
    /// Insert data to the index.
    fn insert(&mut self, change: C);
    /// Remove data from the index.
    fn remove(&mut self, change: C);
    /// Revert the uncommitted changes.
    fn revert(&mut self);
}

/// A persistable in-memory state.
pub struct Persistable<I, C: Eq> {
    /// In-memory index, including both committed and uncommitted changes.
    index: I,
    /// Changes that haven't been committed.
    pending_changes: Vec<IndexChange<C>>,
}

impl<I, C: Eq> Persistable<I, C> {
    /// Get the index.
    pub fn index(&self) -> &I {
        &self.index
    }

    /// Commit the pending changes.
    pub fn commit(&mut self) {
        // The index is always up-to-date, so commting only needs to clear the pending changes.
        self.pending_changes = Vec::new();
    }
}

pub type PersistableHashSet<K> = Persistable<HashSet<K>, K>;
pub type PersistableHashMap<K, V> = Persistable<HashMap<K, V>, (K, V)>;
pub type PersistableBTreeMultiMap<K, V> = Persistable<BTreeMap<K, HashSet<V>>, (K, V)>;

impl<K: Copy + Eq + Hash> Persist<K> for PersistableHashSet<K> {
    fn new() -> Self {
        Self {
            index: HashSet::new(),
            pending_changes: Vec::new(),
        }
    }

    fn insert(&mut self, change: K) {
        self.index.insert(change);
        self.pending_changes.push(IndexChange::Add(change));
    }

    fn remove(&mut self, change: K) {
        self.index.remove(&change);
        self.pending_changes.push(IndexChange::Remove(change));
    }

    fn revert(&mut self) {
        for change in &self.pending_changes {
            match change {
                IndexChange::Add(key) => {
                    self.index.remove(key);
                }
                IndexChange::Remove(key) => {
                    self.index.insert(*key);
                }
            }
        }
        self.pending_changes = Vec::new();
    }
}

impl<K: Clone + Eq + Hash, V: Clone + Eq + Hash> Persist<(K, V)> for PersistableHashMap<K, V> {
    fn new() -> Self {
        Self {
            index: HashMap::new(),
            pending_changes: Vec::new(),
        }
    }

    fn insert(&mut self, change: (K, V)) {
        self.index.insert(change.0.clone(), change.1.clone());
        self.pending_changes.push(IndexChange::Add(change));
    }

    fn remove(&mut self, change: (K, V)) {
        self.index.remove(&change.0);
        self.pending_changes.push(IndexChange::Remove(change));
    }

    fn revert(&mut self) {
        for change in &self.pending_changes {
            match change {
                IndexChange::Add((key, _)) => {
                    self.index.remove(key);
                }
                IndexChange::Remove((key, value)) => {
                    self.index.insert(key.clone(), value.clone());
                }
            }
        }
        self.pending_changes = Vec::new();
    }
}

impl<K: Copy + Eq + Hash + Ord, V: Clone + Eq + Hash> Persist<(K, V)>
    for PersistableBTreeMultiMap<K, V>
{
    fn new() -> Self {
        Self {
            index: BTreeMap::new(),
            pending_changes: Vec::new(),
        }
    }

    fn insert(&mut self, change: (K, V)) {
        self.index
            .entry(change.0)
            .or_insert_with(HashSet::new)
            .insert(change.1.clone());
        self.pending_changes.push(IndexChange::Add(change));
    }

    fn remove(&mut self, change: (K, V)) {
        let values = self.index.entry(change.0).or_default();
        values.remove(&change.1);
        if values.is_empty() {
            self.index.remove(&change.0);
        }
        self.pending_changes.push(IndexChange::Remove(change));
    }

    fn revert(&mut self) {
        for change in &self.pending_changes {
            match change {
                IndexChange::Add((key, value)) => {
                    let values = self.index.entry(*key).or_default();
                    values.remove(value);
                    if values.is_empty() {
                        self.index.remove(key);
                    }
                }
                IndexChange::Remove((key, value)) => {
                    self.index
                        .entry(*key)
                        .or_insert_with(HashSet::new)
                        .insert(value.clone());
                }
            }
        }
        self.pending_changes = Vec::new();
    }
}
