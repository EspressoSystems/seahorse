// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The key-value store.
//!
//! This module defines [KeyValueStore] and [PersistableMap], which provide interfaces to keystore
//! resources (e.g., assets and transactions) to create, read, update, and delete data.

use crate::{EncryptingResourceAdapter, KeystoreError, Ledger};
use atomic_store::AppendLog;
use serde::{de::DeserializeOwned, Serialize};
use snafu::Snafu;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
    K: DeserializeOwned + Eq + Hash + Serialize + Clone,
    V: DeserializeOwned + Serialize,
> {
    store: AppendLog<EncryptingResourceAdapter<(K, Option<V>)>>,
    persistable_index: PersistableHashMap<K, V>,
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
        let mut persistable_index = PersistableHashMap::new();
        for key_value in store.iter() {
            let (key, value) = key_value?;
            match value {
                Some(val) => persistable_index.insert((key, val)),
                None => {
                    if let Some(val) = persistable_index.index.get(&key).cloned() {
                        persistable_index.remove(&(key, val));
                    }
                }
            };
        }
        Ok(Self {
            store,
            persistable_index,
        })
    }

    /// Iterate through the index table.
    pub fn iter(&self) -> impl Iterator<Item = &V> {
        self.persistable_index.index.values()
    }

    /// Load the value associated with the key from the index table.
    pub fn load(&self, key: &K) -> Result<V, KeyValueStoreError> {
        self.persistable_index
            .index
            .get(key)
            .cloned()
            .ok_or(KeyValueStoreError::KeyNotFound)
    }

    /// Commit the persistable index and the store version.
    pub fn commit_version(&mut self) -> Result<(), KeyValueStoreError> {
        self.persistable_index.commit();
        Ok(self.store.commit_version()?)
    }

    /// Revert the persistable index and the store version.
    pub fn revert_version(&mut self) -> Result<(), KeyValueStoreError> {
        self.persistable_index.revert();
        Ok(self.store.revert_version()?)
    }

    /// Store a key-value pair to the persistable index and update the store version.
    pub fn store(&mut self, key: &K, value: &V) -> Result<(), KeyValueStoreError> {
        self.persistable_index.insert((key.clone(), value.clone()));
        self.store
            .store_resource(&(key.clone(), Some(value.clone())))?;
        Ok(())
    }

    /// Delete a key from the persistable index and update the store version.
    ///
    /// Returns the value associated with the deleted key.
    pub fn delete(&mut self, key: &K) -> Result<V, KeyValueStoreError> {
        let value = self.load(key)?;
        self.persistable_index.remove(&(key.clone(), value.clone()));
        self.store.store_resource(&(key.clone(), None))?;
        Ok(value)
    }
}

/// Changes for in-memory state.
pub enum IndexChange<C> {
    Add(C),
    Remove(C),
    // Takes the previous K,V pair
    Update(C),
}

/// An Interface for an in memory index which can insert and remove items
/// To create a persistable index type you can implement this trait for whatever in memory index
/// you choose to use.  E.g. if you create a new type called CustomHashMap<K,V> you can implement
/// Index<(K,V)> for it and then use the persitable type PersistableMap<(K,V), CustomHashMap<K,V>>.
pub trait Index<C> {
    /// Insert an item into the index.  Returns the item value in the index before inserting if there was one
    /// Returns None if there was no item.
    fn insert(&mut self, change: C) -> Option<C>;
    /// Remove a value from the index.  Returns the removed item if something was removed.  None if the item
    /// was not in the index.
    fn remove(&mut self, change: &C) -> Option<C>;
}

impl<K, V> Index<(K, V)> for HashMap<K, V>
where
    K: Clone + Eq + Hash,
{
    fn insert(&mut self, change: (K, V)) -> Option<(K, V)> {
        if let Some(inserted) = HashMap::insert(self, change.0.clone(), change.1) {
            Some((change.0, inserted))
        } else {
            None
        }
    }
    fn remove(&mut self, change: &(K, V)) -> Option<(K, V)> {
        self.remove(&change.0)
            .map(|removed| (change.0.clone(), removed))
    }
}

impl<C> Index<C> for HashSet<C>
where
    C: Clone + Eq + Hash,
{
    fn insert(&mut self, value: C) -> Option<C> {
        if HashSet::insert(self, value.clone()) {
            None
        } else {
            Some(value)
        }
    }
    fn remove(&mut self, value: &C) -> Option<C> {
        if HashSet::remove(self, value) {
            Some(value.clone())
        } else {
            None
        }
    }
}

impl<K, V> Index<(K, V)> for HashMap<K, BTreeSet<V>>
where
    K: Eq + Hash + Clone,
    V: Eq + Hash + Ord + Clone,
{
    fn insert(&mut self, change: (K, V)) -> Option<(K, V)> {
        if self
            .entry(change.0.clone())
            .or_insert_with(BTreeSet::new)
            .insert(change.1.clone())
        {
            None
        } else {
            Some(change)
        }
    }
    fn remove(&mut self, change: &(K, V)) -> Option<(K, V)> {
        let values = self.entry(change.0.clone()).or_default();
        let removed = values.remove(&change.1);
        if values.is_empty() {
            self.remove(&change.0);
        }
        if removed {
            Some(change.clone())
        } else {
            None
        }
    }
}

impl<K, V> Index<(K, V)> for BTreeMap<K, HashSet<V>>
where
    K: Eq + Hash + Clone + Ord,
    V: Eq + Hash + Clone,
{
    fn insert(&mut self, change: (K, V)) -> Option<(K, V)> {
        if self
            .entry(change.0.clone())
            .or_insert_with(HashSet::new)
            .insert(change.1.clone())
        {
            None
        } else {
            Some(change)
        }
    }
    fn remove(&mut self, change: &(K, V)) -> Option<(K, V)> {
        let values = self.entry(change.0.clone()).or_default();
        let removed = values.remove(&change.1);
        if values.is_empty() {
            self.remove(&change.0);
        }
        if removed {
            Some(change.clone())
        } else {
            None
        }
    }
}
/// A persistable in-memory state.
#[derive(Default)]
pub struct PersistableMap<C, I: Index<C>> {
    /// In-memory index, including both committed and uncommitted changes.
    index: I,
    /// Changes that haven't been committed.
    pending_changes: Vec<IndexChange<C>>,
}

impl<C: Clone, I: Index<C> + Default> PersistableMap<C, I> {
    /// Get the index.
    pub fn index(&self) -> &I {
        &self.index
    }

    /// Commit the pending changes.
    pub fn commit(&mut self) {
        // The index is always up-to-date, so commting only needs to clear the pending changes.
        self.pending_changes = Vec::new();
    }

    pub fn new() -> Self {
        Self {
            index: I::default(),
            pending_changes: Vec::new(),
        }
    }

    pub fn insert(&mut self, change: C) {
        if let Some(old) = self.index.insert(change.clone()) {
            self.pending_changes.push(IndexChange::Update(old))
        } else {
            self.pending_changes.push(IndexChange::Add(change));
        }
    }

    pub fn remove(&mut self, change: &C) {
        if let Some(removal) = self.index.remove(change) {
            self.pending_changes.push(IndexChange::Remove(removal));
        }
    }

    pub fn revert(&mut self) {
        for change in self.pending_changes.iter().rev() {
            match change {
                IndexChange::Add(change) => {
                    self.index.remove(change);
                }
                IndexChange::Remove(change) => {
                    self.index.insert(change.clone());
                }
                IndexChange::Update(old) => {
                    self.index.insert(old.clone());
                }
            }
        }
        self.pending_changes = Vec::new();
    }
}

pub type PersistableHashSet<K> = PersistableMap<K, HashSet<K>>;
pub type PersistableHashMap<K, V> = PersistableMap<(K, V), HashMap<K, V>>;
pub type PersistableBTreeMultiMap<K, V> = PersistableMap<(K, V), BTreeMap<K, HashSet<V>>>;
pub type PersistableHashMapBTreeMultiMap<K, V> = PersistableMap<(K, V), HashMap<K, BTreeSet<V>>>;

#[cfg(test)]
pub mod test {
    use crate::key_value_store::*;
    use core::fmt::Debug;
    use proptest::test_runner::{Config, TestRunner};
    use proptest::{collection::vec, prelude::*, prop_oneof, strategy::Strategy};

    #[derive(Clone, Debug, strum_macros::Display)]
    pub enum PersistAction<C: Clone + Debug> {
        Insert(C),
        Remove(C),
        Revert,
        Commit,
    }

    pub fn action_strategy(size: u32) -> impl Strategy<Value = PersistAction<(u32, String)>> {
        prop_oneof![
            Just(PersistAction::Revert),
            Just(PersistAction::Commit),
            (0..size, ".*").prop_map(|(a, b)| PersistAction::Insert((a, b))),
            (0..size, ".*").prop_map(|(a, b)| PersistAction::Remove((a, b))),
        ]
    }

    pub fn actions(size: usize) -> impl Strategy<Value = Vec<PersistAction<(u32, String)>>> {
        vec(action_strategy(size as u32), 1..=size)
    }

    pub fn test_persistasble_impl<
        C: Clone + Debug + Eq + Hash,
        I: Clone + Default + PartialEq + Debug + Index<C>,
    >(
        persistable: PersistableMap<C, I>,
        changes: Vec<PersistAction<C>>,
    ) {
        let mut map = persistable;
        let mut control = I::default();
        let mut revert_index = control.clone();
        for change in changes {
            match change {
                PersistAction::Insert(change) => {
                    control.insert(change.clone());
                    map.insert(change);
                }
                PersistAction::Remove(change) => {
                    control.remove(&change);
                    map.remove(&change);
                }
                PersistAction::Revert => {
                    map.revert();
                    control = revert_index.clone()
                }
                PersistAction::Commit => {
                    map.commit();
                    revert_index = control.clone();
                }
            }
        }
        map.commit();
        assert_eq!(*map.index(), control);
    }

    pub fn test_persistasble<
        C: Clone + Debug + Eq + Hash,
        I: Clone + Default + PartialEq + Debug + Index<C>,
    >(
        _map: PersistableMap<C, I>,
        strat: impl Strategy<Value = Vec<PersistAction<C>>>,
    ) {
        let mut runner = TestRunner::new(Config::default());
        runner
            .run(&strat, move |v| {
                test_persistasble_impl(PersistableMap::<C, I>::new(), v);
                Ok(())
            })
            .unwrap();
    }
    #[test]
    pub fn proptest_persistable_hash_map() {
        test_persistasble(PersistableHashMap::new(), actions(1000));
    }
    #[test]
    pub fn proptest_persistable_hash_set() {
        test_persistasble(PersistableHashSet::new(), actions(1000));
    }
    #[test]
    pub fn proptest_persistable_hash_map_multi() {
        test_persistasble(PersistableBTreeMultiMap::new(), actions(1000));
    }
    #[test]
    pub fn proptest_persistable_hash_map_multi_tree() {
        test_persistasble(PersistableHashMapBTreeMultiMap::new(), actions(1000));
    }
}
