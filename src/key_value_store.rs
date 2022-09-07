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
    K: DeserializeOwned + Eq + Hash + Serialize,
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
                        persistable_index.remove((key, val));
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
        self.persistable_index.remove((key.clone(), value.clone()));
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

pub trait Persistable<I> {
    fn index(&self) -> &I;
    fn commit(&mut self);
}

/// A persistable in-memory state.
pub struct PersistableMap<I, C> {
    /// In-memory index, including both committed and uncommitted changes.
    index: I,
    /// Changes that haven't been committed.
    pending_changes: Vec<IndexChange<C>>,
}

impl<I, C> Persistable<I> for PersistableMap<I, C> {
    /// Get the index.
    fn index(&self) -> &I {
        &self.index
    }

    /// Commit the pending changes.
    fn commit(&mut self) {
        // The index is always up-to-date, so commting only needs to clear the pending changes.
        self.pending_changes = Vec::new();
    }
}

pub type PersistableHashSet<K> = PersistableMap<HashSet<K>, K>;
pub type PersistableHashMap<K, V> = PersistableMap<HashMap<K, V>, (K, V)>;
pub type PersistableBTreeMultiMap<K, V> = PersistableMap<BTreeMap<K, HashSet<V>>, (K, V)>;
pub type PersistableHashMapBTreeMultiMap<K, V> = PersistableMap<HashMap<K, BTreeSet<V>>, (K, V)>;

impl<K: Clone + Eq + Hash> Persist<K> for PersistableHashSet<K> {
    fn new() -> Self {
        Self {
            index: HashSet::new(),
            pending_changes: Vec::new(),
        }
    }

    fn insert(&mut self, change: K) {
        if !self.index.insert(change.clone()) {
            self.pending_changes.push(IndexChange::Add(change));
        }
    }

    fn remove(&mut self, change: K) {
        if self.index.remove(&change) {
            self.pending_changes.push(IndexChange::Remove(change));
        }
    }

    fn revert(&mut self) {
        for change in &self.pending_changes {
            match change {
                IndexChange::Add(key) => {
                    self.index.remove(key);
                }
                IndexChange::Remove(key) => {
                    self.index.insert(key.clone());
                }
                IndexChange::Update(..) => {
                    panic!("Unreachable");
                }
            }
        }
        self.pending_changes = Vec::new();
    }
}

impl<K: Clone + Eq + Hash, V: Clone> Persist<(K, V)> for PersistableHashMap<K, V> {
    fn new() -> Self {
        Self {
            index: HashMap::new(),
            pending_changes: Vec::new(),
        }
    }

    fn insert(&mut self, change: (K, V)) {
        if let Some(old) = self.index.insert(change.0.clone(), change.1.clone()) {
            self.pending_changes
                .push(IndexChange::Update((change.0, old)))
        } else {
            self.pending_changes.push(IndexChange::Add(change));
        }
    }

    fn remove(&mut self, change: (K, V)) {
        if let Some(removal) = self.index.remove_entry(&change.0) {
            self.pending_changes.push(IndexChange::Remove(removal));
        }
    }

    fn revert(&mut self) {
        for change in self.pending_changes.iter().rev() {
            match change {
                IndexChange::Add((key, _)) => {
                    self.index.remove(key);
                }
                IndexChange::Remove((key, value)) => {
                    self.index.insert(key.clone(), value.clone());
                }
                IndexChange::Update((old_key, old_val)) => {
                    self.index.insert(old_key.clone(), old_val.clone());
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
        if self
            .index
            .entry(change.0)
            .or_insert_with(HashSet::new)
            .insert(change.1.clone())
        {
            self.pending_changes.push(IndexChange::Add(change));
        }
    }

    fn remove(&mut self, change: (K, V)) {
        let values = self.index.entry(change.0).or_default();
        let removed = values.remove(&change.1);
        if values.is_empty() {
            self.index.remove(&change.0);
        }
        if removed {
            self.pending_changes.push(IndexChange::Remove(change));
        }
    }

    fn revert(&mut self) {
        for change in self.pending_changes.iter().rev() {
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
                IndexChange::Update(..) => {}
            }
        }
        self.pending_changes = Vec::new();
    }
}

impl<K: Clone + Eq + Hash, V: Clone + Eq + Hash + Ord> Persist<(K, V)>
    for PersistableHashMapBTreeMultiMap<K, V>
{
    fn new() -> Self {
        Self {
            index: HashMap::new(),
            pending_changes: Vec::new(),
        }
    }

    fn insert(&mut self, change: (K, V)) {
        self.index
            .entry(change.0.clone())
            .or_insert_with(BTreeSet::new)
            .insert(change.1.clone());
        self.pending_changes.push(IndexChange::Add(change));
    }

    fn remove(&mut self, change: (K, V)) {
        let values = self.index.entry(change.0.clone()).or_default();
        let removed = values.remove(&change.1);
        if values.is_empty() {
            self.index.remove(&change.0);
        }
        if removed {
            self.pending_changes.push(IndexChange::Remove(change));
        }
    }

    fn revert(&mut self) {
        for change in self.pending_changes.iter().rev() {
            match change {
                IndexChange::Add((key, value)) => {
                    let values = self.index.entry(key.clone()).or_default();
                    values.remove(value);
                    if values.is_empty() {
                        self.index.remove(key);
                    }
                }
                IndexChange::Remove((key, value)) => {
                    self.index
                        .entry(key.clone())
                        .or_insert_with(BTreeSet::new)
                        .insert(value.clone());
                }
                IndexChange::Update(..) => {}
            }
        }
        self.pending_changes = Vec::new();
    }
}

#[cfg(test)]
pub mod test {
    use crate::key_value_store::*;
    use core::fmt::Debug;
    use proptest::test_runner::{Config, TestRunner};
    use proptest::{collection::vec, prelude::*, prop_oneof, strategy::Strategy};
    use std::collections::HashMap;
    pub trait Set<V: Eq + Hash> {
        fn insert(&mut self, value: V) -> bool;
        fn remove(&mut self, value: &V) -> bool;
    }
    impl<V> Set<V> for HashSet<V>
    where
        V: Eq + Hash,
    {
        fn insert(&mut self, value: V) -> bool {
            HashSet::insert(self, value)
        }
        fn remove(&mut self, value: &V) -> bool {
            HashSet::remove(self, value)
        }
    }

    pub trait Map<K: Eq + Hash, V> {
        fn insert(&mut self, key: K, value: V) -> bool;
        fn remove(&mut self, key: &K, value: &V) -> bool;
    }

    impl<K, V> Map<K, V> for HashMap<K, V>
    where
        K: Eq + Hash,
    {
        fn insert(&mut self, key: K, value: V) -> bool {
            HashMap::insert(self, key, value).is_some()
        }
        fn remove(&mut self, key: &K, _value: &V) -> bool {
            HashMap::remove(self, key).is_some()
        }
    }

    impl<K, V> Map<K, V> for HashSet<K>
    where
        K: Eq + Hash,
    {
        fn insert(&mut self, key: K, _value: V) -> bool {
            HashSet::insert(self, key)
        }
        fn remove(&mut self, key: &K, _value: &V) -> bool {
            HashSet::remove(self, key)
        }
    }

    impl<K, V> Map<K, V> for HashMap<K, BTreeSet<V>>
    where
        K: Eq + Hash + Clone,
        V: Eq + Hash + Ord,
    {
        fn insert(&mut self, key: K, value: V) -> bool {
            self.entry(key).or_insert_with(BTreeSet::new).insert(value)
        }
        fn remove(&mut self, key: &K, value: &V) -> bool {
            let values = self.entry(key.clone()).or_default();
            let removed = values.remove(value);
            if values.is_empty() {
                self.remove(key);
            }
            removed
        }
    }

    impl<K, V> Map<K, V> for BTreeMap<K, HashSet<V>>
    where
        K: Eq + Hash + Clone + Ord,
        V: Eq + Hash + Ord,
    {
        fn insert(&mut self, key: K, value: V) -> bool {
            self.entry(key).or_insert_with(HashSet::new).insert(value)
        }
        fn remove(&mut self, key: &K, value: &V) -> bool {
            let values = self.entry(key.clone()).or_default();
            let removed = values.remove(value);
            if values.is_empty() {
                self.remove(key);
            }
            removed
        }
    }

    #[derive(Clone, Debug, strum_macros::Display)]
    pub enum PersistAction<C: Clone + Debug> {
        Insert(C),
        Remove(C),
        Revert,
        Commit,
    }
    pub fn test_persistasble_impl<
        K: Clone + Debug + Eq + Hash,
        V: Clone + Debug,
        I: Clone + Default + PartialEq + Debug + Map<K, V>,
        P: Persist<(K, V)> + Persistable<I>,
    >(
        persistable: P,
        changes: Vec<PersistAction<(K, V)>>,
    ) {
        let mut map = persistable;
        let mut control = I::default();
        let mut revert_index = control.clone();
        for change in changes {
            match change {
                PersistAction::Insert((key, value)) => {
                    control.insert(key.clone(), value.clone());
                    map.insert((key, value));
                }
                PersistAction::Remove((key, value)) => {
                    control.remove(&key, &value);
                    // remove_fn(&mut control, change.clone());
                    map.remove((key, value));
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

    pub fn test_persistasble<
        K: Clone + Debug + Eq + Hash,
        V: Eq + Hash + Debug + Clone,
        I: Clone + Default + PartialEq + Debug + Map<K, V>,
        P: Persist<(K, V)> + Persistable<I>,
    >(
        _map: P,
        strat: impl Strategy<Value = Vec<PersistAction<(K, V)>>>,
    ) {
        let mut runner = TestRunner::new(Config::default());
        runner.run(&strat, move |v| {
            test_persistasble_impl(P::new(), v);
            Ok(())
        }).unwrap();
    }
    #[test]
    pub fn proptest_persistable_hash_map() {
        test_persistasble(PersistableHashMap::new(), actions(1000));
    }
    // #[test]
    // pub fn proptest_persistable_hash_set() {
    //     test_persistasble(PersistableHashSet::new(), actions(1000));
    // }
    #[test]
    pub fn proptest_persistable_hash_map_multi() {
        test_persistasble(PersistableBTreeMultiMap::new(), actions(1000));
    }
    #[test]
    pub fn proptest_persistable_hash_map_multi_tree() {
        test_persistasble(PersistableHashMapBTreeMultiMap::new(), actions(1000));
    }
}
