use crate::persistence::EncryptingResourceAdapter;
use atomic_store::RollingLog;
use serde::{de::DeserializeOwned, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::hash::Hash;

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

pub struct KeyValueStore<
    K: DeserializeOwned + Eq + Hash + Serialize,
    V: DeserializeOwned + Serialize,
> {
    store: RollingLog<EncryptingResourceAdapter<HashMap<K, V>>>,
    index: HashMap<K, V>,
}

impl<
        K: Clone + DeserializeOwned + Eq + Hash + Serialize,
        V: Clone + DeserializeOwned + Serialize,
    > KeyValueStore<K, V>
{
    pub fn new(
        store: RollingLog<EncryptingResourceAdapter<HashMap<K, V>>>,
    ) -> Result<Self, KeyValueStoreError> {
        let index = store.load_latest()?;
        Ok(Self { store, index })
    }

    pub fn iter(&self) -> impl Iterator<Item = &V> {
        self.index.values()
    }

    pub fn load(&self, key: &K) -> Result<V, KeyValueStoreError> {
        self.index
            .get(key)
            .cloned()
            .ok_or(KeyValueStoreError::KeyNotFound)
    }

    pub fn store(&mut self, key: &K, value: &V) -> Result<(), KeyValueStoreError> {
        self.index.insert(key.clone(), value.clone());
        Ok(())
    }

    pub fn commit_version(&mut self) -> Result<(), KeyValueStoreError> {
        self.store.store_resource(&self.index)?;
        Ok(self.store.commit_version()?)
    }

    pub fn revert_version(&mut self) -> Result<(), KeyValueStoreError> {
        self.index = self.store.load_latest()?;
        Ok(())
    }

    pub fn delete(&mut self, key: &K) -> Result<V, KeyValueStoreError> {
        self.index
            .remove(key)
            .ok_or(KeyValueStoreError::KeyNotFound)
    }
}
