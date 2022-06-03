use crate::persistence::EncryptingResourceAdapter;
use atomic_store::RollingLog;
use jf_cap::structs::{AssetCode, AssetPolicy};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

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
    fn new(
        store: RollingLog<EncryptingResourceAdapter<HashMap<K, V>>>,
    ) -> Result<Self, KeyValueStoreError> {
        let index = HashMap::from(store.load_latest()?);
        Ok(Self { store, index })
    }

    fn iter(&self) -> impl Iterator<Item = &V> {
        self.index.values()
    }

    fn load(&self, key: &K) -> Result<V, KeyValueStoreError> {
        self.index
            .get(key)
            .cloned()
            .ok_or(KeyValueStoreError::KeyNotFound)
    }

    fn store(&mut self, key: &K, value: &V) -> Result<(), KeyValueStoreError> {
        self.index.insert(key.clone(), value.clone());
        Ok(())
    }

    fn commit_version(&mut self) -> Result<(), KeyValueStoreError> {
        self.store.store_resource(&self.index)?;
        Ok(self.store.commit_version()?)
    }

    fn revert_version(&mut self) -> Result<(), KeyValueStoreError> {
        self.index = self.store.load_latest()?;
        Ok(())
    }

    fn delete(&mut self, key: &K) -> Result<V, KeyValueStoreError> {
        self.index
            .remove(key)
            .ok_or(KeyValueStoreError::KeyNotFound)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Asset {
    // TODO !keyao `pk` or `primary_key`?
    pk: AssetCode,
    pub data: AssetPolicy,
}

impl Asset {
    pub fn data(&self) -> &AssetPolicy {
        &self.data
    }
}

type AssetsStore = KeyValueStore<AssetCode, Asset>;

pub struct AssetEditor<'a> {
    asset: Asset,
    store: &'a mut AssetsStore,
}

impl<'a> AssetEditor<'a> {
    pub fn new(store: &'a mut AssetsStore, asset: Asset) -> Self {
        Self { asset, store }
    }

    pub fn set_data(mut self, data: AssetPolicy) -> Self {
        self.asset.data = data;
        self
    }

    pub fn save(self) -> Result<Asset, KeyValueStoreError> {
        self.store.store(&self.asset.pk, &self.asset)?;
        Ok(self.asset)
    }
}

impl<'a> Deref for AssetEditor<'a> {
    type Target = Asset;

    fn deref(&self) -> &Asset {
        &self.asset
    }
}

impl<'a> DerefMut for AssetEditor<'a> {
    fn deref_mut(&mut self) -> &mut Asset {
        &mut self.asset
    }
}

pub struct Assets {
    store: AssetsStore,
}

impl Assets {
    pub fn iter(&self) -> impl Iterator<Item = &Asset> {
        self.store.iter()
    }

    pub fn get(&self, pk: &AssetCode) -> Result<Asset, KeyValueStoreError> {
        self.store.load(pk)
    }

    pub fn get_mut(&mut self, pk: &AssetCode) -> Result<AssetEditor<'_>, KeyValueStoreError> {
        let asset = self.get(pk)?;
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    pub fn create(&mut self, pk: AssetCode) -> Result<AssetEditor<'_>, KeyValueStoreError> {
        let asset = Asset {
            pk: pk.clone(),
            data: Default::default(),
        };
        self.store.store(&pk, &asset)?;
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    pub fn delete(&mut self, pk: &AssetCode) -> Result<Asset, KeyValueStoreError> {
        self.store.delete(pk)
    }
}
