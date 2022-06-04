use crate::{key_value_store::*, persistence::EncryptingResourceAdapter};
use atomic_store::RollingLog;
use jf_cap::structs::{AssetCode, AssetPolicy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

#[derive(Clone, Deserialize, Serialize)]
pub struct Asset {
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
    pub fn new(
        store: RollingLog<EncryptingResourceAdapter<HashMap<AssetCode, Asset>>>,
    ) -> Result<Self, KeyValueStoreError> {
        let store = KeyValueStore::new(store)?;
        Ok(Self { store })
    }

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

    pub fn commit(&mut self) -> Result<(), KeyValueStoreError> {
        self.store.commit_version()
    }

    pub fn revert(&mut self) -> Result<(), KeyValueStoreError> {
        self.store.revert_version()
    }

    pub fn create(&mut self, pk: AssetCode) -> Result<AssetEditor<'_>, KeyValueStoreError> {
        let asset = Asset {
            pk,
            data: Default::default(),
        };
        self.store.store(&pk, &asset)?;
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    pub fn delete(&mut self, pk: &AssetCode) -> Result<Asset, KeyValueStoreError> {
        self.store.delete(pk)
    }
}
