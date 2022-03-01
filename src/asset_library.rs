use jf_cap::{
    keys::AuditorPubKey,
    structs::{AssetCode, AssetCodeSeed, AssetDefinition},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::ops::Index;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetInfo {
    pub asset: AssetDefinition,
    pub mint_info: Option<MintInfo>,
}

impl AssetInfo {
    pub fn new(asset: AssetDefinition, mint_info: MintInfo) -> Self {
        Self {
            asset,
            mint_info: Some(mint_info),
        }
    }

    pub fn native() -> Self {
        Self {
            asset: AssetDefinition::native(),
            mint_info: None,
        }
    }

    /// Update this info by merging in information from `info`.
    ///
    /// * `self.asset` is replaced with `info.asset`
    /// * If `info.mint_info` exists, it replaces `self.mint_info`
    pub fn update(&mut self, info: AssetInfo) {
        self.asset = info.asset;
        if let Some(mint_info) = info.mint_info {
            self.mint_info = Some(mint_info);
        }
    }
}

impl From<AssetDefinition> for AssetInfo {
    fn from(asset: AssetDefinition) -> Self {
        Self {
            asset,
            mint_info: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MintInfo {
    pub seed: AssetCodeSeed,
    pub desc: Vec<u8>,
}

impl MintInfo {
    pub fn new(seed: AssetCodeSeed, desc: Vec<u8>) -> Self {
        Self { seed, desc }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AssetLibrary {
    assets: Vec<AssetInfo>,
    // Map from AssetCode to index in `assets`.
    index: HashMap<AssetCode, usize>,
    // Map from auditable AssetCode to its definition.
    auditable: HashMap<AssetCode, AssetDefinition>,
    // Auditor keys, so we can tell when an asset is supposed to be in `auditable`.
    audit_keys: HashSet<AuditorPubKey>,
}

impl AssetLibrary {
    pub fn new(assets: Vec<AssetInfo>, audit_keys: HashSet<AuditorPubKey>) -> Self {
        // Create the library empty so that we can use `insert` to add the assets, which will ensure
        // that all of the data structures (assets, index, and auditable) are populated consistently.
        let mut lib = Self {
            assets: Default::default(),
            index: Default::default(),
            auditable: Default::default(),
            audit_keys,
        };

        for asset in assets {
            lib.insert(asset);
        }
        lib
    }

    /// Insert an asset.
    ///
    /// If `asset` is already in the library it is updated (by `AssetInfo::update`). Otherwise, it
    /// is inserted at the end of the library.
    pub fn insert(&mut self, asset: AssetInfo) {
        if let Some(i) = self.index.get(&asset.asset.code) {
            self.assets[*i].update(asset);
        } else {
            self.index.insert(asset.asset.code, self.assets.len());
            if self
                .audit_keys
                .contains(asset.asset.policy_ref().auditor_pub_key())
            {
                self.auditable.insert(asset.asset.code, asset.asset.clone());
            }
            self.assets.push(asset);
        }
    }

    pub fn add_audit_key(&mut self, key: AuditorPubKey) {
        // Upon discovering a new audit key, we need to check if any existing assets have now become
        // auditable.
        for asset in &self.assets {
            if asset.asset.policy_ref().auditor_pub_key() == &key {
                self.auditable.insert(asset.asset.code, asset.asset.clone());
            }
        }
        self.audit_keys.insert(key);
    }

    pub fn auditable(&self) -> &HashMap<AssetCode, AssetDefinition> {
        &self.auditable
    }

    pub fn iter(&self) -> impl Iterator<Item = &AssetInfo> {
        self.assets.iter()
    }

    pub fn contains(&self, code: AssetCode) -> bool {
        self.index.contains_key(&code)
    }

    pub fn get(&self, code: AssetCode) -> Option<&AssetInfo> {
        self.index.get(&code).map(|i| &self.assets[*i])
    }
}

impl From<Vec<AssetInfo>> for AssetLibrary {
    fn from(assets: Vec<AssetInfo>) -> Self {
        Self::new(assets, Default::default())
    }
}

impl From<AssetLibrary> for Vec<AssetInfo> {
    fn from(lib: AssetLibrary) -> Self {
        lib.assets
    }
}

impl FromIterator<AssetInfo> for AssetLibrary {
    fn from_iter<T: IntoIterator<Item = AssetInfo>>(iter: T) -> Self {
        iter.into_iter().collect::<Vec<_>>().into()
    }
}

impl Index<AssetCode> for AssetLibrary {
    type Output = AssetInfo;

    fn index(&self, code: AssetCode) -> &AssetInfo {
        self.get(code).unwrap()
    }
}
