use jf_cap::{
    keys::AuditorPubKey,
    structs::{AssetCode, AssetCodeSeed, AssetDefinition},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::iter::FromIterator;
use std::ops::Index;
use std::str::FromStr;
use tagged_base64::TaggedBase64;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetInfo {
    pub definition: AssetDefinition,
    pub mint_info: Option<MintInfo>,
}

impl AssetInfo {
    pub fn new(definition: AssetDefinition, mint_info: MintInfo) -> Self {
        Self {
            definition,
            mint_info: Some(mint_info),
        }
    }

    pub fn native() -> Self {
        Self {
            definition: AssetDefinition::native(),
            mint_info: None,
        }
    }

    /// Update this info by merging in information from `info`.
    ///
    /// * `self.definition` is replaced with `info.definition`
    /// * If `info.mint_info` exists, it replaces `self.mint_info`
    pub fn update(&mut self, info: AssetInfo) {
        self.definition = info.definition;
        if let Some(mint_info) = info.mint_info {
            self.mint_info = Some(mint_info);
        }
    }
}

impl From<AssetDefinition> for AssetInfo {
    fn from(definition: AssetDefinition) -> Self {
        Self {
            definition,
            mint_info: None,
        }
    }
}

impl Display for AssetInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "definition:{}", self.definition)?;
        if let Some(mint_info) = &self.mint_info {
            write!(
                f,
                ",seed:{},description:{}",
                mint_info.seed,
                mint_info.fmt_description()
            )?;
        }
        Ok(())
    }
}

impl FromStr for AssetInfo {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // This parse method is meant for a friendly, discoverable CLI interface. It parses a comma-
        // separated list of key-value pairs, like `description:my_asset`. This allows the fields to
        // be specified in any order, or not at all. Recognized fields are "description", "seed",
        // and "definition".
        let mut definition = None;
        let mut seed = None;
        let mut description = None;
        for kv in s.split(',') {
            let (key, value) = match kv.split_once(':') {
                Some(split) => split,
                None => return Err(format!("expected key:value pair, got {}", kv)),
            };
            match key {
                "definition" => {
                    definition = Some(
                        value
                            .parse()
                            .map_err(|_| format!("expected AssetDefinition, got {}", value))?,
                    )
                }
                "seed" => {
                    seed = Some(
                        value
                            .parse()
                            .map_err(|_| format!("expected AssetCodeSeed, got {}", value))?,
                    )
                }
                "description" => description = Some(MintInfo::parse_description(value)),
                _ => return Err(format!("unrecognized key {}", key)),
            }
        }

        let definition = match definition {
            Some(definition) => definition,
            None => return Err(String::from("must specify definition")),
        };
        let mint_info = match (seed, description) {
            (Some(seed), Some(description)) => Some(MintInfo { seed, description }),
            (None, None) => None,
            _ => {
                return Err(String::from(
                    "seed and description must be specified together or not at all",
                ))
            }
        };
        Ok(AssetInfo {
            definition,
            mint_info,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MintInfo {
    pub seed: AssetCodeSeed,
    pub description: Vec<u8>,
}

impl MintInfo {
    pub fn new(seed: AssetCodeSeed, description: Vec<u8>) -> Self {
        Self { seed, description }
    }

    /// Try to format the asset description as human-readable as possible.
    pub fn fmt_description(&self) -> String {
        // If it looks like it came from a string, interpret as a string. Otherwise, encode the
        // binary blob as tagged base64.
        match std::str::from_utf8(&self.description) {
            Ok(s) => String::from(s),
            Err(_) => TaggedBase64::new("DESC", &self.description)
                .unwrap()
                .to_string(),
        }
    }

    /// Inverse of `fmt_description()`.
    pub fn parse_description(description: &str) -> Vec<u8> {
        if let Ok(tb64) = TaggedBase64::parse(description) {
            // If the description was serialized as TaggedBase64, get the binary data.
            tb64.value()
        } else {
            // Otherwise, the description is just a utf-8 string.
            description.as_bytes().to_vec()
        }
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
        if let Some(i) = self.index.get(&asset.definition.code) {
            self.assets[*i].update(asset);
        } else {
            self.index.insert(asset.definition.code, self.assets.len());
            if self
                .audit_keys
                .contains(asset.definition.policy_ref().auditor_pub_key())
            {
                self.auditable
                    .insert(asset.definition.code, asset.definition.clone());
            }
            self.assets.push(asset);
        }
    }

    pub fn add_audit_key(&mut self, key: AuditorPubKey) {
        // Upon discovering a new audit key, we need to check if any existing assets have now become
        // auditable.
        for asset in &self.assets {
            if asset.definition.policy_ref().auditor_pub_key() == &key {
                self.auditable
                    .insert(asset.definition.code, asset.definition.clone());
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
