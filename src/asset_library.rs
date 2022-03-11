// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Collections of and information on CAP assets.
//!
//! This module defines [AssetInfo] and [MintInfo], which store auxiliary information about assets
//! which is useful to wallets but not present in [AssetDefinition]. For example, [AssetInfo] may
//! include a [MintInfo], which contains the secret information needed by the asset creator to mint
//! more of that asset type.
//!
//! This module also defines an interface for verified asset types, [VerifiedAssetLibrary]. This is
//! a collection of assets which can be signed by a trusted party, such as an application developer,
//! and distributed to client applications. Applications with verified status can thus be displayed
//! as such, for example by including a badge in a GUI application. Note that this library merely
//! provides the mechanisms and interfaces for creating and consuming verified asset libraries. It
//! does not define any specific libraries or verification keys, as these are application-specific
//! and thus should be defined in clients of this crate.
use jf_cap::{
    keys::AuditorPubKey,
    structs::{AssetCode, AssetCodeSeed, AssetDefinition},
    BaseField, KeyPair, Signature, VerKey,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::iter::FromIterator;
use std::ops::Index;
use std::str::FromStr;
use tagged_base64::TaggedBase64;

/// Details about an asset type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetInfo {
    /// CAP asset definition.
    pub definition: AssetDefinition,
    /// Secret information required to mint an asset.
    pub mint_info: Option<MintInfo>,
    /// This asset is included in a [VerifiedAssetLibrary].
    pub verified: bool,
    /// This asset is not included in the persistent asset library.
    ///
    /// It will need to be reloaded when the wallet is restarted.
    pub temporary: bool,
}

impl AssetInfo {
    pub fn new(definition: AssetDefinition, mint_info: MintInfo) -> Self {
        Self {
            definition,
            mint_info: Some(mint_info),
            verified: false,
            temporary: false,
        }
    }

    fn verified(definition: AssetDefinition) -> Self {
        Self {
            definition,
            // Verified assets are meant to be distributed. We should never distribute mint info.
            mint_info: None,
            verified: true,
            // Assets loaded from verified libraries are not included in our persistent state.
            // Instead, they should be loaded from the verified library each time the wallet is
            // launched, in case the verified library changes.
            //
            // Note that if the same asset is imported manually, it will be persisted due to the
            // semantics of [AssetInfo::update] with respect to `temporary`, but upon being loaded
            // it will be marked unverified until the verified library containing it is reloaded.
            temporary: true,
        }
    }

    /// Details about the native asset type.
    pub fn native() -> Self {
        Self::from(AssetDefinition::native())
    }

    /// Update this info by merging in information from `info`.
    ///
    /// * `self.definition` is replaced with `info.definition`
    /// * If `info.mint_info` exists, it replaces `self.mint_info`
    /// * `self.temporary` is `true` only if both `self` and `info` are temporary
    /// * `self.verified` is `true` if either `self` or `info` is verified
    pub fn update(&mut self, info: AssetInfo) {
        self.definition = info.definition;
        if let Some(mint_info) = info.mint_info {
            self.mint_info = Some(mint_info);
        }
        self.temporary &= info.temporary;
        self.verified |= info.verified;
    }
}

impl From<AssetDefinition> for AssetInfo {
    fn from(definition: AssetDefinition) -> Self {
        Self {
            definition,
            mint_info: None,
            verified: false,
            temporary: false,
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
                mint_info.fmt_description(),
            )?;
        }
        write!(
            f,
            ",verified:{},temporary:{}",
            self.verified, self.temporary
        )?;
        Ok(())
    }
}

impl FromStr for AssetInfo {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // This parse method is meant for a friendly, discoverable CLI interface. It parses a comma-
        // separated list of key-value pairs, like `description:my_asset`. This allows the fields to
        // be specified in any order, or not at all.
        //
        // Recognized fields are "description", "seed", "definition", and "temporary". Note that the
        // `verified` field cannot be set this way. There is only one way to create verified
        // `AssetInfo`: using [Wallet::verify_assets], which performs a signature check before
        // marking assets verified.
        let mut definition = None;
        let mut seed = None;
        let mut description = None;
        let mut temporary = false;
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
                "temporary" => {
                    temporary = value
                        .parse()
                        .map_err(|_| format!("expected bool, got {}", value))?
                }
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
            temporary,
            verified: false,
        })
    }
}

/// Information required to mint an asset.
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

/// Indexable collection of asset types.
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
    /// Create an [AssetLibrary] with the given assets and viewing keys.
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

    /// Add a viewing key.
    ///
    /// Any assets which were already in the library and can be viewed using this key will be marked
    /// as viewable.
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

    /// List viewable assets.
    pub fn auditable(&self) -> &HashMap<AssetCode, AssetDefinition> {
        &self.auditable
    }

    /// Iterate over all assets in the library.
    pub fn iter(&self) -> impl Iterator<Item = &AssetInfo> {
        self.assets.iter()
    }

    /// Check if the library contains an asset with the given code.
    pub fn contains(&self, code: AssetCode) -> bool {
        self.index.contains_key(&code)
    }

    /// Get the asset with the given code, if there is one.
    pub fn get(&self, code: AssetCode) -> Option<&AssetInfo> {
        self.index.get(&code).map(|i| &self.assets[*i])
    }

    /// The total number of assets in the library.
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Returns `true` if and only if there are no assets in the library.
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
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

impl IntoIterator for AssetLibrary {
    type Item = AssetInfo;
    type IntoIter = <Vec<AssetInfo> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.assets.into_iter()
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

/// A library of assets, signed by a trusted party.
///
/// The creation, distribution, and consumption of verified asset libraries should go roughly as
/// follows:
/// 1. An application developer creates a [KeyPair] which will be used to sign asset libraries meant
///    for their application. They store the [KeyPair] containing the private signing key in a
///    secure, private location. The `gen_signing_key` executable that ships with this crate can be
///    used to do this.
/// 2. The application developer creates a [VerifiedAssetLibrary] using their new signing key and
///    writes it to a file (for example, using [bincode] serialization). The
///    `gen_verified_asset_library` executable that ships with this crate can be used to do this.
/// 3. The application developer distributes this file to users along with the client application.
/// 4. The application, upon creating a [Wallet](crate::Wallet), deserializes the
///    [VerifiedAssetLibrary] and calls [Wallet::verify_assets](crate::Wallet::verify_assets) with
///    the public key from step 1. This key can be hard-coded in the client application.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedAssetLibrary {
    // The public key which was used to sign this library (for inspection purposes).
    signer: VerKey,
    signature: Signature,
    assets: Vec<AssetInfo>,
}

impl VerifiedAssetLibrary {
    /// Create and sign a new verified asset library.
    pub fn new(assets: impl IntoIterator<Item = AssetDefinition>, signer: &KeyPair) -> Self {
        let assets = assets
            .into_iter()
            .map(AssetInfo::verified)
            .collect::<Vec<_>>();
        Self {
            signer: signer.ver_key(),
            signature: signer.sign(&[Self::digest(&assets)]),
            assets,
        }
    }

    /// Obtain a list of the assets in `self`, but only if `self` is signed by `trusted_signer`.
    pub fn open(self, trusted_signer: &VerKey) -> Option<Vec<AssetInfo>> {
        if self.check() == Some(trusted_signer.clone()) {
            Some(self.assets)
        } else {
            None
        }
    }

    /// Check that the library is correctly signed and return the public key used to sign it.
    pub fn check(&self) -> Option<VerKey> {
        if self
            .signer
            .verify(&[Self::digest(&self.assets)], &self.signature)
            .is_ok()
        {
            Some(self.signer.clone())
        } else {
            None
        }
    }

    fn digest(assets: &[AssetInfo]) -> BaseField {
        let bytes = assets
            .iter()
            .map(|asset| bincode::serialize(asset).unwrap())
            .flatten()
            .collect::<Vec<_>>();
        jf_utils::hash_to_field(bytes)
    }
}
