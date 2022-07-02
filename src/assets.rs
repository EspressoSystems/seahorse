// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The assets module.
//!
//! This module defines [Asset], [AssetEditor], and [Assets], which provide CURD (create, read,
//! update, and delete) operations, with the use of [KeyValueStore] to control the assets resource.

use crate::{
    asset_library::Icon, key_value_store::*, KeystoreError, Ledger, MintInfo, VerifiedAssetLibrary,
};
use jf_cap::{
    structs::{AssetCode, AssetDefinition, AssetPolicy},
    VerKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

const ICON_WIDTH: u32 = 64;
const ICON_HEIGHT: u32 = 64;

/// An asset with its code as the primary key.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Asset {
    definition: AssetDefinition,
    /// Optional asset name.
    pub name: Option<String>,
    /// Optional asset description.
    pub description: Option<String>,
    /// Optional asset icon.
    pub icon: Option<Icon>,
    mint_info: Option<MintInfo>,
    // Skip this field when serializing to ensure it's `false` upon deserialization. Thus, an asset
    // loaded from disk will never have `verified = true`.
    //
    // We keep an in-memory set of verified asset codes loaded from asset library in `Assets`.
    // Whenever we load an asset with `get` or `get_mut`, or create one with `create`, we set
    // `verified = true` if its code is in that set. Therefore, `verified` is essentially a transient
    // in-memory only field which is `true` if and only if it's in the verified set.
    #[serde(skip)]
    verified: bool,
}

impl Asset {
    #![allow(dead_code)]

    /// Create a native asset.
    ///
    /// Returns the created asset.
    fn native<L: Ledger>() -> Self {
        Self {
            definition: AssetDefinition::native(),
            name: Some(L::name().to_uppercase()),
            description: Some(format!("The {} native asset type", L::name())),
            icon: None,
            mint_info: None,
            verified: false,
        }
    }

    /// Get the asset definition.
    pub fn definition(&self) -> &AssetDefinition {
        &self.definition
    }

    /// Get the asset code.
    pub fn code(&self) -> AssetCode {
        self.definition.code
    }

    /// Get the asset policy.
    pub fn policy(&self) -> &AssetPolicy {
        self.definition.policy_ref()
    }

    /// Get the optional asset name.
    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }

    /// Get the optional asset description.
    pub fn description(&self) -> Option<String> {
        self.description.clone()
    }

    /// Get the optional asset icon.
    pub fn icon(&self) -> Option<Icon> {
        self.icon.clone()
    }

    /// Get the optional mint information.
    pub fn mint_info(&self) -> Option<MintInfo> {
        self.mint_info.clone()
    }

    /// Check if the asset is verified.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Changes the asset to be verified without mint information.
    ///
    /// Returns the verified asset.
    ///
    /// Mint information isn't included since it's a secret, and we don't want to export secret
    /// information.
    pub(crate) fn export_verified(mut self) -> Self {
        self.mint_info = None;
        self.verified = true;
        self
    }

    /// Create an asset for testing purposes.
    #[cfg(test)]
    pub fn from(
        definition: AssetDefinition,
        name: Option<String>,
        description: Option<String>,
        icon: Option<Icon>,
        mint_info: Option<MintInfo>,
        verified: bool,
    ) -> Self {
        Self {
            definition,
            name,
            description,
            icon,
            mint_info,
            verified,
        }
    }
}

impl FromStr for Asset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // This parse method is meant for a friendly, discoverable CLI interface. It parses a comma-
        // separated list of key-value pairs, like `description:my_asset`. This allows the fields to
        // be specified in any order, or not at all.
        //
        // Recognized fields are "definition", "name", "description", "mint_description", and
        // "seed". Note that the `verified` field cannot be set this way. There is only one way to
        // create verified `Asset`: using [Assets::verify_assets], which performs a signature check
        // before marking assets verified.
        let mut definition = None;
        let mut name = None;
        let mut description = None;
        let mut mint_description = None;
        let mut seed = None;
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
                "name" => {
                    name = Some(value.into());
                }
                "description" => {
                    description = Some(value.into());
                }
                "seed" => {
                    seed = Some(
                        value
                            .parse()
                            .map_err(|_| format!("expected AssetCodeSeed, got {}", value))?,
                    )
                }
                "mint_description" => mint_description = Some(MintInfo::parse_description(value)),
                _ => return Err(format!("unrecognized key {}", key)),
            }
        }
        let definition = match definition {
            Some(definition) => definition,
            None => return Err(String::from("must specify definition")),
        };
        let mint_info = match (seed, mint_description) {
            (Some(seed), Some(description)) => Some(MintInfo { seed, description }),
            (None, None) => None,
            _ => {
                return Err(String::from(
                    "seed and description must be specified together or not at all",
                ))
            }
        };
        Ok(Asset {
            definition,
            name,
            description,
            icon: None,
            mint_info,
            verified: false,
        })
    }
}

#[cfg(test)]
impl From<AssetDefinition> for Asset {
    fn from(definition: AssetDefinition) -> Self {
        Self {
            definition,
            name: None,
            description: None,
            icon: None,
            mint_info: None,
            verified: false,
        }
    }
}

pub type AssetsStore = KeyValueStore<AssetCode, Asset>;

/// An editor to create or update the asset or assets store.
pub struct AssetEditor<'a> {
    asset: Asset,
    store: &'a mut AssetsStore,
}

impl<'a> AssetEditor<'a> {
    /// Create an asset editor.
    fn new(store: &'a mut AssetsStore, asset: Asset) -> Self {
        Self { asset, store }
    }

    /// Set the optional asset name.
    pub fn set_name(mut self, name: Option<String>) -> Self {
        self.asset.name = name;
        self
    }

    /// Set the asset name.
    pub fn with_name(mut self, name: String) -> Self {
        self.asset.name = Some(name);
        self
    }

    /// Clear the asset name.
    pub fn clear_name(mut self) -> Self {
        self.asset.name = None;
        self
    }

    /// Set the optional asset description.
    pub fn set_description(mut self, description: Option<String>) -> Self {
        self.asset.description = description;
        self
    }

    /// Set the asset description.
    pub fn with_description(mut self, description: String) -> Self {
        self.asset.description = Some(description);
        self
    }

    /// Clear the asset description.
    pub fn clear_description(mut self) -> Self {
        self.asset.description = None;
        self
    }

    /// Set the optional asset icon.
    pub fn set_icon(mut self, icon: Option<Icon>) -> Self {
        self.asset.icon = match icon {
            Some(mut icon) => {
                icon.resize(ICON_WIDTH, ICON_HEIGHT);
                Some(icon)
            }
            None => None,
        };
        self
    }

    /// Set the asset icon.
    pub fn with_icon(mut self, mut icon: Icon) -> Self {
        icon.resize(ICON_WIDTH, ICON_HEIGHT);
        self.asset.icon = Some(icon);
        self
    }

    /// Clear the asset icon.
    pub fn clear_icon(mut self) -> Self {
        self.asset.icon = None;
        self
    }

    /// Save the asset to the store.
    ///
    /// Returns the stored asset.
    pub fn save<L: Ledger>(&mut self) -> Result<Asset, KeystoreError<L>> {
        self.store.store(&self.asset.definition.code, &self.asset)?;
        Ok(self.asset.clone())
    }

    /// Updates the asset by merging in the given asset with the same definition.
    /// * Updates the asset name, description or icon if
    ///   * the given asset is verified or the existing asset is not, and
    ///   * the given asset has the corresponding field.
    /// * Updates the mint information, if present in the given asset.
    /// * Sets as verified if either asset if verified.
    pub fn update<L: Ledger>(mut self, other: Asset) -> Result<Self, KeystoreError<L>> {
        let mut asset = self.store.load(&other.definition.code)?;
        if other.verified || !asset.verified {
            if let Some(name) = other.name.clone() {
                asset.name = Some(name);
            }
            if let Some(description) = other.description.clone() {
                asset.description = Some(description);
            }
            if let Some(icon) = other.icon.clone() {
                asset.icon = Some(icon);
            }
        }
        if let Some(mint_info) = other.mint_info.clone() {
            asset.mint_info = Some(mint_info);
        }
        asset.verified |= other.verified;
        self.asset = asset;
        Ok(self)
    }

    /// Updates the asset by merging in the given asset with the same definition.
    /// * Updates the asset name, description or icon if
    ///   * the given asset is verified, and
    ///   * the given asset has the corresponding field.
    /// * Updates the mint information, if present in the given asset.
    /// * Sets as verified if either asset if verified.
    fn update_internal<L: Ledger>(mut self, other: Asset) -> Result<Self, KeystoreError<L>> {
        let mut asset = self.store.load(&other.definition.code)?;
        if other.verified {
            if let Some(name) = other.name.clone() {
                asset.name = Some(name);
            }
            if let Some(description) = other.description.clone() {
                asset.description = Some(description);
            }
            if let Some(icon) = other.icon.clone() {
                asset.icon = Some(icon);
            }
        }
        if let Some(mint_info) = other.mint_info.clone() {
            asset.mint_info = Some(mint_info);
        }
        asset.verified |= other.verified;
        self.asset = asset;
        Ok(self)
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

/// Assets stored in an assets store.
pub struct Assets {
    /// A key-value store for assets.
    store: AssetsStore,

    /// A set of asset codes loaded from verified asset libraries.
    verified_assets: HashSet<AssetCode>,
}

impl Assets {
    #![allow(dead_code)]

    /// Load an assets store.
    ///
    /// None of the loaded assets will be verified until `verify_assets` is called.
    pub fn new<L: Ledger>(store: AssetsStore) -> Result<Self, KeystoreError<L>> {
        Ok(Self {
            store,
            verified_assets: HashSet::new(),
        })
    }

    /// Iterate through the assets.
    pub fn iter(&self) -> impl Iterator<Item = Asset> + '_ {
        let mut assets = Vec::new();
        for mut asset in self.store.iter().cloned() {
            // The asset is verified if it's in the verified set.
            if self.verified_assets.contains(&asset.code()) {
                asset.verified = true;
            }
            assets.push(asset.clone());
        }
        assets.into_iter()
    }

    /// Load a verified asset library with its trusted signer.
    ///
    /// Adds the asset codes to the verified set, adds the assets to the store, and returns the
    /// list of asset definitions.
    ///
    /// Note that the `verified` status of assets is not persisted in order to preserve the
    /// verified asset library as the single source of truth about which assets are verified.
    /// Therefore, this function must be called each time an `Assets` store is created in order to
    /// ensure that the verified assets show up in `verified_assets`.
    ///
    /// This function will not affect assets that have already been loaded into memory. If there's
    /// a previously-loaded asset, we need to reload it after its `verified` flag is updated.
    pub fn verify_assets<L: Ledger>(
        &mut self,
        trusted_signer: &VerKey,
        library: VerifiedAssetLibrary,
    ) -> Result<Vec<AssetDefinition>, KeystoreError<L>> {
        if let Some(assets) = library.open(trusted_signer) {
            let mut definitions = Vec::new();
            for asset in &assets {
                self.verified_assets.insert(asset.definition.code);
                let store_asset = self.store.load(&asset.definition.code);
                let mut editor = AssetEditor::new(&mut self.store, asset.clone());
                if store_asset.is_ok() {
                    editor = editor.update_internal::<L>(asset.clone())?;
                }
                editor.save::<L>()?;
                definitions.push(asset.definition.clone());
            }
            Ok(definitions)
        } else {
            Err(KeystoreError::AssetVerificationError)
        }
    }

    /// Get the asset by the code from the store.
    pub fn get<L: Ledger>(&self, code: &AssetCode) -> Result<Asset, KeystoreError<L>> {
        let mut asset = self.store.load(code)?;
        // The asset is verified if it's in the verified set.
        if self.verified_assets.contains(code) {
            asset.verified = true
        }
        Ok(asset)
    }

    /// Get a mutable asset editor by the code from the store.
    pub fn get_mut<L: Ledger>(
        &mut self,
        code: &AssetCode,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let mut asset = self.get(code)?;
        // The asset is verified if it's in the verified set.
        if self.verified_assets.contains(code) {
            asset.verified = true
        }
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    /// Commit the store version.
    pub fn commit<L: Ledger>(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert<L: Ledger>(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.revert_version()?)
    }

    /// Create an unverified asset.
    ///
    /// If the store doesn't have an asset with the same code, adds the created asset to the store.
    /// Otherwise, updates the exisiting asset.
    ///
    /// Returns the editor for the created asset.
    pub fn create<L: Ledger>(
        &mut self,
        definition: AssetDefinition,
        mint_info: Option<MintInfo>,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let mut asset = Asset {
            definition,
            name: None,
            description: None,
            icon: None,
            mint_info,
            verified: false,
        };
        // The asset is verified if it's in the verified set.
        if self.verified_assets.contains(&asset.definition.code) {
            asset.verified = true
        }
        let store_asset = self.store.load(&asset.definition.code);
        let mut editor = AssetEditor::new(&mut self.store, asset.clone());
        if store_asset.is_ok() {
            editor = editor.update::<L>(asset)?;
        }
        editor.save::<L>()?;
        Ok(editor)
    }

    /// Create a native asset.
    ///
    /// Returns the editor for the created asset.
    pub fn create_native<L: Ledger>(&mut self) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let mut asset = Asset::native::<L>();
        // The asset is verified if it's in the verified set.
        if self.verified_assets.contains(&asset.definition.code) {
            asset.verified = true
        }
        let store_asset = self.store.load(&asset.definition.code);
        let mut editor = AssetEditor::new(&mut self.store, asset.clone());
        if store_asset.is_ok() {
            editor = editor.update::<L>(asset)?;
        }
        editor.save::<L>()?;
        Ok(editor)
    }

    /// Create an asset internally.
    ///
    /// If the store doesn't have an asset with the same code, adds the created asset to the store.
    /// Otherwise, updates the exisiting asset.
    ///
    /// Returns the editor for the created asset.
    pub(crate) fn create_internal<L: Ledger>(
        &mut self,
        definition: AssetDefinition,
        mint_info: Option<MintInfo>,
        verified: bool,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let asset = Asset {
            definition,
            name: None,
            description: None,
            icon: None,
            mint_info,
            verified,
        };
        let store_asset = self.store.load(&asset.definition.code);
        let mut editor = AssetEditor::new(&mut self.store, asset.clone());
        if store_asset.is_ok() {
            editor = editor.update_internal::<L>(asset)?;
        }
        editor.save::<L>()?;
        Ok(editor)
    }

    /// Deletes an asset from the store.
    ///
    /// Returns the deleted asset.
    pub fn delete<L: Ledger>(&mut self, code: &AssetCode) -> Result<Asset, KeystoreError<L>> {
        Ok(self.store.delete(code)?)
    }
}
