// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The assets module.
//!
//! This module defines [Asset], [AssetEditor], and [Assets], which provide CURD (create, read,
//! update, and delete) operations, with the use of [KeyValueStore] to control the assets resource.

use crate::{asset_library::Icon, key_value_store::*, KeystoreError, Ledger, MintInfo};
use jf_cap::structs::{AssetCode, AssetDefinition, AssetPolicy};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

/// An asset with its code as the primary key.
#[derive(Clone, Deserialize, Serialize)]
pub struct Asset {
    definition: AssetDefinition,
    /// Optional asset name.
    pub name: Option<String>,
    /// Optional asset description.
    pub description: Option<String>,
    /// Optional asset icon.
    pub icon: Option<Icon>,
    mint_info: Option<MintInfo>,
    verified: bool,
    temporary: bool,
}

impl Asset {
    #![allow(dead_code)]

    /// Create a verified and temporary asset without mint information.
    ///
    /// Returns the created asset.
    fn new_verified(definition: AssetDefinition) -> Self {
        Self {
            definition,
            name: None,
            description: None,
            icon: None,
            mint_info: None,
            verified: true,
            temporary: true,
        }
    }

    /// Create a native asset.
    ///
    /// Returns the created asset.
    fn new_native<L: Ledger>() -> Self {
        Self {
            definition: AssetDefinition::native(),
            name: Some(L::name().to_uppercase()),
            description: Some(format!("The {} native asset type", L::name())),
            icon: None,
            mint_info: None,
            verified: false,
            temporary: false,
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

    /// Check if the asset is temporary.
    pub fn temporary(&self) -> bool {
        self.temporary
    }
}

type AssetsStore = KeyValueStore<AssetCode, Asset>;

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
        self.asset.icon = icon;
        self
    }

    /// Set the asset icon.
    pub fn with_icon(mut self, icon: Icon) -> Self {
        self.asset.icon = Some(icon);
        self
    }

    /// Clear the asset icon.
    pub fn clear_icon(mut self) -> Self {
        self.asset.icon = None;
        self
    }

    /// Save the asset to the store if it's nontemporary.
    ///
    /// If the store has an asset with the same code, merges with it.
    ///
    /// Returns the stored asset.
    pub fn save<L: Ledger>(&mut self) -> Result<Asset, KeystoreError<L>> {
        self.update();
        if !self.asset.temporary {
            self.store.store(&self.asset.definition.code, &self.asset)?;
        }
        Ok(self.asset.clone())
    }

    /// If there exists an asset in the store with the same code as the editor asset, updates the
    /// editor asset by merging in the store asset.
    /// * Keeps the asset name, description or icon of the editor asset if
    ///   * the editor asset is verified and the store asset is not, and
    ///   * the corresponding attribute exists.
    /// * Keeps the mint information of the editor asset, if present.
    /// * Sets as verified if either asset if verified.
    /// * Sets as temporary if both assets are temporary.
    pub fn update(&mut self) {
        if let Ok(store_asset) = self.store.load(&self.asset.definition.code) {
            let mut asset = store_asset;
            if self.asset.verified || !asset.verified {
                if let Some(name) = self.asset.name.clone() {
                    asset.name = Some(name);
                }
                if let Some(description) = self.asset.description.clone() {
                    asset.description = Some(description);
                }
                if let Some(icon) = self.asset.icon.clone() {
                    asset.icon = Some(icon);
                }
            }
            if let Some(mint_info) = self.asset.mint_info.clone() {
                asset.mint_info = Some(mint_info);
            }
            asset.verified |= self.asset.verified;
            asset.temporary &= self.asset.temporary;
            self.asset = asset;
        }
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
    pub store: AssetsStore,
}

impl Assets {
    #![allow(dead_code)]

    /// Create assets.
    pub fn new<L: Ledger>(store: AssetsStore) -> Result<Self, KeystoreError<L>> {
        Ok(Self { store })
    }

    /// Iterate through the assets.
    pub fn iter(&self) -> impl Iterator<Item = Asset> + '_ {
        self.store.iter().cloned()
    }

    /// Get the asset by the code.
    pub fn get<L: Ledger>(&self, code: &AssetCode) -> Result<Asset, KeystoreError<L>> {
        Ok(self.store.load(code)?)
    }

    /// Get a mutable asset editor by the code.
    pub fn get_mut<L: Ledger>(
        &mut self,
        code: &AssetCode,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let asset = self.get(code)?;
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

    /// Create an unverified and nontemporary asset.
    ///
    /// If the store doesn't have an asset with the same code, adds the created asset to the store.
    /// Otherwise, updates the exisiting asset.
    ///
    /// Returns the editor for the created asset.
    ///
    /// To create a verified and temporary asset, use `create_verified` instead.
    pub fn create<L: Ledger>(
        &mut self,
        definition: AssetDefinition,
        mint_info: Option<MintInfo>,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let asset = Asset {
            definition: definition.clone(),
            name: None,
            description: None,
            icon: None,
            mint_info,
            verified: false,
            temporary: false,
        };
        let mut editor = AssetEditor::new(&mut self.store, asset.clone());
        editor.update();
        self.store.store(&definition.code, &asset)?;
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    /// Create a verified and temporary asset without mint information.
    ///
    /// If the store doesn't have an asset with the same code, adds the created asset to the store.
    /// Otherwise, updates the exisiting asset.
    ///
    /// Returns the editor for the created asset.
    ///
    /// To create an unverified and nontemporary asset, use `create` instead.
    fn create_verified<L: Ledger>(
        &mut self,
        definition: AssetDefinition,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let asset = Asset {
            definition: definition.clone(),
            name: None,
            description: None,
            icon: None,
            mint_info: None,
            verified: true,
            temporary: true,
        };
        let mut editor = AssetEditor::new(&mut self.store, asset.clone());
        editor.update();
        self.store.store(&definition.code, &asset)?;
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    /// Create a native asset.
    ///
    /// Returns the editor for the created asset.
    fn create_native<L: Ledger>(
        &mut self,
        definition: AssetDefinition,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let asset = Asset {
            definition: AssetDefinition::native(),
            name: Some(L::name().to_uppercase()),
            description: Some(format!("The {} native asset type", L::name())),
            icon: None,
            mint_info: None,
            verified: false,
            temporary: false,
        };
        let mut editor = AssetEditor::new(&mut self.store, asset.clone());
        editor.update();
        self.store.store(&definition.code, &asset)?;
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    /// Deletes an asset from the store.
    ///
    /// Returns the deleted asset.
    pub fn delete<L: Ledger>(&mut self, code: &AssetCode) -> Result<Asset, KeystoreError<L>> {
        Ok(self.store.delete(code)?)
    }
}
