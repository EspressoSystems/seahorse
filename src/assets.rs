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

/// An asset with its definition as the primary key.
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

type AssetsStore = KeyValueStore<AssetDefinition, Asset>;

/// An editor to create or update the asset or assets store.
pub struct AssetEditor<'a> {
    asset: Asset,
    store: &'a mut AssetsStore,
}

impl<'a> AssetEditor<'a> {
    /// Create an asset editor.
    pub fn new(store: &'a mut AssetsStore, asset: Asset) -> Self {
        Self { asset, store }
    }

    /// Set the asset name.
    pub fn set_name(mut self, name: Option<String>) -> Self {
        self.asset.name = name;
        self
    }

    /// Set the asset description.
    pub fn set_description(mut self, description: Option<String>) -> Self {
        self.asset.description = description;
        self
    }

    /// Set the asset icon.
    pub fn set_icon(mut self, icon: Option<Icon>) -> Self {
        self.asset.icon = icon;
        self
    }

    /// Save the asset to the assets store.
    ///
    /// Returns the stored asset.
    pub fn save<L: Ledger>(self) -> Result<Asset, KeystoreError<L>> {
        self.store.store(&self.asset.definition, &self.asset)?;
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

/// Assets stored in an assets store.
pub struct Assets {
    store: AssetsStore,
}

impl Assets {
    /// Create assets.
    pub fn new<L: Ledger>(store: AssetsStore) -> Result<Self, KeystoreError<L>> {
        Ok(Self { store })
    }

    /// Iterate through the assets.
    pub fn iter(&self) -> impl Iterator<Item = Asset> + '_ {
        self.store.iter().cloned()
    }

    /// Get the asset by the definiton.
    pub fn get<L: Ledger>(&self, definition: &AssetDefinition) -> Result<Asset, KeystoreError<L>> {
        Ok(self.store.load(definition)?)
    }

    /// Get a mutable asset editor by the definition.
    pub fn get_mut<L: Ledger>(
        &mut self,
        definition: &AssetDefinition,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let asset = self.get(definition)?;
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

    /// Create an asset and add it to the store.
    ///
    /// Returns the created asset.
    pub fn create<L: Ledger>(
        &mut self,
        definition: AssetDefinition,
        mint_info: Option<MintInfo>,
        verified: bool,
        temporary: bool,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let asset = Asset {
            definition: definition.clone(),
            name: None,
            description: None,
            icon: None,
            mint_info,
            verified,
            temporary,
        };
        self.store.store(&definition, &asset)?;
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    /// Deletes an asset from the store.
    ///
    /// Returns the deleted asset.
    pub fn delete<L: Ledger>(
        &mut self,
        definition: &AssetDefinition,
    ) -> Result<Asset, KeystoreError<L>> {
        Ok(self.store.delete(definition)?)
    }
}
