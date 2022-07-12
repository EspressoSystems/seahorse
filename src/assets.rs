// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The assets module.
//!
//! This module defines [Asset], [AssetEditor], and [Assets], which provide CURD (create, read,
//! update, and delete) operations, with the use of [KeyValueStore] to control the assets resource.

use crate::{key_value_store::*, KeystoreError, Ledger};
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use espresso_macros::ser_test;
use image::{imageops, ImageBuffer, ImageFormat, ImageResult, Pixel, Rgba};
use jf_cap::{
    structs::{AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy},
    BaseField, CurveParam, KeyPair, Signature, VerKey,
};
use jf_primitives::signatures::{schnorr::SchnorrSignatureScheme, SignatureScheme};
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Seek};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use tagged_base64::TaggedBase64;

const ICON_WIDTH: u32 = 64;
const ICON_HEIGHT: u32 = 64;

type IconPixel = Rgba<u8>;

/// A small icon to display with an asset in a GUI interface.
#[ser_test(arbitrary)]
#[tagged_blob("ICON")]
#[derive(Clone, Debug, PartialEq)]
pub struct Icon(ImageBuffer<IconPixel, Vec<u8>>);

impl CanonicalSerialize for Icon {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        // The serialization format we will use is very simple: write the width as a u32, the height
        // as a u32, and then the raw data.
        writer
            .write_all(&self.width().to_le_bytes())
            .map_err(SerializationError::IoError)?;
        writer
            .write_all(&self.height().to_le_bytes())
            .map_err(SerializationError::IoError)?;
        writer
            .write_all(self.0.as_raw())
            .map_err(SerializationError::IoError)
    }

    fn serialized_size(&self) -> usize {
        // 8 bytes for the width and height (4 bytes each) plus 1 byte for each pixel channel in the
        // data.
        assert_eq!(self.width().to_le_bytes().len(), 4);
        assert_eq!(self.height().to_le_bytes().len(), 4);
        8 + (IconPixel::CHANNEL_COUNT as usize) * self.0.as_raw().len()
    }
}

impl CanonicalDeserialize for Icon {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        // Read the width and height so we can figure out how much raw data there is.
        let mut width_buf = [0; 4];
        let mut height_buf = [0; 4];
        reader
            .read_exact(&mut width_buf)
            .map_err(SerializationError::IoError)?;
        reader
            .read_exact(&mut height_buf)
            .map_err(SerializationError::IoError)?;
        // The raw buffer has size c*width*height, where c is the channel count of the pixel type.
        let width = u32::from_le_bytes(width_buf);
        let height = u32::from_le_bytes(height_buf);
        let mut image_buf =
            vec![0; (width as usize) * (height as usize) * (IconPixel::CHANNEL_COUNT as usize)];
        reader
            .read_exact(&mut image_buf)
            .map_err(SerializationError::IoError)?;
        Ok(Self(
            ImageBuffer::from_raw(width, height, image_buf).unwrap(),
        ))
    }
}

impl<'a> Arbitrary<'a> for Icon {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Each row in the image is an array of pixels, which are each CHANNEL_COUNT u8's.
        let width = u.arbitrary_len::<[u8; IconPixel::CHANNEL_COUNT as usize]>()?;
        // The height corresponds to the length of an array of rows; that is, a container whose
        // elements are arrays (`Vec`) of pixels (`[u8; CHANNEL_COUNT]`), hence
        // `Vec<[u8; CHANNEL_COUNT]>`.
        let height = u.arbitrary_len::<Vec<[u8; IconPixel::CHANNEL_COUNT as usize]>>()?;
        let mut buf = vec![0; width * height * (IconPixel::CHANNEL_COUNT as usize)];
        u.fill_buffer(&mut buf)?;
        Ok(Self(
            ImageBuffer::from_raw(width as u32, height as u32, buf).unwrap(),
        ))
    }
}

impl Icon {
    /// Resize the icon.
    ///
    /// A cubic filter is used to interpolate pixels in the resized image.
    pub fn resize(&mut self, width: u32, height: u32) {
        // CatmullRom is a cubic filter which offers a good balance of performance and quality.
        self.0 = imageops::resize(&self.0, width, height, imageops::FilterType::CatmullRom);
    }

    /// Get the size `(width, height)` of the image.
    pub fn size(&self) -> (u32, u32) {
        (self.width(), self.height())
    }

    /// The icon width in pixels
    pub fn width(&self) -> u32 {
        self.0.width()
    }

    /// The icon height in pixels.
    pub fn height(&self) -> u32 {
        self.0.height()
    }

    /// Load from a byte stream.
    pub fn load(r: impl BufRead + Seek, format: ImageFormat) -> ImageResult<Self> {
        Ok(Self(image::load(r, format)?.into_rgba8()))
    }

    /// Load from a PNG byte stream.
    pub fn load_png(r: impl BufRead + Seek) -> ImageResult<Self> {
        Self::load(r, ImageFormat::Png)
    }

    /// Load from a JPEG byte stream.
    pub fn load_jpeg(r: impl BufRead + Seek) -> ImageResult<Self> {
        Self::load(r, ImageFormat::Jpeg)
    }

    /// Write to a byte stream.
    pub fn write(&self, mut w: impl Write + Seek, format: ImageFormat) -> ImageResult<()> {
        self.0.write_to(&mut w, format)
    }

    /// Write to a byte stream using the PNG format.
    pub fn write_png(&self, w: impl Write + Seek) -> ImageResult<()> {
        self.write(w, ImageFormat::Png)
    }

    /// Write to a byte stream using the JPEG format.
    pub fn write_jpeg(&self, w: impl Write + Seek) -> ImageResult<()> {
        self.write(w, ImageFormat::Jpeg)
    }
}

impl From<ImageBuffer<IconPixel, Vec<u8>>> for Icon {
    fn from(image: ImageBuffer<IconPixel, Vec<u8>>) -> Self {
        Self(image)
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
/// 4. The application, upon creating a [Keystore](crate::Keystore), deserializes the
///    [VerifiedAssetLibrary] and calls [Keystore::verify_assets](crate::Keystore::verify_assets) with
///    the public key from step 1. This key can be hard-coded in the client application.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedAssetLibrary {
    // The public key which was used to sign this library (for inspection purposes).
    signer: VerKey,
    signature: Signature,
    assets: Vec<Asset>,
}

impl VerifiedAssetLibrary {
    /// Create and sign a new verified asset library.
    pub fn new(assets: Vec<Asset>, signer: &KeyPair) -> Self {
        Self {
            signer: signer.ver_key(),
            signature: signer.sign(
                &[Self::digest(&assets)],
                SchnorrSignatureScheme::<CurveParam>::CS_ID,
            ),
            assets: assets
                .into_iter()
                .map(|asset| asset.export_verified())
                .collect(),
        }
    }

    /// Obtain a list of the assets in `self`, but only if `self` is signed by `trusted_signer`.
    pub fn open(self, trusted_signer: &VerKey) -> Option<Vec<Asset>> {
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
            .verify(
                &[Self::digest(&self.assets)],
                &self.signature,
                SchnorrSignatureScheme::<CurveParam>::CS_ID,
            )
            .is_ok()
        {
            Some(self.signer.clone())
        } else {
            None
        }
    }

    fn digest(assets: &[Asset]) -> BaseField {
        let bytes = assets
            .iter()
            .flat_map(|asset| bincode::serialize(asset).unwrap())
            .collect::<Vec<_>>();
        jf_utils::hash_to_field(bytes)
    }
}

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
    #[cfg(any(test, feature = "testing"))]
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

#[cfg(any(test, feature = "testing"))]
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
                // Resize the icon to the default value.
                icon.resize(ICON_WIDTH, ICON_HEIGHT);
                Some(icon)
            }
            None => None,
        };
        self
    }

    /// Set the asset icon.
    pub fn with_icon(mut self, mut icon: Icon) -> Self {
        // Resize the icon to the default value.
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
        if other.definition != self.asset.definition {
            return Err(KeystoreError::InconsistentAsset {
                expected: self.asset.definition,
            });
        }
        if other.verified || !self.asset.verified {
            if let Some(name) = other.name.clone() {
                self.asset.name = Some(name);
            }
            if let Some(description) = other.description.clone() {
                self.asset.description = Some(description);
            }
            if let Some(icon) = other.icon.clone() {
                self.asset.icon = Some(icon);
            }
        }
        if let Some(mint_info) = other.mint_info.clone() {
            self.asset.mint_info = Some(mint_info);
        }
        self.asset.verified |= other.verified;
        Ok(self)
    }

    /// Updates the asset by merging in the given asset with the same definition.
    /// * Updates the asset name, description or icon if
    ///   * the given asset is verified, and
    ///   * the given asset has the corresponding field.
    /// * Updates the mint information, if present in the given asset.
    /// * Sets as verified if either asset if verified.
    pub(crate) fn update_internal<L: Ledger>(
        mut self,
        other: Asset,
    ) -> Result<Self, KeystoreError<L>> {
        if other.definition != self.asset.definition {
            return Err(KeystoreError::InconsistentAsset {
                expected: self.asset.definition,
            });
        }
        if other.verified {
            if let Some(name) = other.name.clone() {
                self.asset.name = Some(name);
            }
            if let Some(description) = other.description.clone() {
                self.asset.description = Some(description);
            }
            if let Some(icon) = other.icon.clone() {
                self.asset.icon = Some(icon);
            }
        }
        if let Some(mint_info) = other.mint_info.clone() {
            self.asset.mint_info = Some(mint_info);
        }
        self.asset.verified |= other.verified;
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
    verified_assets: PersistableHashSet<AssetCode>,
}

impl Assets {
    #![allow(dead_code)]

    /// Load an assets store.
    ///
    /// None of the loaded assets will be verified until `verify_assets` is called.
    pub fn new<L: Ledger>(store: AssetsStore) -> Result<Self, KeystoreError<L>> {
        Ok(Self {
            store,
            verified_assets: Persistable::new(),
        })
    }

    /// Iterate through the assets.
    pub fn iter(&self) -> impl Iterator<Item = Asset> + '_ {
        let mut assets = Vec::new();
        for mut asset in self.store.iter().cloned() {
            // The asset is verified if it's in the verified set.
            if self.verified_assets.index().contains(&asset.code()) {
                asset.verified = true;
            }
            assets.push(asset.clone());
        }
        assets.into_iter()
    }

    /// Get the asset by the code from the store.
    pub fn get<L: Ledger>(&self, code: &AssetCode) -> Result<Asset, KeystoreError<L>> {
        let mut asset = self.store.load(code)?;
        // The asset is verified if it's in the verified set.
        if self.verified_assets.index().contains(code) {
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
        if self.verified_assets.index().contains(code) {
            asset.verified = true
        }
        Ok(AssetEditor::new(&mut self.store, asset))
    }

    /// Commit the store version.
    pub fn commit<L: Ledger>(&mut self) -> Result<(), KeystoreError<L>> {
        self.verified_assets.commit();
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert<L: Ledger>(&mut self) -> Result<(), KeystoreError<L>> {
        self.verified_assets.revert();
        Ok(self.store.revert_version()?)
    }

    /// Insert an asset.
    ///
    /// If the store doesn't have an asset with the same code, adds the inserted asset to the store.
    /// Otherwise, updates the exisiting asset.
    ///
    /// Returns the editor for the inserted asset.
    pub fn insert<L: Ledger>(
        &mut self,
        mut asset: Asset,
    ) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        // The asset is verified if it's in the verified set.
        if self
            .verified_assets
            .index()
            .contains(&asset.definition.code)
        {
            asset.verified = true
        }
        let store_asset = self.store.load(&asset.definition.code);
        let mut editor = if let Ok(store_asset) = store_asset {
            AssetEditor::new(&mut self.store, store_asset).update(asset.clone())?
        } else {
            AssetEditor::new(&mut self.store, asset.clone())
        };
        // Make sure the icon has the default size.
        editor = editor.set_icon(asset.icon());
        editor.save::<L>()?;
        Ok(editor)
    }

    /// Create an asset.
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
        let asset = Asset {
            definition,
            name: None,
            description: None,
            icon: None,
            mint_info,
            verified: false,
        };
        self.insert(asset)
    }

    /// Create a native asset.
    ///
    /// Returns the editor for the created asset.
    pub fn create_native<L: Ledger>(&mut self) -> Result<AssetEditor<'_>, KeystoreError<L>> {
        let asset = Asset::native::<L>();
        self.insert(asset)
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
        self.insert(asset)
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
                self.insert(asset.clone())?;
                definitions.push(asset.definition.clone());
            }
            Ok(definitions)
        } else {
            Err(KeystoreError::AssetVerificationError)
        }
    }

    /// Deletes an asset from the store.
    ///
    /// Returns the deleted asset.
    pub fn delete<L: Ledger>(&mut self, code: &AssetCode) -> Result<Asset, KeystoreError<L>> {
        Ok(self.store.delete(code)?)
    }
}
