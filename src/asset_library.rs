// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Collections of and information on CAP assets.
//!
//! This module defines [AssetInfo] and [MintInfo], which store auxiliary information about assets
//! which is useful to keystores but not present in [AssetDefinition]. For example, [AssetInfo] may
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
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use espresso_macros::ser_test;
use image::{imageops, ImageBuffer, ImageFormat, ImageResult, Pixel, Rgba};
use jf_cap::{
    keys::ViewerPubKey,
    structs::{AssetCode, AssetCodeSeed, AssetDefinition},
    BaseField, CurveParam, KeyPair, Signature, VerKey,
};
use jf_primitives::signatures::{schnorr::SchnorrSignatureScheme, SignatureScheme};
use jf_utils::tagged_blob;
use reef::Ledger;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::io::{BufRead, Seek};
use std::iter::FromIterator;
use std::ops::Index;
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

/// Details about an asset type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetInfo {
    /// CAP asset definition.
    pub definition: AssetDefinition,
    /// UI-friendly name assigned to this asset.
    ///
    /// The name is purely for display purposes. It is not bound to anything in the CAP protocol,
    /// and will not be populated when a keystore discovers an asset, only when a user manually
    /// imports or creates that asset with a particular name. Two keystores will only agree on the
    /// name for an asset if both keystores have imported that asset with the same name.
    pub name: Option<String>,
    /// UI-friendly description assigned to this asset.
    ///
    /// This is intended to be a field containing a bit more information than `name`, but really it
    /// can be used however the client wants.
    ///
    /// The description is purely for display purposes. It is not bound to anything in the CAP
    /// protocol, and will not be populated when a keystore discovers an asset, only when a user
    /// manually imports or creates that asset with a particular description. Two keystores will only
    /// agree on the description for an asset if both keystores have imported that asset with the same
    /// description.
    pub description: Option<String>,
    /// Icon used when displaying this asset in a GUI.
    ///
    /// The icon is purely for display purposes. It is not bound to anything in the CAP protocol,
    /// and will not be populated when a keystore discovers an asset, only when a user manually
    /// imports or creates that asset with a particular icon. Two keystores will only agree on the
    /// icon for an asset if both keystores have imported that asset with the same icon.
    pub icon: Option<Icon>,
    /// Secret information required to mint an asset.
    pub mint_info: Option<MintInfo>,
    /// This asset is included in a [VerifiedAssetLibrary].
    pub verified: bool,
    /// This asset is not included in the persistent asset library.
    ///
    /// It will need to be reloaded when the keystore is restarted.
    pub temporary: bool,
}

impl AssetInfo {
    pub fn new(definition: AssetDefinition, mint_info: MintInfo) -> Self {
        Self {
            definition,
            name: None,
            description: None,
            icon: None,
            mint_info: Some(mint_info),
            verified: false,
            temporary: false,
        }
    }

    fn verified(mut self) -> Self {
        // Verified assets are meant to be distributed. We should never distribute mint info.
        self.mint_info = None;
        self.verified = true;
        // Assets loaded from verified libraries are not included in our persistent state. Instead,
        // they should be loaded from the verified library each time the keystore is launched, in case
        // the verified library changes.
        //
        // Note that if the same asset is imported manually, it will be persisted due to the
        // semantics of [AssetInfo::update] with respect to `temporary`, but upon being loaded it
        // will be marked unverified until the verified library containing it is reloaded.
        self.temporary = true;
        self
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with_icon(mut self, image: impl Into<Icon>) -> Self {
        let mut icon = image.into();
        icon.resize(ICON_WIDTH, ICON_HEIGHT);
        self.icon = Some(icon);
        self
    }

    /// Details about the native asset type.
    pub fn native<L: Ledger>() -> Self {
        Self::from(AssetDefinition::native())
            .with_name(L::name().to_uppercase())
            .with_description(format!("The {} native asset type", L::name()))
    }

    /// Update this info by merging in information from `info`.
    ///
    /// Both `self` and `info` must refer to the same CAP asset; that is, `self.definition` must
    /// equal `info.definition`.
    ///
    /// * `self.definition` is replaced with `info.definition`
    /// * `self.name` and `self.description` are updated with `info.name` and `info.description`, if
    ///   present, _unless_ `self` is verified and `info` is not.
    /// * If `info.mint_info` exists, it replaces `self.mint_info`
    /// * `self.temporary` is `true` only if both `self` and `info` are temporary
    /// * `self.verified` is `true` if either `self` or `info` is verified
    pub fn update(&mut self, info: AssetInfo) {
        assert_eq!(self.definition, info.definition);
        if let Some(mint_info) = info.mint_info {
            self.mint_info = Some(mint_info);
        }
        if info.verified || !self.verified {
            // Update UI metadata as long as `info` is at least as verified as `self`.
            if let Some(name) = info.name {
                self.name = Some(name);
            }
            if let Some(description) = info.description {
                self.description = Some(description);
            }
            if let Some(icon) = info.icon {
                self.icon = Some(icon);
            }
        }
        self.temporary &= info.temporary;
        self.verified |= info.verified;
    }
}

impl From<AssetDefinition> for AssetInfo {
    fn from(definition: AssetDefinition) -> Self {
        Self {
            definition,
            name: None,
            description: None,
            icon: None,
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
        // Recognized fields are "description", "name", "definition", "mint_description", "seed",
        // and "temporary". Note that the `verified` field cannot be set this way. There is only one
        // way to create verified `AssetInfo`: using [Keystore::verify_assets], which performs a
        // signature check before marking assets verified.
        let mut definition = None;
        let mut name = None;
        let mut description = None;
        let mut mint_description = None;
        let mut seed = None;
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
        let mint_info = match (seed, mint_description) {
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
            name,
            description,
            icon: None,
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
    pub assets: Vec<AssetInfo>,
    // Map from AssetCode to index in `assets`.
    index: HashMap<AssetCode, usize>,
    // Map from viewable AssetCode to its definition.
    viewable: HashMap<AssetCode, AssetDefinition>,
    // Viewing keys, so we can tell when an asset is supposed to be in `viewable`.
    viewing_keys: HashSet<ViewerPubKey>,
}

impl AssetLibrary {
    /// Create an [AssetLibrary] with the given assets and viewing keys.
    pub fn new(assets: Vec<AssetInfo>, viewing_keys: HashSet<ViewerPubKey>) -> Self {
        // Create the library empty so that we can use `insert` to add the assets, which will ensure
        // that all of the data structures (assets, index, and viewable) are populated consistently.
        let mut lib = Self {
            assets: Default::default(),
            index: Default::default(),
            viewable: Default::default(),
            viewing_keys,
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
                .viewing_keys
                .contains(asset.definition.policy_ref().viewer_pub_key())
            {
                self.viewable
                    .insert(asset.definition.code, asset.definition.clone());
            }
            self.assets.push(asset);
        }
    }

    /// Add a viewing key.
    ///
    /// Any assets which were already in the library and can be viewed using this key will be marked
    /// as viewable.
    pub fn add_viewing_key(&mut self, key: ViewerPubKey) {
        // Upon discovering a new viewing key, we need to check if any existing assets have now become
        // viewable.
        for asset in &self.assets {
            if asset.definition.policy_ref().viewer_pub_key() == &key {
                self.viewable
                    .insert(asset.definition.code, asset.definition.clone());
            }
        }
        self.viewing_keys.insert(key);
    }

    /// List viewable assets.
    pub fn viewable(&self) -> &HashMap<AssetCode, AssetDefinition> {
        &self.viewable
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
/// 4. The application, upon creating a [Keystore](crate::Keystore), deserializes the
///    [VerifiedAssetLibrary] and calls [Keystore::verify_assets](crate::Keystore::verify_assets) with
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
    pub fn new(assets: impl IntoIterator<Item = AssetInfo>, signer: &KeyPair) -> Self {
        let assets = assets
            .into_iter()
            .map(|asset| asset.verified())
            .collect::<Vec<_>>();
        Self {
            signer: signer.ver_key(),
            signature: signer.sign(
                &[Self::digest(&assets)],
                SchnorrSignatureScheme::<CurveParam>::CS_ID,
            ),
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

    fn digest(assets: &[AssetInfo]) -> BaseField {
        let bytes = assets
            .iter()
            .flat_map(|asset| bincode::serialize(asset).unwrap())
            .collect::<Vec<_>>();
        jf_utils::hash_to_field(bytes)
    }
}
