// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Collections of and information on CAP assets.
//!
//! This module defines [MintInfo], which contains the secret information needed by the asset
//! creator to mint more of that asset type.
//!
//! This module also defines an interface for verified asset types, [VerifiedAssetLibrary]. This is
//! a collection of assets which can be signed by a trusted party, such as an application developer,
//! and distributed to client applications. Applications with verified status can thus be displayed
//! as such, for example by including a badge in a GUI application. Note that this library merely
//! provides the mechanisms and interfaces for creating and consuming verified asset libraries. It
//! does not define any specific libraries or verification keys, as these are application-specific
//! and thus should be defined in clients of this crate.
use crate::assets::Asset;
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use espresso_macros::ser_test;
use image::{imageops, ImageBuffer, ImageFormat, ImageResult, Pixel, Rgba};
use jf_cap::{structs::AssetCodeSeed, BaseField, CurveParam, KeyPair, Signature, VerKey};
use jf_primitives::signatures::{schnorr::SchnorrSignatureScheme, SignatureScheme};
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Seek};
use tagged_base64::TaggedBase64;

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
