// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Traits and types for creating and loading keystores.
//!
//! This module defines the [KeystoreLoader] interface, which allows various implementations as
//! plugins to the persistence layer. It also provides a ew generally useful implementations based
//! on the [MnemonicPasswordLogin] mechanism:
//!
//! * [InteractiveLoader]
//! * [CreateLoader]
//! * [LoginLoader]
//! * [RecoveryLoader]

use crate::{
    encryption::{Cipher, CipherText},
    hd::{KeyTree, Mnemonic, Salt},
    EncryptionSnafu, KeySnafu, KeystoreError, Ledger,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::path::PathBuf;

pub mod create;
pub mod interactive;
pub mod login;
pub mod recovery;

#[cfg(test)]
mod tests;

pub use create::CreateLoader;
pub use interactive::InteractiveLoader;
pub use login::LoginLoader;
pub use recovery::RecoveryLoader;

pub trait KeystoreLoader<L: Ledger> {
    /// Metadata about a keystore which is always stored unencrypted.
    ///
    /// This allows loaders and tools to report some basic information about the keystore and handle
    /// login attempts without decrypting.
    ///
    /// DO NOT put secrets in here.
    type Meta;

    /// The location of the keystore targetted by this loader.
    ///
    /// This tells users of the loader, like
    /// [AtomicKeystoreStorage](crate::persistence::AtomicKeystoreStorage), where to load existing
    /// metadata from when calling [load](Self::load).
    fn location(&self) -> PathBuf;

    /// Create a new keystore.
    ///
    /// The caller must ensure that no keystore currently exists at `self.location()`. The loader
    /// will create the metadata for a new keystore and return it, along with the key tree to use
    /// when deriving keys for the new keystore. The caller should persist the new metadata in
    /// `self.location()`.
    fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<L>>;

    /// Load an existing keystore.
    ///
    /// The caller must have loaded `meta` from `self.location()`. The loader will use `meta` to
    /// authenticate the keystore and derive the key tree, which is used to decrypt the rest of the
    /// keystore files and derive new keys.
    ///
    /// The loader may change `meta`. For instance, some loaders allow the owner of a keystore to
    /// log in using a mnemonic phrase and reset the password. In this case, `meta` would be updated
    /// with a new password. If the value of `meta` after this call succeeds is not equal to its
    /// value before the call, the caller is responsible for persisting the new value in
    /// `self.location()`.
    ///
    /// If [load](Self::load) fails, it will not change `meta`.
    fn load(&mut self, meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<L>>;
}

/// Metadata that supports login with a password and backup/recovery with a mnemonic.
///
/// Like all Seahorse keystores, a keystore using [MnemonicPasswordLogin] is ultimately derived from
/// a mnemonic phrase. This phrase can be used later on to recover the keystore if the owner loses
/// access to the encrypted keystore files or forgets their password. In addition, keystores that
/// use [MnemonicPasswordLogin] have a password which can be used to decrypt the keystore files
/// without having to type in the entire unwieldy mnemonic phrase.
///
/// The contents of the [MnemonicPasswordLogin] metadata are:
/// * a version header
/// * a 32-byte salt, which is randomly generated when the keystore is created
/// * the keystore's mnemonic phrase, securely encrypted
/// * random bytes (sampled when the keystore is created) encrypted and authenticated using a key
///   derived from the mnemonic
///
/// This data is used throughout the keystore lifecycle as follows.
///
/// ## Creation
///
/// When a new keystore is created, a mnemonic phrase is sampled randomly and the owner provides a
/// password. The loader then samples 32 bytes of salt which, combined with the password, derives an
/// encryption key that is used to encrypt the mnemonic. Storing the mnemonic, encrypted under the
/// password, is how we facilitate convenient login, as we will soon see.
///
/// We also store 32 random bytes, encrypted and authenticated using a key derived from the mnemonic
/// phrase. This allows applications to check whether a mnemonic phrase is the correct one for this
/// keystore without having access to the password to decrypt the mnemonic: if the random bytes
/// successfully decrypt using the key derived from the potential mnemonic, then it is the correct
/// one. This is especially useful when attempting to recover a keystore from a mnemonic.
///
/// ## Login
///
/// To log in to a keystore, the owner must provide the password. They need not provide the
/// mnemonic. The loader uses the password and the salt stored in the metadata to derive a
/// decryption key, and then decrypts the mnemonic phrase, which was stored encrypted in the
/// metadata. Keys derived from the mnemonic phrase can then be used to decrypt the rest of the
/// keystore files and access the owner's assets.
///
/// ## Recovery
///
/// There are two cases of recovery: recovering access to encrypted keystore files after forgetting
/// the password, or recovering a keystore whose files have been lost. [MnemonicPasswordLogin]
/// supports both cases. Recovery is slower without the keystore files, but no less effective.
///
/// When the keystore files are available, the owner's mnemonic phrase can be used to derive the
/// keys necessary to decrypt them. In this case, the random bytes encrypted using the mnemonic
/// phrase and stored in the metadata are used to quickly report an error if the user provides an
/// incorrect mnemonic phrase. If decryption is successful, the user may provide a new password, and
/// the loader will sample a new random salt and re-encrypt the mnemonic phrase using the new
/// password and salt. At this point, the user is able to log into their keystore through the normal
/// login flow, using only the new password.
///
/// When the keystore files are not available, recovery is exactly the same as creating a new wallet
/// using the owner's original mnemonic phrase and a new password. It is then incumbent upon the
/// owner of the wallet to regenerate their keys. If they used the correct mnemonic, the new keys
/// will be the same keys that were generated in the original wallet, and they will be able to
/// recover access to their on-chain assets. Note, however, that off-chain metadata that was stored
/// in the lost keystore files cannot be recovered this way. Also note that since the original
/// metadata is not available in this case, there is no way to report an error if the user enters
/// the wrong mnemonic. If they do, they will simply be unable to recover their on-chain assets.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MnemonicPasswordLogin {
    version: (u8, u8, u8),
    salt: Salt,
    // Encrypted mnemonic phrase. This will only decrypt successfully if we have the correct
    // password, so we can use it as a quick check that the user entered the right thing.
    encrypted_mnemonic: CipherText,
    // Encrypted random bytes using a key generated from the mnemonic phrase. This will only decrypt
    // suffessfully if we have the correct mnemonic, so it can be used to check the user's input
    // when recovering from a mnemonic.
    encrypted_bytes: CipherText,
}

impl MnemonicPasswordLogin {
    const KEY_CHECK_SUB_TREE: &'static str = "key_check";

    /// Create new login metadata with a given mnemonic phrase and password.
    pub fn new<L: Ledger>(
        rng: &mut ChaChaRng,
        mnemonic: &Mnemonic,
        password: &[u8],
    ) -> Result<Self, KeystoreError<L>> {
        let (encrypted_mnemonic, salt) = Self::encrypt_mnemonic(rng, mnemonic, password)?;

        // Generate and encrypt some random bytes using the mnemonic, so in the future we can check
        // if the mnemonic is correct.
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let encrypted_bytes = Cipher::new(
            KeyTree::from_mnemonic(mnemonic).derive_sub_tree(Self::KEY_CHECK_SUB_TREE.as_bytes()),
            Some(ChaChaRng::from_rng(rng).unwrap()),
        )
        .encrypt(&bytes)
        .context(EncryptionSnafu)?;

        Ok(Self {
            version: (
                env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
            ),
            salt,
            encrypted_mnemonic,
            encrypted_bytes,
        })
    }

    /// Check if a password matches the one associated with this metadata.
    pub fn check_password(&self, password: &[u8]) -> bool {
        self.decrypt_mnemonic(password).is_some()
    }

    /// Check if a password phrase matches the one associated with this metadata.
    pub fn check_mnemonic(&self, mnemonic: &Mnemonic) -> bool {
        // Check if the mnemonic is correct by attempting to decrypt the random bytes.
        Cipher::decrypter(
            KeyTree::from_mnemonic(mnemonic).derive_sub_tree(Self::KEY_CHECK_SUB_TREE.as_bytes()),
        )
        .decrypt(&self.encrypted_bytes)
        .is_ok()
    }

    /// Decrypt the mnemonic phrase associated with this metadata.
    ///
    /// Returns `Some` mnemonic phrase if `password` is the correct one. Otherwise returns `None`.
    pub fn decrypt_mnemonic(&self, password: &[u8]) -> Option<Mnemonic> {
        // Generate the decryption key and check that we can use it to decrypt `encrypted_mnemonic`.
        // If we can't, the key is wrong.
        let decryption_key = KeyTree::from_password_and_salt(password, &self.salt).ok()?;
        if let Ok(mnemonic_bytes) =
            Cipher::decrypter(decryption_key.derive_sub_tree(Self::KEY_CHECK_SUB_TREE.as_bytes()))
                .decrypt(&self.encrypted_mnemonic)
        {
            // If the data decrypts successfully, then `mnemonic_bytes` is authenticated, so we can
            // safely unwrap when deserializing it.
            Some(Mnemonic::from_phrase(std::str::from_utf8(&mnemonic_bytes).unwrap()).unwrap())
        } else {
            None
        }
    }

    /// Change the password associated with this metadata.
    ///
    /// After this function succeeds, the new password may be used to log into the keystore with
    /// this metadata, and the old password may no longer be used.
    ///
    /// If `mnemonic` is not the mnemonic phrase associated with this metadata, this function fails,
    /// and the metadata is unchanged.
    pub fn set_password<L: Ledger>(
        &mut self,
        rng: &mut ChaChaRng,
        mnemonic: &Mnemonic,
        new_password: &[u8],
    ) -> Result<(), KeystoreError<L>> {
        if !self.check_mnemonic(mnemonic) {
            return Err(KeystoreError::Failed {
                msg: String::from("incorrect mnemonic"),
            });
        }

        // Encrypt the mnemonic phrase, which we can decrypt on load to check the derived key.
        let (encrypted_mnemonic, salt) = Self::encrypt_mnemonic(rng, mnemonic, new_password)?;
        self.encrypted_mnemonic = encrypted_mnemonic;
        self.salt = salt;

        Ok(())
    }

    fn encrypt_mnemonic<L: Ledger>(
        rng: &mut ChaChaRng,
        mnemonic: &Mnemonic,
        password: &[u8],
    ) -> Result<(CipherText, Salt), KeystoreError<L>> {
        // Encrypt the mnemonic phrase, which we can decrypt on load to check the derived key.
        let (encryption_key, salt) = KeyTree::from_password(rng, password).context(KeySnafu)?;
        let encrypted_mnemonic = Cipher::new(
            encryption_key.derive_sub_tree(Self::KEY_CHECK_SUB_TREE.as_bytes()),
            Some(ChaChaRng::from_rng(rng).unwrap()),
        )
        .encrypt(mnemonic.phrase().as_bytes())
        .context(EncryptionSnafu)?;

        Ok((encrypted_mnemonic, salt))
    }
}
