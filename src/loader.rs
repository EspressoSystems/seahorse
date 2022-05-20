// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Traits and types for creating and loading keystores.
//!
//! This module defines the [KeystoreLoader] interface, which allows various implementations as
//! plugins to the persistence layer. It also provides a generally useful implementation [Loader],
//! which loads an encrypted keystore from the file system using a mnemonic phrase to generate keys
//! and a password to provide a more convenient login interface.
use super::{encryption, hd, reader, EncryptionSnafu, KeySnafu, KeystoreError, MnemonicSnafu};
use encryption::{Cipher, CipherText, Salt};
use hd::{KeyTree, Mnemonic};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use reader::Reader;
use reef::Ledger;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::path::{Path, PathBuf};

pub trait KeystoreLoader<L: Ledger> {
    type Meta; // Metadata stored in plaintext and used by the loader to access the keystore.
    fn location(&self) -> PathBuf;
    fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<L>>;
    fn load(&mut self, meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<L>>;
}

// Metadata about a keystore which is always stored unencrypted, so we can report some basic
// information about the keystore without decrypting. This also aids in the key derivation process.
//
// DO NOT put secrets in here.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoaderMetadata {
    version: (u8, u8, u8),
    salt: Salt,
    // Encrypted mnemonic phrase. This will only decrypt successfully if we have the correct
    // password, so we can use it as a quick check that the user entered the right thing.
    encrypted_mnemonic: CipherText,
    // Encrypted random bytes using a key generated from the mnemonic phrase. This will only decrypt
    // suffessfully if we have the correct mnemonic, so it can be used to check the user's input
    // when recoverying from a mnemonic.
    encrypted_bytes: CipherText,
}

enum LoaderInput {
    User(Reader),
    PasswordLiteral(String),
    RecoveryLiteral(String, String),
    MnemonicPasswordLiteral(String, String),
}

impl LoaderInput {
    fn create_password<L: Ledger>(&mut self) -> Result<String, KeystoreError<L>> {
        match self {
            Self::User(reader) => loop {
                let password = reader.read_password("Create password: ")?;
                let confirm = reader.read_password("Retype password: ")?;
                if password == confirm {
                    return Ok(password);
                } else {
                    println!("Passwords do not match.");
                }
            },

            Self::PasswordLiteral(password)
            | Self::MnemonicPasswordLiteral(_, password)
            | Self::RecoveryLiteral(_, password) => Ok(password.to_string()),
        }
    }

    fn read_password<L: Ledger>(&mut self) -> Result<Option<String>, KeystoreError<L>> {
        match self {
            Self::User(reader) => loop {
                println!("Forgot your password? Want to change it? [y/n]");
                match reader.read_line() {
                    Some(line) => match line.as_str().trim() {
                        "n" => break Ok(Some(reader.read_password("Enter password: ")?)),
                        "y" => break Ok(None),
                        _ => println!("Please enter 'y' or 'n'."),
                    },
                    None => {
                        return Err(KeystoreError::Failed {
                            msg: String::from("eof"),
                        })
                    }
                }
            },
            Self::PasswordLiteral(password) => Ok(Some(password.to_string())),
            Self::MnemonicPasswordLiteral(_, password) => Ok(Some(password.to_string())),
            Self::RecoveryLiteral(_, _) => Ok(None),
        }
    }

    fn create_mnemonic<L: Ledger>(
        &mut self,
        rng: &mut ChaChaRng,
    ) -> Result<Mnemonic, KeystoreError<L>> {
        match self {
            Self::User(reader) => {
                println!(
                    "Your keystore will be identified by a secret mnemonic phrase. This phrase will \
                     allow you to recover your keystore if you lose access to it. Anyone who has access \
                     to this phrase will be able to view and spend your assets. Store this phrase in a \
                     safe, private place."
                );
                'outer: loop {
                    let (_, mnemonic) = KeyTree::random(rng);
                    println!("Your mnemonic phrase will be:");
                    println!("{}", mnemonic);
                    'inner: loop {
                        println!("1) Accept phrase and create keystore");
                        println!("2) Generate a new phrase");
                        println!(
                            "3) Manually enter a mnemonic (use this to recover a lost keystore)"
                        );
                        match reader.read_line() {
                            Some(line) => match line.as_str().trim() {
                                "1" => return Ok(mnemonic),
                                "2" => continue 'outer,
                                "3" => return Self::read_mnemonic_interactive(reader),
                                _ => continue 'inner,
                            },
                            None => {
                                return Err(KeystoreError::Failed {
                                    msg: String::from("eof"),
                                })
                            }
                        }
                    }
                }
            }

            Self::PasswordLiteral(_) => Err(KeystoreError::Failed {
                msg: String::from("missing mnemonic phrase"),
            }),

            Self::MnemonicPasswordLiteral(mnemonic, _) | Self::RecoveryLiteral(mnemonic, _) => {
                Mnemonic::from_phrase(mnemonic.as_str()).context(MnemonicSnafu)
            }
        }
    }

    fn read_mnemonic<L: Ledger>(&mut self) -> Result<Mnemonic, KeystoreError<L>> {
        match self {
            Self::User(reader) => Self::read_mnemonic_interactive(reader),
            Self::PasswordLiteral(_) => Err(KeystoreError::Failed {
                msg: String::from("missing mnemonic phrase"),
            }),
            Self::MnemonicPasswordLiteral(mnemonic, _) | Self::RecoveryLiteral(mnemonic, _) => {
                Mnemonic::from_phrase(mnemonic.as_str()).context(MnemonicSnafu)
            }
        }
    }

    fn interactive(&self) -> bool {
        matches!(self, Self::User(..))
    }

    fn read_mnemonic_interactive<L: Ledger>(
        reader: &mut Reader,
    ) -> Result<Mnemonic, KeystoreError<L>> {
        loop {
            let phrase = reader.read_password("Enter mnemonic phrase: ")?;
            match Mnemonic::from_phrase(&phrase) {
                Ok(mnemonic) => return Ok(mnemonic),
                Err(err) => {
                    println!("That's not a valid mnemonic phrase ({})", err);
                }
            }
        }
    }
}

pub struct Loader {
    dir: PathBuf,
    pub rng: ChaChaRng,
    input: LoaderInput,
}

impl Loader {
    pub fn new(dir: PathBuf, reader: Reader) -> Self {
        Self {
            dir,
            input: LoaderInput::User(reader),
            rng: ChaChaRng::from_entropy(),
        }
    }

    pub fn from_literal(mnemonic: Option<String>, password: String, dir: PathBuf) -> Self {
        match mnemonic {
            Some(m) => Self {
                dir,
                input: LoaderInput::MnemonicPasswordLiteral(m, password),
                rng: ChaChaRng::from_entropy(),
            },
            None => Self {
                dir,
                input: LoaderInput::PasswordLiteral(password),
                rng: ChaChaRng::from_entropy(),
            },
        }
    }

    pub fn recovery(mnemonic: String, new_password: String, dir: PathBuf) -> Self {
        Self {
            dir,
            input: LoaderInput::RecoveryLiteral(mnemonic, new_password),
            rng: ChaChaRng::from_entropy(),
        }
    }

    pub fn into_reader(self) -> Option<Reader> {
        match self.input {
            LoaderInput::User(reader) => Some(reader),
            _ => None,
        }
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    fn create_from_mnemonic<L: Ledger>(&mut self) -> Result<(Mnemonic, KeyTree), KeystoreError<L>> {
        let mnemonic = self.input.create_mnemonic(&mut self.rng)?;
        let key = KeyTree::from_mnemonic(&mnemonic);
        Ok((mnemonic, key))
    }

    // Create a password, returning salt and encrypted mnemonic.
    fn create_password<L: Ledger>(
        &mut self,
        mnemonic: Mnemonic,
    ) -> Result<(Salt, CipherText), KeystoreError<L>> {
        let password = self.input.create_password()?;

        // Encrypt the mnemonic phrase, which we can decrypt on load to check the derived key.
        let (encryption_key, salt) =
            KeyTree::from_password(&mut self.rng, password.as_bytes()).context(KeySnafu)?;
        let encrypted_mnemonic = Cipher::new(
            encryption_key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
            ChaChaRng::from_rng(&mut self.rng).unwrap(),
        )
        .encrypt(mnemonic.into_phrase().as_str().as_bytes())
        .context(EncryptionSnafu)?;

        Ok((salt, encrypted_mnemonic))
    }
}

static KEY_CHECK_SUB_TREE: &str = "key_check";

impl<L: Ledger> KeystoreLoader<L> for Loader {
    type Meta = LoaderMetadata;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(LoaderMetadata, KeyTree), KeystoreError<L>> {
        println!("creating meta from loader");
        let (mnemonic, key) = self.create_from_mnemonic()?;

        // Generate and encrypt some random bytes using the mnemonic, so in the future we can check
        // if the mnemonic is correct.
        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        let encrypted_bytes = Cipher::new(
            key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
            ChaChaRng::from_rng(&mut self.rng).unwrap(),
        )
        .encrypt(&bytes)
        .context(EncryptionSnafu)?;

        let (salt, encrypted_mnemonic) = self.create_password(mnemonic)?;
        let meta = LoaderMetadata {
            version: (
                env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
            ),
            salt,
            encrypted_mnemonic,
            encrypted_bytes,
        };
        println!("created meta form loader");
        Ok((meta, key))
    }

    fn load(&mut self, meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<L>> {
        let key = loop {
            if let Some(password) = self.input.read_password()? {
                // Generate the decryption key and check that we can use it to decrypt
                // `encrypted_mnemonic`. If we can't, the key is wrong.
                let decryption_key =
                    KeyTree::from_password_and_salt(password.as_bytes(), &meta.salt)
                        .context(KeySnafu)?;
                if let Ok(mnemonic_bytes) = Cipher::new(
                    decryption_key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
                    ChaChaRng::from_rng(&mut self.rng).unwrap(),
                )
                .decrypt(&meta.encrypted_mnemonic)
                {
                    // If the data decrypts successfully, then `mnemonic_bytes` is authenticated, so
                    // we can safely unwrap when deserializing it.
                    break KeyTree::from_mnemonic(
                        &Mnemonic::from_phrase(std::str::from_utf8(&mnemonic_bytes).unwrap())
                            .unwrap(),
                    );
                } else if self.input.interactive() {
                    println!("Sorry, that's incorrect.");
                } else {
                    return Err(KeystoreError::Failed {
                        msg: String::from("incorrect password"),
                    });
                }
            } else {
                // Reset password using mnemonic.
                let mnemonic = self.input.read_mnemonic()?;
                let key = KeyTree::from_mnemonic(&mnemonic);

                // Check if the entered mnemonic is correct by attempting to decrypt the encrypted
                // random bytes.
                if Cipher::new(
                    key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
                    ChaChaRng::from_rng(&mut self.rng).unwrap(),
                )
                .decrypt(&meta.encrypted_bytes)
                .is_ok()
                {
                    let (salt, encrypted_mnemonic) = self.create_password(mnemonic)?;
                    meta.salt = salt;
                    meta.encrypted_mnemonic = encrypted_mnemonic;
                    break key;
                } else if self.input.interactive() {
                    println!("Sorry, that's incorrect.");
                } else {
                    return Err(KeystoreError::Failed {
                        msg: String::from("incorrect mnemonic"),
                    });
                }
            }
        };

        Ok(key)
    }
}
