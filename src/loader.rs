// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::{encryption, hd, reader, EncryptionError, KeyError, WalletError};
use encryption::{Cipher, CipherText, Salt};
use hd::KeyTree;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reader::Reader;
use reef::Ledger;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::path::PathBuf;

pub trait WalletLoader<L: Ledger> {
    type Meta; // Metadata stored in plaintext and used by the loader to access the wallet.
    fn location(&self) -> PathBuf;
    fn create(&mut self) -> Result<(Self::Meta, KeyTree), WalletError<L>>;
    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError<L>>;
}

// Metadata about a wallet which is always stored unencrypted, so we can report some basic
// information about the wallet without decrypting. This also aids in the key derivation process.
//
// DO NOT put secrets in here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoaderMetadata {
    salt: Salt,
    // Encrypted bytes from a mnemonic. This will only decrypt successfully if we have the
    // correct password, so we can use it as a quick check that the user entered the right thing.
    encrypted_mnemonic: CipherText,
}

enum LoaderInput {
    User(Reader),
    PasswordLiteral(String),
    MnemonicPasswordLiteral(String, String),
}

impl LoaderInput {
    fn create_password<L: Ledger>(&mut self) -> Result<String, WalletError<L>> {
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

            Self::PasswordLiteral(password) => Ok(password.to_string()),

            Self::MnemonicPasswordLiteral(_, password) => Ok(password.to_string()),
        }
    }

    fn read_password<L: Ledger>(&mut self) -> Result<String, WalletError<L>> {
        match self {
            Self::User(reader) => reader.read_password("Enter password: "),
            Self::PasswordLiteral(password) => Ok(password.to_string()),
            Self::MnemonicPasswordLiteral(_, password) => Ok(password.to_string()),
        }
    }

    fn create_mnemonic<L: Ledger>(
        &mut self,
        rng: &mut ChaChaRng,
    ) -> Result<String, WalletError<L>> {
        match self {
            Self::User(reader) => {
                println!(
                    "Your wallet will be identified by a secret mnemonic phrase. This phrase will \
                     allow you to recover your wallet if you lose access to it. Anyone who has access \
                     to this phrase will be able to view and spend your assets. Store this phrase in a \
                     safe, private place."
                );
                'outer: loop {
                    let (_, mnemonic) = KeyTree::random(rng).context(KeyError)?;
                    println!("Your mnemonic phrase will be:");
                    println!("{}", mnemonic);
                    'inner: loop {
                        println!("1) Accept phrase and create wallet");
                        println!("2) Generate a new phrase");
                        println!(
                            "3) Manually enter a mnemonic (use this to recover a lost wallet)"
                        );
                        match reader.read_line() {
                            Some(line) => match line.as_str().trim() {
                                "1" => return Ok(mnemonic),
                                "2" => continue 'outer,
                                "3" => {
                                    return reader.read_password("Enter mnemonic phrase: ");
                                }
                                _ => continue 'inner,
                            },
                            None => {
                                return Err(WalletError::Failed {
                                    msg: String::from("eof"),
                                })
                            }
                        }
                    }
                }
            }

            Self::PasswordLiteral(_) => Err(WalletError::Failed {
                msg: String::from("missing mnemonic phrase"),
            }),

            Self::MnemonicPasswordLiteral(mnemonic, _) => Ok(mnemonic.to_string()),
        }
    }

    fn interactive(&self) -> bool {
        matches!(self, Self::User(..))
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

    pub fn into_reader(self) -> Option<Reader> {
        match self.input {
            LoaderInput::User(reader) => Some(reader),
            _ => None,
        }
    }

    fn load_from_password<L: Ledger>(
        &mut self,
        meta: &LoaderMetadata,
    ) -> Result<KeyTree, WalletError<L>> {
        let password = self.input.read_password()?;
        KeyTree::from_password_and_salt(password.as_bytes(), &meta.salt).context(KeyError)
    }

    fn create_from_mnemonic<L: Ledger>(&mut self) -> Result<(String, KeyTree), WalletError<L>> {
        let mnemonic = self.input.create_mnemonic(&mut self.rng)?;
        let key = KeyTree::from_mnemonic(mnemonic.as_bytes()).context(KeyError)?;
        Ok((mnemonic, key))
    }
}

static KEY_CHECK_SUB_TREE: &str = "key_check";

impl<L: Ledger> WalletLoader<L> for Loader {
    type Meta = LoaderMetadata;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(LoaderMetadata, KeyTree), WalletError<L>> {
        let (mnemonic, key) = self.create_from_mnemonic()?;

        // Encrypt the mnemonic phrase, which we can decrypt on load to check the derived key.
        let password = self.input.create_password()?;
        let (encryption_key, salt) =
            KeyTree::from_password(&mut self.rng, password.as_bytes()).context(KeyError)?;
        let encrypted_mnemonic = Cipher::new(
            encryption_key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
            ChaChaRng::from_rng(&mut self.rng).unwrap(),
        )
        .encrypt(mnemonic.as_bytes())
        .context(EncryptionError)?;

        let meta = LoaderMetadata {
            salt,
            encrypted_mnemonic,
        };
        Ok((meta, key))
    }

    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError<L>> {
        let key = loop {
            // Generate the decryption key and check that we can use it to decrypt
            // `encrypted_mnemonic`. If we can't, the key is wrong.
            let decryption_key = self.load_from_password(meta)?;
            if let Ok(mnemonic_bytes) = Cipher::new(
                decryption_key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
                ChaChaRng::from_rng(&mut self.rng).unwrap(),
            )
            .decrypt(&meta.encrypted_mnemonic)
            {
                break KeyTree::from_mnemonic(&mnemonic_bytes).context(KeyError)?;
            } else if self.input.interactive() {
                println!("Sorry, that's incorrect.");
            } else {
                return Err(WalletError::Failed {
                    msg: String::from("incorrect authentication"),
                });
            }
        };

        Ok(key)
    }
}
