// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    hd,
    loader::{KeystoreLoader, MnemonicPasswordLogin},
    reader, KeystoreError,
};
use async_trait::async_trait;
use hd::{KeyTree, Mnemonic};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reader::Reader;
use reef::Ledger;
use std::path::{Path, PathBuf};

/// Load or a create a keystore with interactive, text-based login.
///
/// This loader will read from the given reader to gather configuration and authentication when
/// creating or opening a keystore. It supports the creation of new keystores with a mnemonic
/// recovery phrase and a password for convenience, as well as logging into existing keystores with
/// a password.
pub struct InteractiveLoader {
    dir: PathBuf,
    pub rng: ChaChaRng,
    input: Reader,
}

impl InteractiveLoader {
    pub fn new(dir: PathBuf, input: Reader) -> Self {
        Self {
            dir,
            input,
            rng: ChaChaRng::from_entropy(),
        }
    }

    pub fn into_reader(self) -> Reader {
        self.input
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    async fn create_password<L: 'static + Ledger>(&mut self) -> Result<String, KeystoreError<L>> {
        loop {
            let password = self.input.read_password("Create password: ").await?;
            let confirm = self.input.read_password("Retype password: ").await?;
            if password == confirm {
                return Ok(password);
            } else {
                println!("Passwords do not match.");
            }
        }
    }

    async fn read_mnemonic<L: 'static + Ledger>(&mut self) -> Result<Mnemonic, KeystoreError<L>> {
        loop {
            let phrase = self.input.read_password("Enter mnemonic phrase: ").await?;
            match Mnemonic::from_phrase(&phrase) {
                Ok(mnemonic) => return Ok(mnemonic),
                Err(err) => {
                    println!("That's not a valid mnemonic phrase ({})", err);
                }
            }
        }
    }
}

#[async_trait]
impl<L: 'static + Ledger> KeystoreLoader<L> for InteractiveLoader {
    type Meta = MnemonicPasswordLogin;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    async fn create(&mut self) -> Result<(MnemonicPasswordLogin, KeyTree), KeystoreError<L>> {
        println!(
            "Your keystore will be identified by a secret mnemonic phrase. This phrase will \
             allow you to recover your keystore if you lose access to it. Anyone who has access \
             to this phrase will be able to view and spend your assets. Store this phrase in a \
             safe, private place."
        );
        let mnemonic = 'outer: loop {
            let (_, mnemonic) = KeyTree::random(&mut self.rng);
            println!("Your mnemonic phrase will be:");
            println!("{}", mnemonic);
            'inner: loop {
                println!("1) Accept phrase and create keystore");
                println!("2) Generate a new phrase");
                println!("3) Manually enter a mnemonic (use this to recover a lost keystore)");
                match self.input.read_line().await {
                    Some(line) => match line.as_str().trim() {
                        "1" => break 'outer (mnemonic),
                        "2" => continue 'outer,
                        "3" => break 'outer (self.read_mnemonic().await?),
                        _ => continue 'inner,
                    },
                    None => {
                        return Err(KeystoreError::Failed {
                            msg: String::from("eof"),
                        })
                    }
                }
            }
        };
        let key = KeyTree::from_mnemonic(&mnemonic);
        let password = self.create_password().await?;
        let meta = MnemonicPasswordLogin::new(&mut self.rng, &mnemonic, password.as_bytes())?;

        Ok((meta, key))
    }

    async fn load(&mut self, meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<L>> {
        let key = loop {
            let password = loop {
                println!("Forgot your password? Want to change it? [y/n]");
                match self.input.read_line().await {
                    Some(line) => match line.as_str().trim() {
                        "n" => break Some(self.input.read_password("Enter password: ").await?),
                        "y" => break None,
                        _ => println!("Please enter 'y' or 'n'."),
                    },
                    None => {
                        return Err(KeystoreError::Failed {
                            msg: String::from("eof"),
                        });
                    }
                }
            };

            if let Some(password) = password {
                if let Some(mnemonic) = meta.decrypt_mnemonic(password.as_bytes()) {
                    break KeyTree::from_mnemonic(&mnemonic);
                } else {
                    println!("Sorry, that's incorrect.");
                }
            } else {
                // Reset password using mnemonic.
                let mnemonic = self.read_mnemonic().await?;
                if meta.check_mnemonic(&mnemonic) {
                    let password = self.create_password().await?;
                    // This should never fail after we have verified the mnemonic.
                    meta.set_password::<L>(&mut self.rng, &mnemonic, password.as_bytes())
                        .unwrap();
                    break KeyTree::from_mnemonic(&mnemonic);
                } else {
                    println!("Sorry, that's incorrect.");
                }
            }
        };

        Ok(key)
    }
}
