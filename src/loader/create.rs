// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    hd::{KeyTree, Mnemonic},
    loader::{KeystoreLoader, MnemonicPasswordLogin},
    KeystoreError,
};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reef::Ledger;
use std::path::PathBuf;

/// Create or log into a keystore using a given password and mnemonic.
///
/// This loader will attempt to create or log into a keystore using a given password and mnemonic.
/// If no keystore exists, it will create one using the mnemonic and password. If one does exist, it
/// will attempt to log in using the password, unless the loader was created with
/// [CreateLoader::exclusive].
pub struct CreateLoader {
    mnemonic: Mnemonic,
    password: String,
    dir: PathBuf,
    exclusive: bool,
    rng: ChaChaRng,
}

impl CreateLoader {
    pub fn new(rng: &mut ChaChaRng, dir: PathBuf, mnemonic: Mnemonic, password: String) -> Self {
        Self {
            dir,
            mnemonic,
            password,
            exclusive: false,
            rng: ChaChaRng::from_rng(rng).unwrap(),
        }
    }

    /// A [CreateLoader] which fails if a keystore already exists.
    pub fn exclusive(
        rng: &mut ChaChaRng,
        dir: PathBuf,
        mnemonic: Mnemonic,
        password: String,
    ) -> Self {
        Self {
            dir,
            mnemonic,
            password,
            exclusive: true,
            rng: ChaChaRng::from_rng(rng).unwrap(),
        }
    }
}

impl<L: Ledger> KeystoreLoader<L> for CreateLoader {
    type Meta = MnemonicPasswordLogin;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<L>> {
        let meta =
            MnemonicPasswordLogin::new(&mut self.rng, &self.mnemonic, self.password.as_bytes())?;
        let key = KeyTree::from_mnemonic(&self.mnemonic);
        Ok((meta, key))
    }

    fn load(&mut self, meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<L>> {
        if self.exclusive {
            return Err(KeystoreError::Failed {
                msg: String::from("using an exclusive CreateLoader with an existing keystore"),
            });
        }

        let mnemonic = meta
            .decrypt_mnemonic(self.password.as_bytes())
            .ok_or_else(|| KeystoreError::Failed {
                msg: String::from("incorrect password"),
            })?;
        Ok(KeyTree::from_mnemonic(&mnemonic))
    }
}
