// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    hd::KeyTree,
    loader::{KeystoreLoader, MnemonicPasswordLogin},
    KeystoreError,
};
use reef::Ledger;
use std::path::PathBuf;

/// Log into a keystore using a given password.
///
/// This loader will attempt to authenticate and decrypt an existing keystore under the given
/// password. It does not support creating a new keystore.
pub struct LoginLoader {
    password: String,
    dir: PathBuf,
}

impl LoginLoader {
    pub fn new(dir: PathBuf, password: String) -> Self {
        Self { dir, password }
    }
}

impl<L: Ledger> KeystoreLoader<L> for LoginLoader {
    type Meta = MnemonicPasswordLogin;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<L>> {
        Err(KeystoreError::Failed {
            msg: String::from("LoginLoader does not support creating a new keystore"),
        })
    }

    fn load(&mut self, meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<L>> {
        let mnemonic = meta
            .decrypt_mnemonic(self.password.as_bytes())
            .ok_or_else(|| KeystoreError::Failed {
                msg: String::from("incorrect password"),
            })?;
        Ok(KeyTree::from_mnemonic(&mnemonic))
    }
}
