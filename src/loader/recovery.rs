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
use async_trait::async_trait;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reef::Ledger;
use std::path::PathBuf;

/// Recover a keystore from a mnemonic phrase.
///
/// If encrypted keystore files already exist, this loader will use the given mnemonic phrase to
/// decrypt them, change the keystore's password, and then re-encrypt it. If no files exist, the
/// loader will create a new keystore using the given mnemonic and password. If the mnemonic used is
/// in fact the same as the mnemonic used to create a keystore which has been lost, then the caller
/// can recover their assets using [generate_sending_account](crate::Keystore::generate_sending_account) with
/// `scan_from` set to `Some(EventIndex::default())`. This will result in regenerating the same keys
/// that belonged to the old keystore and scanning the ledger for records belonging to those keys.
///
/// Note that in the second case, recovery without encrypted keystore files, the loader cannot check
/// if the given mnemonic is correct. The caller will only discover that they have used the wrong
/// mnemonic when they fail to recover their balance of assets. When the keystore files are present,
/// however, the loader will return an error if the mnemonic is not the one which was used to create
/// the existing files.
pub struct RecoveryLoader {
    mnemonic: Mnemonic,
    new_password: String,
    dir: PathBuf,
    rng: ChaChaRng,
}

impl RecoveryLoader {
    pub fn new(
        rng: &mut ChaChaRng,
        dir: PathBuf,
        mnemonic: Mnemonic,
        new_password: String,
    ) -> Self {
        Self {
            dir,
            mnemonic,
            new_password,
            rng: ChaChaRng::from_rng(rng).unwrap(),
        }
    }
}

#[async_trait]
impl<L: Ledger> KeystoreLoader<L> for RecoveryLoader {
    type Meta = MnemonicPasswordLogin;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    async fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<L>> {
        let meta = MnemonicPasswordLogin::new(
            &mut self.rng,
            &self.mnemonic,
            self.new_password.as_bytes(),
        )?;
        let key = KeyTree::from_mnemonic(&self.mnemonic);
        Ok((meta, key))
    }

    async fn load(&mut self, meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<L>> {
        meta.set_password(&mut self.rng, &self.mnemonic, self.new_password.as_bytes())?;
        Ok(KeyTree::from_mnemonic(&self.mnemonic))
    }
}
