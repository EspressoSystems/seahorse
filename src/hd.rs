// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Hierarchical deterministic key generation
//!
//! This module provides an interface for procedurally generating a tree of keys. It does not
//! implement the full [BIP 32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//! standard for HD wallets, only the features relevant to our system. For example, BIP 32 provides
//! features for deriving public keys from parent public keys without knowing any private keys, to
//! allow for trustless key rotation. Kkey rotation is less important in CAP systems, which provide
//! unlinkability by default.
//!
//! The keys generated by this interface are 32-byte pseudo-random values with no internal
//! structure. They have no relationship to elliptic curve points, but they can be used as a random
//! seed for generating elliptic curve keys for use in the wallet. The lack of structure makes these
//! keys useful for other applications too, though, such as encryption and decryption.
//!
//! The relationship between derived keys and their parents can be described as a tree. A single
//! root KeyTree is generated from some external means (such as entropy, or from a password or
//! mnemonic using a KDF). This root tree can be used to derive sub-trees using
//! [KeyTree::derive_sub_tree], and any [KeyTree] can be used to derive more sub-trees as well as
//! leaf keys. Each derived [KeyTree] and [Key] is a commitment to its parent, but it is infeasible
//! to compute the parent key from the child.
//!
//! KeyTrees are opaque. They cannot be used for anything other than to derive more keys. Only leaf
//! keys can be used as keys in applications, via the [Key::as_bytes] method. Each key commits to
//! its role: leaf keys and key trees will not collide, even if they are derived from the same
//! parent key with the same `id`.
pub use crate::secret::Secret;

pub use bip0039::Mnemonic;

use jf_cap::keys::{AuditorKeyPair, FreezerKeyPair, UserKeyPair};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::rand_core::{CryptoRng, RngCore};
use rand_chacha::ChaChaRng;
use sha3::{Digest, Sha3_256, Sha3_512};
use std::convert::TryInto;
use zeroize::Zeroize;

// We use 16-byte seeds, or, equivalently, 12-word mnemonic phrases.
const SEED_LENGTH: usize = 16;

/// Salt used when deriving keys from passwords.
pub type Salt = [u8; 32];

/// A virtual tree of keys.
#[derive(Clone, Debug)]
pub struct KeyTree {
    // Sub-trees are 64 bytes, twice as large as the actual keys, to make it much harder to break
    // security upwards through the tree. This is probably not strictly necessary (32 bytes is
    // already quite large) but it is an extra layer of security for sub-tree separation, which is
    // the most important security property of this system.
    //
    // BIP32 uses a similar idea by extending their keys with an extra 32 bytes of entropy (the
    // chain code).
    state: Secret<[u8; 64]>,
    // We track the depth in the tree of each sub-tree, so that we can mix it into the hash function
    // at each level as a deterministic salt. This effectively changes the hash function used at
    // each level of the tree, making us less vulnerable to precomputation attacks even in the
    // presence of sub-tree ID reuse.
    depth: usize,
}

macro_rules! derive_key_pair {
    ($self: expr, $label:expr, $id: expr, $tar:ident) => {{
        let id = [$label.as_bytes(), $id].concat();
        let derived_seed = $self.derive_key_internal(&id);
        let mut rng = ChaChaRng::from_seed(*derived_seed.as_bytes().open_secret());
        $tar::generate(&mut rng)
    }};
}

impl KeyTree {
    /// Build a new [KeyTree] from a prng.
    ///
    /// Returns a 12-word mnemonic that can be used to recover this [KeyTree] using
    /// [KeyTree::from_mnemonic]. The generated mnemonic conforms to
    /// [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) and includes a
    /// 4-bit checksum for error detection at recovery time.
    pub fn random(rng: &mut (impl CryptoRng + RngCore)) -> (Self, Mnemonic) {
        // Sample some entropy.
        let mut entropy = [0u8; SEED_LENGTH];
        rng.fill_bytes(&mut entropy);

        // Convert entropy to a mnemonic phrase as specified in BIP-39. Note that `from_entropy` can
        // only fail if `entropy` is not a multiple of 4 bytes in 128..256; `SEED_LENGTH` ensures
        // this cannot happen, so it is safe to `unwrap`.
        let mnemonic = Mnemonic::from_entropy(entropy.to_vec()).unwrap();

        // Use the entropy to construct a KeyTree.
        let key_tree = Self::from_mnemonic(&mnemonic);
        (key_tree, mnemonic)
    }

    /// Build a new [KeyTree] from a password using the [argon2] KDF.
    ///
    /// Returns the 32-byte salt that can be used to recover this [KeyTree] using
    /// [KeyTree::from_password_and_salt].
    pub fn from_password(
        rng: &mut (impl CryptoRng + RngCore),
        password: &[u8],
    ) -> Result<(Self, Salt), argon2::Error> {
        let mut salt = Salt::default();
        rng.fill_bytes(&mut salt);
        let key = Self::from_password_and_salt(password, &salt)?;
        Ok((key, salt))
    }

    /// Recover a password-protected [KeyTree].
    pub fn from_password_and_salt(password: &[u8], salt: &[u8]) -> Result<Self, argon2::Error> {
        let mut key = Secret::<[u8; 64]>::build();
        let config = argon2::Config {
            hash_length: key.len() as u32,
            ..Default::default()
        };
        let mut hash = argon2::hash_raw(password, salt, &config)?;
        *key = hash.clone().try_into().unwrap();
        hash.zeroize();
        Ok(Self {
            state: key.finalize(),
            depth: 0,
        })
    }

    /// Recover a [KeyTree] from its mnemonic seed phrase.
    ///
    /// See [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for more
    /// details on deterministically recovering entropy from a mnemonic.
    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Self {
        Self {
            // BIP39 allows mnemonics to be password-protected, so `to_seed` takes a password. We
            // use a different form of password protection, where the mnemonic for a wallet is
            // encrypted using a password, allowing for more user-friendly login. This is handled at
            // a higher level, and we use the empty password here, following the reccomendation of
            // BIP-39 for the case when there is no password associated with the mnemonic.
            state: Secret::new(&mut mnemonic.to_seed("")),
            depth: 0,
        }
    }

    /// Derive a sub-tree of this [KeyTree].
    ///
    /// The sub-tree can be used to derive keys, or even further sub-trees. This is a one-way
    /// function: it is infeasible to compute from the sub-tree the state of the parent tree or any
    /// other sub-tree not derived from this sub-tree. This irreversibility makes sub-trees useful
    /// for representing different accounts, or different domains like encryption keys vs. protocol
    /// keys.
    pub fn derive_sub_tree(&self, id: &[u8]) -> KeyTree {
        // Note that the hash for deriving a new sub-tree does not need to include a commitment to
        // the role of the key (sub-tree vs key) because sub-trees and keys are different sizes and
        // thus cannot suffer from domain confusion.
        let mut digest = Sha3_512::new()
            // Commit to the parent key.
            .chain(self.state.open_secret())
            // Mix in the depth of the tree as a salt.
            .chain(&self.depth.to_le_bytes())
            .chain(id)
            .finalize();
        Self {
            state: Secret::new(digest.as_mut()),
            depth: self.depth + 1,
        }
    }

    // The internal API that derive a Key
    fn derive_key_internal(&self, id: &[u8]) -> Key {
        // Note that the hash for deriving a new key does not need to include a commitment to the
        // role of the key (key vs sub-tree) because keys and sub-trees are different sizes and thus
        // cannot suffer from domain confusion.
        let mut digest = Sha3_256::new()
            // Commit to the parent key.
            .chain(self.state.open_secret())
            // Mix in the depth of the tree as a salt.
            .chain(&self.depth.to_le_bytes())
            .chain(id)
            .finalize();
        Key(Secret::new(digest.as_mut()))
    }

    /// Derive a generic [Key] from the [KeyTree] with a certain id.
    pub fn derive_key(&self, id: &[u8]) -> Key {
        let id = ["default key".as_ref(), id].concat();
        self.derive_key_internal(id.as_ref())
    }

    /// Derive a sending key from the [KeyTree] with a certain id.
    pub fn derive_user_keypair(&self, id: &[u8]) -> UserKeyPair {
        derive_keypair!(self, "user keypair", id, UserKeyPair)
    }

    /// Derive a viewing key from the [KeyTree] with a certain id.
    pub fn derive_auditor_keypair(&self, id: &[u8]) -> AuditorKeyPair {
        derive_keypair!(self, "auditor keypair", id, AuditorKeyPair)
    }

    /// Derive a freezing key from the [KeyTree] with a certain id.
    pub fn derive_freezer_keypair(&self, id: &[u8]) -> FreezerKeyPair {
        derive_keypair!(self, "freezer keypair", id, FreezerKeyPair)
    }
}

/// A 32-byte pseudo-random key.
#[derive(Clone, Debug)]
pub struct Key(Secret<[u8; 32]>);

impl Key {
    /// Get the pseudo-random bytes that make up this key.
    ///
    /// The result is wrapped in a [Secret] to discourage the compiler from making unnecessary
    /// copies in memory. To extract the raw bytes, use [Secret::open_secret], but do so with
    /// extreme caution.
    pub fn as_bytes(&self) -> &Secret<[u8; 32]> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_key_tree_gen_mnemonic() {
        use ark_std::rand::thread_rng;

        let mut rng = thread_rng();
        let (key_tree, mnemonic) = KeyTree::random(&mut rng);

        // The mnemonic should be 12 words.
        assert_eq!(12, mnemonic.to_string().split_whitespace().count());

        // Check that we can recover the same key tree from the mnemonic phrase.
        let key_tree_recovered = KeyTree::from_mnemonic(&mnemonic);

        assert_eq!(
            key_tree.state.open_secret(),
            key_tree_recovered.state.open_secret()
        )
    }

    #[test]
    fn test_key_tree_gen_password() {
        use ark_std::rand::thread_rng;

        let mut rng = thread_rng();
        let mut password = [0u8; 32];
        rng.fill_bytes(&mut password);

        let (key_tree, salt) = KeyTree::from_password(&mut rng, &password).unwrap();
        let key_tree_recovered = KeyTree::from_password_and_salt(&password, &salt).unwrap();

        assert_eq!(
            key_tree.state.open_secret(),
            key_tree_recovered.state.open_secret()
        );
    }

    #[test]
    fn test_key_tree_domain_separation() {
        use ark_std::rand::thread_rng;

        let mut rng = thread_rng();
        let mut id1 = [0u8; 32];
        let mut id2 = [0u8; 32];
        rng.fill_bytes(&mut id1);
        rng.fill_bytes(&mut id2);
        assert_ne!(id1, id2);

        let (key_tree, _) = KeyTree::random(&mut rng);
        let all_keys = vec![
            bincode::serialize(&key_tree.derive_auditor_key_pair(&id1)).unwrap(),
            bincode::serialize(&key_tree.derive_auditor_key_pair(&id2)).unwrap(),
            bincode::serialize(&key_tree.derive_freezer_key_pair(&id1)).unwrap(),
            bincode::serialize(&key_tree.derive_freezer_key_pair(&id2)).unwrap(),
            bincode::serialize(&key_tree.derive_user_key_pair(&id1)).unwrap(),
            bincode::serialize(&key_tree.derive_user_key_pair(&id2)).unwrap(),
            key_tree.derive_key(&id1).as_bytes().open_secret().to_vec(),
            key_tree.derive_key(&id2).as_bytes().open_secret().to_vec(),
            key_tree.derive_sub_tree(&id1).state.open_secret().to_vec(),
            key_tree.derive_sub_tree(&id2).state.open_secret().to_vec(),
        ];
        let distinct_keys = all_keys.iter().cloned().collect::<HashSet<_>>();
        assert_eq!(distinct_keys.len(), all_keys.len());
    }
}
