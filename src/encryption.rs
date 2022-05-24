// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Symmetric encryption for locally persistent keystore data.
//!
//! All secret data that the keystore stores on the file system is encrypted using this module. The
//! encryption scheme is an encrypt-then-MAC implementation using ChaCha20 as a stream cipher and
//! SHA3-256 as an HMAC.
//!
//! The choice of stream cipher merits some discussion. Other stream ciphers which were considered
//! include AES-GCM-SIV and AES-CTR. Briefly, the advantages of each:
//! * AES-GCM-SIV is natively authenticating and would not require the use of a separate MAC
//!   function. It is also somewhat resistant to nonce reuse, a common class of security bugs in
//!   cryptography implementations.
//! * AES-CTR is widely used and thoroughly analyzed, and common consumer hardware includes
//!   instructions designed to accelerate this algorithm.
//!
//! Now, the reasons why we prefer ChaCha20:
//!
//! * AES-GCM-SIV uses a polynomial hash function which is subject to sharding attacks that reduce
//!   the security of the cipher to about 90 bits. This figure is extrapolated from table 1 of
//!   [https://eprint.iacr.org/2017/708.pdf](https://eprint.iacr.org/2017/708.pdf) (page 14). Note
//!   that the 90 bits figure is based _specifically_ on chosen plaintext attacks, and potentially
//!   underestimates the security, since CPA attacks are milder than other attacks (like key
//!   recovery) and are usually easiest to carry out anyways. In particular, the length of the
//!   longest encrypted plaintext (`k` in the table indicates the longest message is `~2^k` AES
//!   blocks long) significantly reduces the additional amount of work required to carry out the
//!   attack, but the keystore only encrypts relatively small amounts of data with any one key.
//!   Nevertheless, we can avoid this attack entirely by using a hash-based MAC instead of a
//!   polynomial MAC.
//!
//! * AES-CTR has security against a plaintext-distinguishing attack which decreases with the length
//!   of the message being encrypted, and so it is recommended to rekey after encrypting a certain
//!   number of blocks. Detailed recommendations vary from [every 1024 blocks
//!   (16kb)](https://support.xilinx.com/s/article/65528?language=en_US) to every [2^32 blocks
//!   (69gb)](https://datatracker.ietf.org/doc/html/rfc4344#page-3). The lack of a consistent,
//!   standardized recommendation coupled with the performance implications of adopting the more
//!   conservative recommendation makes this a less attractive choice than ChaCha20.
//!   
//!   The root of AES-CTR's plaintext distinguishing vulnerability is the fact that it is based on a
//!   pseudo-random permutation. ChaCha20 is based on a pseudo-random function which is not
//!   invertible, and so it is immune to the particular attack that succeeds against AES-CTR.
//!   Moreover, even if ChaCha20's PRF turned out to be invertible, its security parameters
//!   (specifically the 512-bit block size) are much better than AES to begin with, and it would
//!   take a message of 2^128 blocks being encrypted with the same key to have a 2^-256 probability
//!   of distinguishing plaintexts.
//!
//! The keystore uses this library to encrypt data at a small granularity. For the log-structured
//! data, each log entry is encrypted separately. Matching the encryption granularity to the
//! structure of the data is advantageous for a few reasons. First, it allows us to recover most of
//! the data if a single entry becomes corrupted on disk. More relevantly for this module, it allows
//! us to use a different key for each encrypted message, which is an easy way to avoid nonce reuse
//! misuse vulnerabilities, and works well with procedural key generation.
//!
//! This module uses the [hd] module for procedural key generation. A [Cipher] wraps an entire
//! [hd::KeyTree] and uses the tree to deterministically generate a new key for each message it
//! encrypts. This reduces are vulnerability to nonce reuse misuse bugs and increases our defense in
//! depth.
use super::hd;
use ark_serialize::*;
use chacha20::{cipher, ChaCha20};
use cipher::{NewCipher, StreamCipher};
use generic_array::GenericArray;
pub use hd::Salt;
use hmac::{crypto_mac::MacError, Hmac, Mac, NewMac};
use jf_utils::{deserialize_canonical_bytes, CanonicalBytes};
use rand_chacha::rand_core::{CryptoRng, RngCore};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    DataTooLong {
        #[snafu(source(false))]
        source: cipher::errors::LoopError,
    },
    ArgonError {
        #[snafu(source(false))]
        source: argon2::Error,
    },
    InvalidHmac {
        #[snafu(source(false))]
        source: MacError,
    },
    /// Randomness was not provided, so encryption failed.
    NoRandomness,
}

pub type Result<T> = std::result::Result<T, Error>;

pub type Nonce = [u8; 32];

/// An authenticating stream cipher.
///
/// This implementation uses the encrypt-then-MAC strategy, with ChaCha20 as the stream cipher and
/// SHA3-256 as an HMAC.
///
/// It requires an entire sub-tree of the HD key structure, as it generates separate keys for
/// encryption and authentication for each message it encrypts.
#[derive(Clone)]
pub struct Cipher<Rng: CryptoRng = ChaChaRng> {
    hmac_key: hd::Key,
    cipher_keyspace: hd::KeyTree,
    rng: Option<Rng>,
}

impl Cipher<ChaChaRng> {
    pub fn decrypter(keys: hd::KeyTree) -> Self {
        Self::new(keys, None)
    }
}

impl<Rng: RngCore + CryptoRng> Cipher<Rng> {
    pub fn new(keys: hd::KeyTree, rng: Option<Rng>) -> Self {
        Self {
            hmac_key: keys.derive_key("hmac".as_bytes()),
            cipher_keyspace: keys.derive_sub_tree("cipher".as_bytes()),
            rng,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<CipherText> {
        let rng = self.rng.as_mut().ok_or(Error::NoRandomness)?;

        // Generate a random nonce unique to this message and use it to derive the encryption key.
        let mut nonce = Nonce::default();
        rng.fill_bytes(&mut nonce);
        let cipher_key = self.cipher_key(&nonce);

        // Encrypt the plaintext by applying the keystream.
        let mut bytes = plaintext.to_vec();
        self.apply(&cipher_key, &mut bytes)?;

        // Add the authentication tag.
        let hmac = self
            .hmac(&self.hmac_key, &nonce, &bytes)
            .finalize()
            .into_bytes()
            .into();
        Ok(CipherText { bytes, nonce, hmac })
    }

    pub fn decrypt(&self, ciphertext: &CipherText) -> Result<Vec<u8>> {
        // Verify the HMAC before doing anything else.
        self.hmac(&self.hmac_key, &ciphertext.nonce, &ciphertext.bytes)
            .verify(&ciphertext.hmac)
            .map_err(|source| Error::InvalidHmac { source })?;

        // If authentication succeeded, re-generate the key which was used to encrypt and
        // authenticate this message, based on the associated nonce, and use it to decrypt the
        // ciphertext.
        let cipher_key = self.cipher_key(&ciphertext.nonce);
        let mut bytes = ciphertext.bytes.clone();
        self.apply(&cipher_key, &mut bytes)?;
        Ok(bytes)
    }

    fn apply(&self, key: &hd::Key, data: &mut [u8]) -> Result<()> {
        // We don't need a random nonce for the stream cipher, since we are initializing it with a
        // new key for each message.
        let key = <&GenericArray<u8, _>>::from(key.as_bytes().open_secret());
        let mut cipher = ChaCha20::new(key, &chacha20::Nonce::default());
        cipher
            .try_apply_keystream(data)
            .map_err(|source| Error::DataTooLong { source })?;
        Ok(())
    }

    fn hmac(&self, hmac_key: &hd::Key, nonce: &[u8], ciphertext: &[u8]) -> Hmac<Sha3_256> {
        let mut hmac = Hmac::<Sha3_256>::new_from_slice(hmac_key.as_bytes().open_secret()).unwrap();
        hmac.update(nonce);
        // Note: the ciphertext must be the last field, since it is variable sized and we do not
        // explicitly commit to its length. If we included another variably sized field after the
        // ciphertext, an attacker could alter the field boundaries to create a semantically
        // different message with the same MAC.
        hmac.update(ciphertext);
        hmac
    }

    fn cipher_key(&self, nonce: &[u8]) -> hd::Key {
        self.cipher_keyspace.derive_key(nonce)
    }
}

/// Encrypted and authenticated data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
pub struct CipherText {
    hmac: [u8; 32],
    nonce: Nonce,
    bytes: Vec<u8>,
}
deserialize_canonical_bytes!(CipherText);

// We serialize the ciphertext-and-metadata structure using a custom ark_serialize implementation in
// order to derive an unstructured, byte-oriented serialization format that does not look like a
// struct. This provides a few nice properties:
//  * the serialized byte stream should truly be indistinguishable from random data, since it is
//    just a concatenation of pseudo-random fields
//  * the deserialization process is extremely simple, and allows us to access and verify the MAC
//    before doing anything more than read in the encrypted file
impl CanonicalSerialize for CipherText {
    fn serialize<W: Write>(&self, mut w: W) -> std::result::Result<(), SerializationError> {
        w.write_all(&self.hmac).map_err(SerializationError::from)?;
        w.write_all(&self.nonce).map_err(SerializationError::from)?;
        // We serialize the only variably sized field, the ciphertext itself, last, so that we don't
        // have to serialize its length (which would break the apparent pseudo-randomness of the
        // serialized byte stream). We can deserialize it by simply reading until the end of the
        // byte stream once we've deserialized the fixed-width fields.
        w.write_all(&self.bytes).map_err(SerializationError::from)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.nonce.len() + self.hmac.len() + self.bytes.len()
    }
}

impl CanonicalDeserialize for CipherText {
    fn deserialize<R: Read>(mut r: R) -> std::result::Result<Self, SerializationError> {
        // Deserialize the known-size fields.
        let mut hmac = <[u8; 32]>::default();
        r.read_exact(&mut hmac).map_err(SerializationError::from)?;
        let mut nonce = Nonce::default();
        r.read_exact(&mut nonce).map_err(SerializationError::from)?;
        // The ciphertext is whatever happens to be left in the input stream.
        let bytes = r
            .bytes()
            .collect::<std::result::Result<_, _>>()
            .map_err(SerializationError::from)?;
        Ok(Self { nonce, hmac, bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hd::KeyTree;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaChaRng,
    };

    fn random_cipher(rng: &mut ChaChaRng) -> Cipher {
        Cipher::new(
            KeyTree::random(rng).0,
            Some(ChaChaRng::from_rng(rng).unwrap()),
        )
    }

    fn corrupt(rng: &mut ChaChaRng, data: &mut [u8]) {
        let index = rng.next_u64() as usize % data.len();
        data[index] = !data[index];
    }

    fn assert_invalid_hmac(cipher: &Cipher, data: &CipherText) {
        match cipher.decrypt(data) {
            Err(Error::InvalidHmac { .. }) => {}
            res => {
                panic!("expected InvalidHmac, got {:?}", res);
            }
        }
    }

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::from_seed([42; 32]);
        let mut cipher = random_cipher(&mut rng);

        let mut plaintext = vec![0u8; 1024];
        rng.fill_bytes(&mut plaintext);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(plaintext, cipher.decrypt(&ciphertext).unwrap());
    }

    #[test]
    fn decrypt_incorrect_key() {
        let mut rng = ChaChaRng::from_seed([42; 32]);
        let mut cipher1 = random_cipher(&mut rng);

        let mut plaintext = vec![0u8; 1024];
        rng.fill_bytes(&mut plaintext);
        let ciphertext = cipher1.encrypt(&plaintext).unwrap();

        let cipher2 = random_cipher(&mut rng);
        assert_invalid_hmac(&cipher2, &ciphertext);
        assert_eq!(plaintext, cipher1.decrypt(&ciphertext).unwrap());
    }

    #[test]
    fn decrypt_corrupt() {
        let mut rng = ChaChaRng::from_seed([42; 32]);
        let mut cipher = random_cipher(&mut rng);

        let mut plaintext = vec![0u8; 1024];
        rng.fill_bytes(&mut plaintext);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(plaintext, cipher.decrypt(&ciphertext).unwrap());

        // Corrupt a random byte in the HMAC.
        let mut corrupt_hmac = ciphertext.clone();
        corrupt(&mut rng, &mut corrupt_hmac.hmac);
        assert_invalid_hmac(&cipher, &corrupt_hmac);

        // Corrupt a random byte in the nonce.
        let mut corrupt_nonce = ciphertext.clone();
        corrupt(&mut rng, &mut corrupt_nonce.nonce);
        assert_invalid_hmac(&cipher, &corrupt_nonce);

        // Corrupt a random byte in the payload.
        let mut corrupt_payload = ciphertext.clone();
        corrupt(&mut rng, &mut corrupt_payload.bytes);
        assert_invalid_hmac(&cipher, &corrupt_payload);
    }
}
