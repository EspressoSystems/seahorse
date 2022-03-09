// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use ark_serialize::CanonicalSerialize;
use jf_cap::KeyPair;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use tagged_base64::TaggedBase64;

fn main() {
    let mut rng = ChaChaRng::from_entropy();
    let key_pair = KeyPair::generate(&mut rng);

    // `KeyPair` doesn't have a `tagged_blob` attribute, so we have to manually convert the key to
    // bytes and then to tagged base 64 for printing.
    let mut bytes = vec![];
    key_pair.serialize(&mut bytes).unwrap();
    let private = TaggedBase64::new("SIGNKEY", &bytes).unwrap();

    println!("Public key: {}", key_pair.ver_key_ref());
    println!("Private key: {}", private);
}
