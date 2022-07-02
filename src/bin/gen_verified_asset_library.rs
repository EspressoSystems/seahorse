// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use ark_serialize::CanonicalDeserialize;
use jf_cap::KeyPair;
use seahorse::{asset_library::VerifiedAssetLibrary, assets::Asset};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use structopt::StructOpt;
use tagged_base64::TaggedBase64;

#[derive(StructOpt)]
#[structopt(
    name = "gen_verified_asset_library",
    about = "Generate and sign asset libraries."
)]
struct Options {
    /// Include assets in the library by reading them from IN (separated by newlines).
    #[structopt(short, long, name = "IN")]
    input: Vec<PathBuf>,

    /// Write the library to OUT.
    #[structopt(short, long, name = "OUT")]
    output: PathBuf,

    /// The signing key to use when authenticating the library.
    #[structopt(short, long)]
    key: String,

    /// Optional list of assets to include, passed on the command line rather than using --input.
    assets: Vec<Asset>,
}

fn main() -> io::Result<()> {
    let mut opt = Options::from_args();
    let key = match TaggedBase64::parse(&opt.key) {
        Ok(tb64) => match KeyPair::deserialize(tb64.value().as_slice()) {
            Ok(key) => key,
            Err(err) => {
                eprintln!("Invalid key: {}", err);
                exit(1);
            }
        },
        Err(err) => {
            eprintln!("Invalid key: {}", err);
            exit(1);
        }
    };

    // Collect assets from 2 possible sources:
    // 	* input files given on the command line
    // 	* literal assets given on the command line
    let mut assets = vec![];
    for path in opt.input {
        let file = BufReader::new(File::open(&path)?);
        for line in file.lines() {
            let line = line?;
            let asset = match Asset::from_str(&line) {
                Ok(asset) => asset,
                Err(err) => {
                    eprintln!("invalid asset {} in file {:?}: {}", line, path, err);
                    exit(1);
                }
            };
            assets.push(asset);
        }
    }
    assets.append(&mut opt.assets);

    // Generate and sign the library.
    let library = VerifiedAssetLibrary::new(assets, &key);

    // Write the library to the output file.
    let mut file = File::create(opt.output)?;
    file.write_all(&bincode::serialize(&library).unwrap())?;

    Ok(())
}
