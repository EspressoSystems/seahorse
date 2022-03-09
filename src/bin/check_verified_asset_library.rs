// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use seahorse::asset_library::VerifiedAssetLibrary;
use std::fs::read;
use std::io;
use std::path::PathBuf;
use std::process::exit;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(
    name = "check_verified_asset_library",
    about = "Check that a verified asset library is correctly signed and print its contents."
)]
struct Options {
    /// Only check the validity of the library, do not print its contents.
    #[structopt(short, long)]
    check: bool,

    /// The library to check.
    library: PathBuf,
}

fn main() -> io::Result<()> {
    let opt = Options::from_args();
    let bytes = read(opt.library)?;
    let library = match bincode::deserialize::<VerifiedAssetLibrary>(&bytes) {
        Ok(library) => library,
        Err(err) => {
            eprintln!("Malformed library: {}", err);
            exit(1);
        }
    };
    if let Some(signer) = library.check() {
        if !opt.check {
            println!("Signed by {}", signer);
            for asset in library.open(&signer).unwrap() {
                println!("{}", asset);
            }
        }
        Ok(())
    } else {
        eprintln!("Library is not properly signed.");
        exit(1);
    }
}
