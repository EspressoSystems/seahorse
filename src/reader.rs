// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Interactive input.
//!
//! This module defines a [Reader] which can be used to read interactive input using [rustyline] for
//! line editing and [rpassword] for hiding sensitive inputs like passwords and mnemonics. It also
//! has an automated mode to circumvent the interactive features when scripting for the CLI.
use crate::{io::SharedIO, KeyStoreError};
use reef::Ledger;
use rpassword::prompt_password_stdout;
use std::io::{BufRead, Write};

pub enum Reader {
    Interactive(rustyline::Editor<()>),
    Automated(SharedIO),
}

impl Clone for Reader {
    fn clone(&self) -> Self {
        match self {
            Self::Interactive(_) => Self::interactive(),
            Self::Automated(io) => Self::automated(io.clone()),
        }
    }
}

impl Reader {
    pub fn interactive() -> Self {
        Self::Interactive(rustyline::Editor::<()>::new())
    }

    pub fn automated(io: SharedIO) -> Self {
        Self::Automated(io)
    }

    pub fn read_password<L: Ledger>(&mut self, prompt: &str) -> Result<String, KeyStoreError<L>> {
        match self {
            Self::Interactive(_) => {
                prompt_password_stdout(prompt).map_err(|err| KeyStoreError::Failed {
                    msg: err.to_string(),
                })
            }
            Self::Automated(io) => {
                writeln!(io, "{}", prompt).map_err(|err| KeyStoreError::Failed {
                    msg: err.to_string(),
                })?;
                let mut password = String::new();
                match io.read_line(&mut password) {
                    Ok(_) => Ok(password),
                    Err(err) => Err(KeyStoreError::Failed {
                        msg: err.to_string(),
                    }),
                }
            }
        }
    }

    pub fn read_line(&mut self) -> Option<String> {
        let prompt = "> ";
        match self {
            Self::Interactive(editor) => editor.readline(prompt).ok(),
            Self::Automated(io) => {
                writeln!(io, "{}", prompt).ok();
                let mut line = String::new();
                match io.read_line(&mut line) {
                    Ok(0) => {
                        // EOF
                        None
                    }
                    Err(_) => None,
                    Ok(_) => Some(line),
                }
            }
        }
    }
}
