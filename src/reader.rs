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
use crate::{io::SharedIO, KeystoreError};
use async_std::task::spawn_blocking;
use reef::Ledger;
use rpassword::prompt_password;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

pub enum Reader {
    Interactive(Arc<Mutex<rustyline::Editor<()>>>),
    Automated(SharedIO),
}

impl Clone for Reader {
    fn clone(&self) -> Self {
        match self {
            Self::Interactive(editor) => Self::Interactive(editor.clone()),
            Self::Automated(io) => Self::Automated(io.clone()),
        }
    }
}

impl Reader {
    pub fn interactive() -> Self {
        Self::Interactive(Arc::new(Mutex::new(rustyline::Editor::<()>::new())))
    }

    pub fn automated(io: SharedIO) -> Self {
        Self::Automated(io)
    }

    pub async fn read_password<L: 'static + Ledger>(
        &mut self,
        prompt: &str,
    ) -> Result<String, KeystoreError<L>> {
        let prompt = prompt.to_owned();
        match self {
            Self::Interactive(_) => {
                spawn_blocking(move || {
                    prompt_password(prompt).map_err(|err| KeystoreError::Failed {
                        msg: err.to_string(),
                    })
                })
                .await
            }
            Self::Automated(io) => {
                let mut io = io.clone();
                spawn_blocking(move || {
                    writeln!(io, "{}", prompt).map_err(|err| KeystoreError::Failed {
                        msg: err.to_string(),
                    })?;
                    let mut password = String::new();
                    match io.read_line(&mut password) {
                        Ok(_) => Ok(password),
                        Err(err) => Err(KeystoreError::Failed {
                            msg: err.to_string(),
                        }),
                    }
                })
                .await
            }
        }
    }

    pub async fn read_line(&mut self) -> Option<String> {
        let prompt = "> ";
        match self {
            Self::Interactive(editor) => {
                let editor = editor.clone();
                spawn_blocking(move || editor.lock().unwrap().readline(prompt).ok()).await
            }
            Self::Automated(io) => {
                let mut io = io.clone();
                spawn_blocking(move || {
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
                })
                .await
            }
        }
    }
}
