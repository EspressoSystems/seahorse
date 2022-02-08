use crate::{io::SharedIO, WalletError};
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

    pub fn read_password<L: Ledger>(&mut self, prompt: &str) -> Result<String, WalletError<L>> {
        match self {
            Self::Interactive(_) => {
                prompt_password_stdout(prompt).map_err(|err| WalletError::Failed {
                    msg: err.to_string(),
                })
            }
            Self::Automated(io) => {
                writeln!(io, "{}", prompt).map_err(|err| WalletError::Failed {
                    msg: err.to_string(),
                })?;
                let mut password = String::new();
                match io.read_line(&mut password) {
                    Ok(_) => Ok(password),
                    Err(err) => Err(WalletError::Failed {
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
