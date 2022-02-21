use super::{encryption, hd, reader, EncryptionError, KeyError, WalletError};
use encryption::{Cipher, CipherText, Salt};
use hd::KeyTree;
use mnemonic::decode;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use reader::Reader;
use reef::Ledger;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::path::PathBuf;

pub trait WalletLoader<L: Ledger> {
    type Meta; // Metadata stored in plaintext and used by the loader to access the wallet.
    fn location(&self) -> PathBuf;
    fn create(&mut self) -> Result<(Self::Meta, KeyTree), WalletError<L>>;
    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError<L>>;
}

// Metadata about a wallet which is always stored unencrypted, so we can report some basic
// information about the wallet without decrypting. This also aids in the key derivation process.
//
// DO NOT put secrets in here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoaderMetadata {
    salt: Salt,
    // Encrypted bytes from a mnemonic. This will only decrypt successfully if we have the
    // correct password, so we can use it as a quick check that the user entered the right thing.
    check_data: CipherText,
}

enum LoaderInput {
    User(Reader),
    MnemonicPasswordLiteral((Option<String>, String)),
}

impl LoaderInput {
    fn create_password<L: Ledger>(&mut self) -> Result<String, WalletError<L>> {
        match self {
            Self::User(reader) => loop {
                let password = reader.read_password("Create password: ")?;
                let confirm = reader.read_password("Retype password: ")?;
                if password == confirm {
                    return Ok(password);
                } else {
                    println!("Passwords do not match.");
                }
            },

            Self::MnemonicPasswordLiteral(s) => Ok(s.1.clone()),
        }
    }

    fn read_password<L: Ledger>(&mut self) -> Result<String, WalletError<L>> {
        match self {
            Self::User(reader) => reader.read_password("Enter password: "),
            Self::MnemonicPasswordLiteral(s) => Ok(s.1.clone()),
        }
    }

    fn create_mnemonic<L: Ledger>(
        &mut self,
        rng: &mut ChaChaRng,
    ) -> Result<String, WalletError<L>> {
        match self {
            Self::User(reader) => {
                println!(
                    "Your wallet will be identified by a secret mnemonic phrase. This phrase will \
                     allow you to recover your wallet if you lose access to it. Anyone who has access \
                     to this phrase will be able to view and spend your assets. Store this phrase in a \
                     safe, private place."
                );
                'outer: loop {
                    let (_, mnemonic) = KeyTree::random(rng).context(KeyError)?;
                    println!("Your mnemonic phrase will be:");
                    println!("{}", mnemonic);
                    'inner: loop {
                        println!("1) Accept phrase and create wallet");
                        println!("2) Generate a new phrase");
                        println!(
                            "3) Manually enter a mnemonic (use this to recover a lost wallet)"
                        );
                        match reader.read_line() {
                            Some(line) => match line.as_str().trim() {
                                "1" => return Ok(mnemonic),
                                "2" => continue 'outer,
                                "3" => {
                                    return reader.read_password("Enter mnemonic phrase: ");
                                }
                                _ => continue 'inner,
                            },
                            None => {
                                return Err(WalletError::Failed {
                                    msg: String::from("eof"),
                                })
                            }
                        }
                    }
                }
            }

            Self::MnemonicPasswordLiteral(s) => match &s.0 {
                Some(mnemonic) => Ok(mnemonic.to_string()),
                None => {
                    return Err(WalletError::Failed {
                        msg: String::from("missing mnemonic phrase"),
                    })
                }
            },
        }
    }

    fn interactive(&self) -> bool {
        match self {
            Self::User(..) => true,
            Self::MnemonicPasswordLiteral(..) => false,
        }
    }
}

pub struct Loader {
    dir: PathBuf,
    pub rng: ChaChaRng,
    input: LoaderInput,
}

impl Loader {
    pub fn new(dir: PathBuf, reader: Reader) -> Self {
        Self {
            dir,
            input: LoaderInput::User(reader),
            rng: ChaChaRng::from_entropy(),
        }
    }

    pub fn from_literal(mnemonic: Option<String>, password: String, dir: PathBuf) -> Self {
        Self {
            dir,
            input: LoaderInput::MnemonicPasswordLiteral((mnemonic, password)),
            rng: ChaChaRng::from_entropy(),
        }
    }

    pub fn into_reader(self) -> Option<Reader> {
        match self.input {
            LoaderInput::User(reader) => Some(reader),
            _ => None,
        }
    }

    fn create_from_password<L: Ledger>(&mut self) -> Result<(KeyTree, Salt), WalletError<L>> {
        let password = self.input.create_password()?;
        KeyTree::from_password(&mut self.rng, password.as_bytes()).context(KeyError)
    }

    fn load_from_password<L: Ledger>(
        &mut self,
        meta: &LoaderMetadata,
    ) -> Result<KeyTree, WalletError<L>> {
        let password = self.input.read_password()?;
        KeyTree::from_password_and_salt(password.as_bytes(), &meta.salt).context(KeyError)
    }

    fn create_from_mnemonic<L: Ledger>(
        &mut self,
    ) -> Result<(String, KeyTree, Salt), WalletError<L>> {
        let mnemonic = self.input.create_mnemonic(&mut self.rng)?;
        let (key, salt) = self.create_from_password()?;
        Ok((mnemonic, key, salt))
    }
}

static KEY_CHECK_SUB_TREE: &str = "key_check";

impl<L: Ledger> WalletLoader<L> for Loader {
    type Meta = LoaderMetadata;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(LoaderMetadata, KeyTree), WalletError<L>> {
        let (mnemonic, key, salt) = self.create_from_mnemonic()?;

        // Encrypt the mnemonic phrase, which we can decrypt on load to check the derived key.
        let mut mnemonic_bytes = Vec::<u8>::new();
        if decode(mnemonic, &mut mnemonic_bytes).is_err() | (mnemonic_bytes.len() != 32) {
            return Err(WalletError::Failed {
                msg: String::from("invalid mnemonic phrase"),
            });
        }
        let check_data = Cipher::new(
            key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
            ChaChaRng::from_rng(&mut self.rng).unwrap(),
        )
        .encrypt(&mnemonic_bytes)
        .context(EncryptionError)?;

        let meta = LoaderMetadata { salt, check_data };
        Ok((meta, key))
    }

    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError<L>> {
        let key = loop {
            // Generate the key and check that we can use it to decrypt `check_data`. If we can't,
            // the key is wrong.
            let key = self.load_from_password(meta)?;
            if Cipher::new(
                key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
                ChaChaRng::from_rng(&mut self.rng).unwrap(),
            )
            .decrypt(&meta.check_data)
            .is_ok()
            {
                break key;
            } else if self.input.interactive() {
                println!("Sorry, that's incorrect.");
            } else {
                return Err(WalletError::Failed {
                    msg: String::from("incorrect authentication"),
                });
            }
        };

        Ok(key)
    }
}
