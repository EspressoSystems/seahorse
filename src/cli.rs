// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

////////////////////////////////////////////////////////////////////////////////
// The generic cap Wallet Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a wallet interactively.
//

use crate::{
    events::EventIndex,
    io::SharedIO,
    loader::{Loader, LoaderMetadata, WalletLoader},
    reader::Reader,
    AssetInfo, BincodeError, IoError, TransactionReceipt, TransactionStatus, WalletBackend,
    WalletError,
};
use async_std::task::block_on;
use async_trait::async_trait;
use fmt::{Display, Formatter};
use futures::future::BoxFuture;
use jf_cap::{
    keys::{AuditorKeyPair, AuditorPubKey, FreezerKeyPair, FreezerPubKey, UserKeyPair},
    proof::UniversalParam,
    structs::{AssetCode, AssetPolicy, FreezeFlag, NoteType, ReceiverMemo, RecordCommitment},
    utils::compute_universal_param_size,
};
use net::{MerklePath, UserAddress};
use reef::Ledger;
use snafu::ResultExt;
use std::any::type_name;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use tagged_base64::TaggedBase64;
use tempdir::TempDir;

pub trait CLI<'a> {
    type Ledger: 'static + Ledger;
    type Backend: 'a + WalletBackend<'a, Self::Ledger> + Send + Sync;
    type Args: CLIArgs;

    fn init_backend(
        universal_param: &'a UniversalParam,
        args: Self::Args,
        loader: &mut impl WalletLoader<Self::Ledger, Meta = LoaderMetadata>,
    ) -> Result<Self::Backend, WalletError<Self::Ledger>>;

    fn extra_commands() -> Vec<Command<'a, Self>>
    where
        Self: Sized,
    {
        vec![]
    }
}

pub trait CLIArgs {
    fn key_gen_path(&self) -> Option<PathBuf>;
    fn storage_path(&self) -> Option<PathBuf>;

    /// Override the default, terminal-based IO.
    ///
    /// If io() returns Some, the CLI will use the provided IO adapters, without interactive line
    /// editing or password input hiding. Otherwise, it will use stdin (which must be a terminal)
    /// and stdout, with interactive line editing and password hiding.
    fn io(&self) -> Option<SharedIO>;

    fn use_tmp_storage(&self) -> bool;
}

pub type Wallet<'a, C> = crate::Wallet<'a, <C as CLI<'a>>::Backend, <C as CLI<'a>>::Ledger>;

// A REPL command.
pub struct Command<'a, C: CLI<'a>> {
    // The name of the command, for display and lookup.
    pub name: String,
    // The parameters of the command and their types, as strings, for display purposes in the 'help'
    // command.
    pub params: Vec<(String, String)>,
    // The keyword parameters of the command and their types, as strings, for display purposes in
    // the 'help' command.
    pub kwargs: Vec<(String, String)>,
    // A brief description of what the command does.
    pub help: String,
    // Run the command with a list of arguments.
    pub run: CommandFunc<'a, C>,
}

pub type CommandFunc<'a, C> = Box<
    dyn Send
        + Sync
        + for<'l> Fn(
            SharedIO,
            &'l mut Wallet<'a, C>,
            Vec<String>,
            HashMap<String, String>,
        ) -> BoxFuture<'l, ()>,
>;

impl<'a, C: CLI<'a>> Display for Command<'a, C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        for (param, ty) in &self.params {
            write!(f, " {}: {}", param, ty)?;
        }
        for (param, ty) in &self.kwargs {
            write!(f, " [{}: {}]", param, ty)?;
        }
        write!(f, "\n    {}", self.help)?;
        Ok(())
    }
}

pub trait CLIInput<'a, C: CLI<'a>>: Sized {
    fn parse_for_wallet(wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self>;
}

macro_rules! cli_input_from_str {
    ($($t:ty),*) => {
        $(
            impl<'a, C: CLI<'a>> CLIInput<'a, C> for $t {
                fn parse_for_wallet(_wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self> {
                    Self::from_str(s).ok()
                }
            }
        )*
    }
}

cli_input_from_str! {
    bool, u64, String, AssetCode, AssetInfo, AuditorPubKey, FreezerPubKey, UserAddress,
    PathBuf, ReceiverMemo, RecordCommitment, MerklePath, EventIndex
}

impl<'a, C: CLI<'a>, L: Ledger> CLIInput<'a, C> for TransactionReceipt<L> {
    fn parse_for_wallet(_wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self> {
        Self::from_str(s).ok()
    }
}

// Convenience macros for panicking if output fails.
#[macro_export]
macro_rules! cli_writeln {
    ($($arg:expr),+ $(,)?) => { writeln!($($arg),+).expect("failed to write CLI output") };
}
#[macro_export]
macro_rules! cli_write {
    ($($arg:expr),+ $(,)?) => { write!($($arg),+).expect("failed to write CLI output") };
}

#[macro_export]
macro_rules! command {
    ($name:ident,
     $help:expr,
     $cli:ident,
     |$io:pat, $wallet:pat, $($arg:ident : $argty:ty),*
      $(; $($kwarg:ident : Option<$kwargty:ty>),*)?| $run:expr) => {
        Command {
            name: String::from(stringify!($name)),
            params: vec![$((
                String::from(stringify!($arg)),
                String::from(type_name::<$argty>()),
            )),*],
            kwargs: vec![$($((
                String::from(stringify!($kwarg)),
                String::from(type_name::<$kwargty>()),
            )),*)?],
            help: String::from($help),
            run: Box::new(|mut io, wallet, args, kwargs| Box::pin(async move {
                if args.len() != count!($($arg)*) {
                    cli_writeln!(io, "incorrect number of arguments (expected {})", count!($($arg)*));
                    return;
                }

                // For each (arg, ty) pair in the signature of the handler function, create a local
                // variable `arg: ty` by converting from the corresponding string in the `args`
                // vector. `args` will be unused if $($arg)* is empty, hence the following allows.
                #[allow(unused_mut)]
                #[allow(unused_variables)]
                let mut args = args.into_iter();
                $(
                    let $arg = match <$argty as CLIInput<$cli>>::parse_for_wallet(wallet, args.next().unwrap().as_str()) {
                        Some(arg) => arg,
                        None => {
                            cli_writeln!(
                                io,
                                "invalid value for argument {} (expected {})",
                                stringify!($arg),
                                type_name::<$argty>());
                            return;
                        }
                    };
                )*

                // For each (kwarg, ty) pair in the signature of the handler function, create a
                // local variable `kwarg: Option<ty>` by converting the value associated with
                // `kwarg` in `kwargs` to tye type `ty`.
                $($(
                    let $kwarg = match kwargs.get(stringify!($kwarg)) {
                        Some(val) => match <$kwargty as CLIInput<$cli>>::parse_for_wallet(wallet, val) {
                            Some(arg) => Some(arg),
                            None => {
                                cli_writeln!(
                                    io,
                                    "invalid value for argument {} (expected {})",
                                    stringify!($kwarg),
                                    type_name::<$kwargty>());
                                return;
                            }
                        }
                        None => None,
                    };
                )*)?
                // `kwargs` will be unused if there are no keyword params.
                let _ = kwargs;

                let $io = &mut io;
                let $wallet = wallet;
                $run
            }))
        }
    };

    // Don't require a comma after $wallet if there are no additional args.
    ($name:ident, $help:expr, $cli:ident, |$io:pat, $wallet:pat| $run:expr) => {
        command!($name, $help, $cli, |$io, $wallet,| $run)
    };

    // Don't require wallet at all.
    ($name:ident, $help:expr, $cli:ident, |$io:pat| $run:expr) => {
        command!($name, $help, $cli, |$io, _| $run)
    };
}

#[macro_export]
macro_rules! count {
    () => (0);
    ($x:tt $($xs:tt)*) => (1 + count!($($xs)*));
}

// Export macros as items of this module (since #[macro_export] puts them at the crate root).
pub use crate::cli_write;
pub use crate::cli_writeln;
pub use crate::command;
pub use crate::count;

// Types which can be listed in terminal output and parsed from a list index.
#[async_trait]
pub trait Listable<'a, C: CLI<'a>>: Sized {
    async fn list(wallet: &mut Wallet<'a, C>) -> Vec<ListItem<Self>>;

    fn list_sync(wallet: &mut Wallet<'a, C>) -> Vec<ListItem<Self>> {
        block_on(Self::list(wallet))
    }
}

pub struct ListItem<T> {
    pub index: usize,
    pub item: T,
    pub annotation: Option<String>,
}

impl<T: Display> Display for ListItem<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}. {}", self.index, self.item)?;
        if let Some(annotation) = &self.annotation {
            write!(f, " ({})", annotation)?;
        }
        Ok(())
    }
}

impl<'a, C: CLI<'a>, T: Listable<'a, C> + CLIInput<'a, C>> CLIInput<'a, C> for ListItem<T> {
    fn parse_for_wallet(wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self> {
        if let Ok(index) = usize::from_str(s) {
            // If the input looks like a list index, build the list for type T and get an element of
            // type T by indexing.
            let mut items = T::list_sync(wallet);
            if index < items.len() {
                Some(items.remove(index))
            } else {
                None
            }
        } else {
            // Otherwise, just parse a T directly.
            T::parse_for_wallet(wallet, s).map(|item| ListItem {
                item,
                index: 0,
                annotation: None,
            })
        }
    }
}

#[async_trait]
impl<'a, C: CLI<'a>> Listable<'a, C> for AssetCode {
    async fn list(wallet: &mut Wallet<'a, C>) -> Vec<ListItem<Self>> {
        // Get our viewing and freezing keys so we can check if the asset types are
        // viewable/freezable.
        let viewing_keys = wallet.auditor_pub_keys().await;
        let freezing_keys = wallet.freezer_pub_keys().await;

        // Get the wallet's asset library and convert to ListItems.
        wallet
            .assets()
            .await
            .into_iter()
            .enumerate()
            .map(|(index, asset)| ListItem {
                index,
                annotation: if asset.definition.code == AssetCode::native() {
                    Some(String::from("native"))
                } else {
                    // Annotate the listing with attributes indicating whether the asset is
                    // viewable, freezable, and mintable by us.
                    let mut attributes = String::new();
                    let policy = asset.definition.policy_ref();
                    if viewing_keys.contains(policy.auditor_pub_key()) {
                        attributes.push('v');
                    }
                    if freezing_keys.contains(policy.freezer_pub_key()) {
                        attributes.push('f');
                    }
                    if asset.mint_info.is_some() {
                        attributes.push('m');
                    }
                    if attributes.is_empty() {
                        None
                    } else {
                        Some(attributes)
                    }
                },
                item: asset.definition.code,
            })
            .collect()
    }
}

fn init_commands<'a, C: CLI<'a>>() -> Vec<Command<'a, C>> {
    let mut commands = C::extra_commands();
    commands.append(&mut vec![
        command!(
            address,
            "print all public addresses of this wallet",
            C,
            |io, wallet| {
                for pub_key in wallet.pub_keys().await {
                    cli_writeln!(io, "{}", UserAddress(pub_key.address()));
                }
            }
        ),
        command!(
            pub_key,
            "print all of the public keys of this wallet",
            C,
            |io, wallet| {
                for pub_key in wallet.pub_keys().await {
                    cli_writeln!(io, "{:?}", pub_key);
                }
            }
        ),
        command!(
            assets,
            "list assets known to the wallet",
            C,
            |io, wallet| {
                for item in <AssetCode as Listable<C>>::list(wallet).await {
                    cli_writeln!(io, "{}", item);
                }
                cli_writeln!(io, "(v=viewable, f=freezeable, m=mintable)");
            }
        ),
        command!(
            asset,
            "print information about an asset",
            C,
            |io, wallet, asset: ListItem<AssetCode>| {
                let asset = match wallet.asset(asset.item).await {
                    Some(asset) => asset.clone(),
                    None => {
                        cli_writeln!(io, "No such asset {}", asset.item);
                        return;
                    }
                };

                // Try to format the asset description as human-readable as possible.
                let desc = if let Some(mint_info) = &asset.mint_info {
                    mint_info.fmt_description()
                } else if asset.definition.code == AssetCode::native() {
                    String::from("Native")
                } else {
                    String::from("Asset")
                };
                cli_writeln!(io, "{} {}", desc, asset.definition.code);

                // Print the viewer, noting if it is us.
                let policy = asset.definition.policy_ref();
                if policy.is_auditor_pub_key_set() {
                    let viewing_key = policy.auditor_pub_key();
                    if wallet.auditor_pub_keys().await.contains(viewing_key) {
                        cli_writeln!(io, "Viewer: me");
                    } else {
                        cli_writeln!(io, "Viewer: {}", *viewing_key);
                    }
                } else {
                    cli_writeln!(io, "Not viewable");
                }

                // Print the freezer, noting if it is us.
                if policy.is_freezer_pub_key_set() {
                    let freezer_key = policy.freezer_pub_key();
                    if wallet.freezer_pub_keys().await.contains(freezer_key) {
                        cli_writeln!(io, "Freezer: me");
                    } else {
                        cli_writeln!(io, "Freezer: {}", *freezer_key);
                    }
                } else {
                    cli_writeln!(io, "Not freezeable");
                }

                // Print the minter, noting if it is us.
                if asset.mint_info.is_some() {
                    cli_writeln!(io, "Minter: me");
                } else if asset.definition.code == AssetCode::native() {
                    cli_writeln!(io, "Not mintable");
                } else {
                    cli_writeln!(io, "Minter: unknown");
                }
            }
        ),
        command!(
            balance,
            "print owned balances of asset",
            C,
            |io, wallet, asset: ListItem<AssetCode>| {
                cli_writeln!(io, "Address Balance");
                for pub_key in wallet.pub_keys().await {
                    cli_writeln!(
                        io,
                        "{} {}",
                        UserAddress(pub_key.address()),
                        wallet.balance(&pub_key.address(), &asset.item).await
                    );
                }
            }
        ),
        command!(
            transfer,
            "transfer some owned assets to another user",
            C,
            |io, wallet, asset: ListItem<AssetCode>, from: UserAddress, to: UserAddress, amount: u64, fee: u64; wait: Option<bool>| {
                let res = wallet.transfer(&from.0, &asset.item, &[(to.0, amount)], fee).await;
                finish_transaction::<C>(io, wallet, res, wait, "transferred").await;
            }
        ),
        command!(
            create_asset,
            "create a new asset",
            C,
            |io, wallet, desc: String; viewing_key: Option<AuditorPubKey>,
             freezing_key: Option<FreezerPubKey>, view_amount: Option<bool>,
             view_address: Option<bool>, view_blind: Option<bool>, viewing_threshold: Option<u64>|
            {
                let mut policy = AssetPolicy::default();
                if let Some(viewing_key) = viewing_key {
                    policy = policy.set_auditor_pub_key(viewing_key);
                }
                if let Some(freezing_key) = freezing_key {
                    policy = policy.set_freezer_pub_key(freezing_key);
                }
                if Some(true) == view_amount {
                    policy = match policy.reveal_amount() {
                        Ok(policy) => policy,
                        Err(err) => {
                            cli_writeln!(io, "Invalid policy: {}", err);
                            return;
                        }
                    }
                }
                if Some(true) == view_address {
                    policy = match policy.reveal_user_address() {
                        Ok(policy) => policy,
                        Err(err) => {
                            cli_writeln!(io, "Invalid policy: {}", err);
                            return;
                        }
                    }
                }
                if Some(true) == view_blind {
                    policy = match policy.reveal_blinding_factor() {
                        Ok(policy) => policy,
                        Err(err) => {
                            cli_writeln!(io, "Invalid policy: {}", err);
                            return;
                        }
                    }
                }
                if let Some(viewing_threshold) = viewing_threshold {
                    policy = policy.set_reveal_threshold(viewing_threshold);
                }
                match wallet.define_asset(desc.as_bytes(), policy).await {
                    Ok(def) => {
                        cli_writeln!(io, "{}", def.code);
                    }
                    Err(err) => {
                        cli_writeln!(io, "{}\nAsset was not created.", err);
                    }
                }
            }
        ),
        command!(
            mint,
            "mint an asset",
            C,
            |io, wallet, asset: ListItem<AssetCode>, from: UserAddress, to: UserAddress, amount: u64, fee: u64; wait: Option<bool>| {
                let res = wallet.mint(&from.0, fee, &asset.item, amount, to.0).await;
                finish_transaction::<C>(io, wallet, res, wait, "minted").await;
            }
        ),
        command!(
            freeze,
            "freeze assets owned by another users",
            C,
            |io, wallet, asset: ListItem<AssetCode>, fee_account: UserAddress, target: UserAddress,
             amount: u64, fee: u64; wait: Option<bool>|
            {
                let res = wallet.freeze(&fee_account.0, fee, &asset.item, amount, target.0).await;
                finish_transaction::<C>(io, wallet, res, wait, "frozen").await;
            }
        ),
        command!(
            unfreeze,
            "unfreeze previously frozen assets owned by another users",
            C,
            |io, wallet, asset: ListItem<AssetCode>, fee_account: UserAddress, target: UserAddress,
             amount: u64, fee: u64; wait: Option<bool>|
            {
                let res = wallet.unfreeze(&fee_account.0, fee, &asset.item, amount, target.0).await;
                finish_transaction::<C>(io, wallet, res, wait, "unfrozen").await;
            }
        ),
        command!(
            transactions,
            "list past transactions sent and received by this wallet",
            C,
            |io, wallet| {
                match wallet.transaction_history().await {
                    Ok(txns) => {
                        cli_writeln!(io, "Submitted Status Asset Type Sender Receiver Amount ...");
                        for txn in txns {
                            let status = match &txn.receipt {
                                Some(receipt) => wallet
                                    .transaction_status(receipt)
                                    .await
                                    .unwrap_or(TransactionStatus::Unknown),
                                None => {
                                    // Transaction history entries lack a receipt only if they are
                                    // received transactions from someone else. We only receive
                                    // transactions once they have been retired.
                                    TransactionStatus::Retired
                                }
                            };
                            // Try to get a readable name for the asset.
                            let asset = if txn.asset == AssetCode::native() {
                                String::from("Native")
                            } else if let Some(AssetInfo {
                                mint_info: Some(mint_info),
                                ..
                            }) = wallet.asset(txn.asset).await
                            {
                                // If the description looks like it came from a string, interpret as
                                // a string. Otherwise, encode the binary blob as tagged base64.
                                match std::str::from_utf8(&mint_info.description) {
                                    Ok(s) => String::from(s),
                                    Err(_) => TaggedBase64::new("DESC", &mint_info.description)
                                        .unwrap()
                                        .to_string(),
                                }
                            } else {
                                txn.asset.to_string()
                            };
                            let sender = match txn.sender {
                                Some(sender) => UserAddress(sender).to_string(),
                                None => String::from("unknown"),
                            };
                            cli_write!(
                                io,
                                "{} {} {} {} {} ",
                                txn.time,
                                status,
                                asset,
                                txn.kind,
                                sender
                            );
                            for (receiver, amount) in txn.receivers {
                                cli_write!(io, "{} {} ", UserAddress(receiver), amount);
                            }
                            if let Some(receipt) = txn.receipt {
                                cli_write!(io, "{}", receipt);
                            }
                            cli_writeln!(io);
                        }
                    }
                    Err(err) => cli_writeln!(io, "Error reading transaction history: {}", err),
                }
            }
        ),
        command!(
            transaction,
            "print the status of a transaction",
            C,
            |io, wallet, receipt: TransactionReceipt<C::Ledger>| {
                match wallet.transaction_status(&receipt).await {
                    Ok(status) => cli_writeln!(io, "{}", status),
                    Err(err) => cli_writeln!(io, "Error getting transaction status: {}", err),
                }
            }
        ),
        command!(
            wait,
            "wait for a transaction to complete",
            C,
            |io, wallet, receipt: TransactionReceipt<C::Ledger>| {
                match wallet.await_transaction(&receipt).await {
                    Ok(status) => cli_writeln!(io, "{}", status),
                    Err(err) => cli_writeln!(io, "Error waiting for transaction: {}", err),
                }
            }
        ),
        command!(keys, "list keys tracked by this wallet", C, |io, wallet| {
            print_keys::<C>(io, wallet).await;
        }),
        command!(
            gen_key,
            "generate new keys",
            C,
            |io, wallet, key_type: KeyType; scan_from: Option<EventIndex>, wait: Option<bool>| {
                match key_type {
                    KeyType::Viewing => match wallet.generate_audit_key().await {
                        Ok(pub_key) => cli_writeln!(io, "{}", pub_key),
                        Err(err) => cli_writeln!(io, "Error generating viewing key: {}", err),
                    },
                    KeyType::Freezing => match wallet.generate_freeze_key().await {
                        Ok(pub_key) => cli_writeln!(io, "{}", pub_key),
                        Err(err) => cli_writeln!(io, "Error generating freezing key: {}", err),
                    },
                    KeyType::Spending => match wallet.generate_user_key(scan_from).await {
                        Ok(pub_key) => {
                            if wait == Some(true) {
                                if let Err(err) = wallet.await_key_scan(&pub_key.address()).await {
                                    cli_writeln!(io, "Error waiting for key scan: {}", err);
                                }
                            }
                            cli_writeln!(io, "{}", UserAddress(pub_key.address()));
                        }
                        Err(err) => cli_writeln!(io, "Error generating spending key: {}", err),
                    },
                }
            }
        ),
        command!(
            load_key,
            "load a key from a file",
            C,
            |io, wallet, key_type: KeyType, path: PathBuf; scan_from: Option<EventIndex>, wait: Option<bool>| {
                let mut file = match File::open(path.clone()) {
                    Ok(file) => file,
                    Err(err) => {
                        cli_writeln!(io, "Error opening file {:?}: {}", path, err);
                        return;
                    }
                };
                let mut bytes = Vec::new();
                if let Err(err) = file.read_to_end(&mut bytes) {
                    cli_writeln!(io, "Error reading file: {}", err);
                    return;
                }

                match key_type {
                    KeyType::Viewing => match bincode::deserialize::<AuditorKeyPair>(&bytes) {
                        Ok(key) => match wallet.add_audit_key(key.clone()).await {
                            Ok(()) => cli_writeln!(io, "{}", key.pub_key()),
                            Err(err) => cli_writeln!(io, "Error saving viewing key: {}", err),
                        },
                        Err(err) => {
                            cli_writeln!(io, "Error loading viewing key: {}", err);
                        }
                    },
                    KeyType::Freezing => match bincode::deserialize::<FreezerKeyPair>(&bytes) {
                        Ok(key) => match wallet.add_freeze_key(key.clone()).await {
                            Ok(()) => cli_writeln!(io, "{}", key.pub_key()),
                            Err(err) => cli_writeln!(io, "Error saving freezing key: {}", err),
                        },
                        Err(err) => {
                            cli_writeln!(io, "Error loading freezing key: {}", err);
                        }
                    },
                    KeyType::Spending => match bincode::deserialize::<UserKeyPair>(&bytes) {
                        Ok(key) => match wallet.add_user_key(
                            key.clone(),
                            scan_from.unwrap_or_default(),
                        ).await {
                            Ok(()) => {
                                if wait == Some(true) {
                                    if let Err(err) = wallet.await_key_scan(&key.address()).await {
                                        cli_writeln!(io, "Error waiting for key scan: {}", err);
                                    }
                                } else {
                                    cli_writeln!(io,
                                        "Note: assets belonging to this key will become available
                                        after a scan of the ledger. This may take a long time. If
                                        you have the owner memo for a record you want to use
                                        immediately, use import_memo.");
                                    cli_writeln!(io, "{}", UserAddress(key.address()));
                                }
                            }
                            Err(err) => cli_writeln!(io, "Error saving spending key: {}", err),
                        },
                        Err(err) => {
                            cli_writeln!(io, "Error loading spending key: {}", err);
                        }
                    },
                };
            }
        ),
        command!(
            import_memo,
            "import an owner memo belonging to this wallet",
            C,
            |io,
             wallet,
             memo: ReceiverMemo,
             comm: RecordCommitment,
             uid: u64,
             proof: MerklePath| {
                if let Err(err) = wallet.import_memo(memo, comm, uid, proof.0).await {
                    cli_writeln!(io, "{}", err);
                }
            }
        ),
        command!(
            info,
            "print general information about this wallet",
            C,
            |io, wallet| {
                cli_writeln!(io, "Addresses:");
                for pub_key in wallet.pub_keys().await {
                    cli_writeln!(io, "  {}", UserAddress(pub_key.address()));
                }
                print_keys::<C>(io, wallet).await;
            }
        ),
        command!(
            view,
            "list unspent records of viewable asset types",
            C,
            |io, wallet, asset: ListItem<AssetCode>; account: Option<UserAddress>| {
                let records = wallet
                    .records()
                    .await
                    .filter(|rec| rec.ro.asset_def.code == asset.item && match &account {
                        Some(address) => rec.ro.pub_key.address() == address.0,
                        None => true
                    });

                cli_write!(io, "UID\tAMOUNT\tFROZEN");
                if account.is_none() {
                    cli_write!(io, "\tOWNER");
                }
                cli_writeln!(io);
                for record in records {
                    cli_write!(io, "{}\t{}\t{}",
                        record.uid,
                        record.ro.amount,
                        record.ro.freeze_flag == FreezeFlag::Frozen
                    );
                    if account.is_none() {
                        cli_write!(io, "\t{}", UserAddress::from(record.ro.pub_key.address()));
                    }
                    cli_writeln!(io);
                }
            }
        ),
        command!(
            import_asset,
            "import an asset type",
            C,
            |io, wallet, asset: AssetInfo| {
                if let Err(err) = wallet.import_asset(asset).await {
                    cli_writeln!(io, "Error: {}", err);
                }
            }
        ),
        // The following commands are not part of the public interface, but are used for
        // synchronization in automated CLI tests.
        #[cfg(any(test, feature = "testing"))]
        command!(
            now,
            "print the index of the latest event processed by the wallet",
            C,
            |io, wallet| {
                cli_writeln!(io, "{}", wallet.now().await);
            }
        ),
        #[cfg(any(test, feature = "testing"))]
        command!(
            sync,
            "wait until the wallet has processed up to a given event index",
            C,
            |io, wallet, t: EventIndex| {
                if let Err(err) = wallet.sync(t).await {
                    cli_writeln!(io, "Error waiting for sync point {}: {}", t, err);
                }
            }
        ),
    ]);

    commands
}

async fn print_keys<'a, C: CLI<'a>>(io: &mut SharedIO, wallet: &Wallet<'a, C>) {
    cli_writeln!(io, "Spending keys:");
    for key in wallet.pub_keys().await {
        cli_writeln!(io, "  {}", key);
    }
    cli_writeln!(io, "Viewing keys:");
    for key in wallet.auditor_pub_keys().await {
        cli_writeln!(io, "  {}", key);
    }
    cli_writeln!(io, "Freezing keys:");
    for key in wallet.freezer_pub_keys().await {
        cli_writeln!(io, "  {}", key);
    }
}

pub enum KeyType {
    Viewing,
    Freezing,
    Spending,
}

impl<'a, C: CLI<'a>> CLIInput<'a, C> for KeyType {
    fn parse_for_wallet(_wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self> {
        match s {
            "view" | "viewing" => Some(Self::Viewing),
            "freeze" | "freezing" => Some(Self::Freezing),
            "spend" | "spending" => Some(Self::Spending),
            _ => None,
        }
    }
}

pub async fn finish_transaction<'a, C: CLI<'a>>(
    io: &mut SharedIO,
    wallet: &Wallet<'a, C>,
    result: Result<TransactionReceipt<C::Ledger>, WalletError<C::Ledger>>,
    wait: Option<bool>,
    success_state: &str,
) {
    match result {
        Ok(receipt) => {
            if wait == Some(true) {
                match wallet.await_transaction(&receipt).await {
                    Err(err) => {
                        cli_writeln!(io, "Error waiting for transaction to complete: {}", err);
                    }
                    Ok(TransactionStatus::Retired) => {
                        cli_writeln!(io, "Assets successfully {}", success_state);
                    }
                    _ => {
                        cli_writeln!(io, "Transaction failed. Assets were not {}", success_state);
                    }
                }
            } else {
                cli_writeln!(io, "{}", receipt);
            }
        }
        Err(err) => {
            cli_writeln!(io, "{}\nAssets were not {}.", err, success_state);
        }
    }
}

pub async fn cli_main<'a, L: 'static + Ledger, C: CLI<'a, Ledger = L>>(
    args: C::Args,
) -> Result<(), WalletError<L>> {
    if let Some(path) = args.key_gen_path() {
        key_gen::<C>(path)
    } else {
        repl::<L, C>(args).await
    }
}

pub fn key_gen<'a, C: CLI<'a>>(mut path: PathBuf) -> Result<(), WalletError<C::Ledger>> {
    let key_pair = crate::new_key_pair();

    let mut file = File::create(path.clone()).context(IoError)?;
    let bytes = bincode::serialize(&key_pair).context(BincodeError)?;
    file.write_all(&bytes).context(IoError)?;

    path.set_extension("pub");
    let mut file = File::create(path).context(IoError)?;
    let bytes = bincode::serialize(&key_pair.pub_key()).context(BincodeError)?;
    file.write_all(&bytes).context(IoError)?;

    Ok(())
}

async fn repl<'a, L: 'static + Ledger, C: CLI<'a, Ledger = L>>(
    args: C::Args,
) -> Result<(), WalletError<L>> {
    let (storage, _tmp_dir) = match args.storage_path() {
        Some(storage) => (storage, None),
        None if !args.use_tmp_storage() => {
            let home = std::env::var("HOME").map_err(|_| WalletError::Failed {
                msg: String::from(
                    "HOME directory is not set. Please set your HOME directory, or specify \
                        a different storage location using --storage.",
                ),
            })?;
            let mut dir = PathBuf::from(home);
            dir.push(format!(
                ".espresso/{}/wallet",
                L::name()
                    .to_lowercase()
                    .replace('/', "_")
                    .replace('\\', "_")
            ));
            (dir, None)
        }
        None => {
            let tmp_dir = TempDir::new("wallet").context(IoError)?;
            (PathBuf::from(tmp_dir.path()), Some(tmp_dir))
        }
    };

    let (mut io, reader) = match args.io() {
        Some(io) => (io.clone(), Reader::automated(io)),
        None => (SharedIO::std(), Reader::interactive()),
    };
    cli_writeln!(
        io,
        "Welcome to the {} wallet, version {}",
        C::Ledger::name(),
        env!("CARGO_PKG_VERSION")
    );
    cli_writeln!(io, "(c) 2021 Espresso Systems, Inc.");

    let mut loader = Loader::new(storage, reader);

    let max_degree = compute_universal_param_size(NoteType::Transfer, 3, 3, L::merkle_height())
        .unwrap_or_else(|err| {
            panic!(
                "Error while computing the universal parameter size for Transfer: {}",
                err
            )
        });
    // NOTE: since we are currently using fresh SRS (instead of from proper SRS from MPC
    // ceremony), and deserializing takes longer than generating new SRS, we choose to
    // generate new one instead of storing and reading from files.
    // TODO: (alex) use proper SRS for production
    let universal_param = Box::leak(Box::new(
        jf_cap::proof::universal_setup(max_degree, &mut loader.rng)
            .unwrap_or_else(|err| panic!("Error while generating universal param: {}", err)),
    ));

    // Alternatively, here's how you would store and load SRS from files:
    // // generate and store SRS in default path
    // store_universal_parameter_for_demo(max_degree, None);
    // let universal_param = Box::leak(Box::new(
    //     jf_cap::parameters::load_universal_parameter(None)
    //         .unwrap_or_else(|err| panic!("Error while loading universal param from file: {}", err)),
    // ));

    let backend = C::init_backend(universal_param, args, &mut loader)?;

    // Loading the wallet takes a while. Let the user know that's expected.
    //todo !jeb.bearer Make it faster
    cli_writeln!(io, "connecting...");
    let mut wallet = Wallet::<C>::new(backend).await?;
    cli_writeln!(io, "Type 'help' for a list of commands.");
    let commands = init_commands::<C>();

    let mut input = loader.into_reader().unwrap();
    'repl: while let Some(line) = input.read_line() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }
        if tokens[0] == "help" {
            for command in commands.iter() {
                cli_writeln!(io, "{}", command);
            }
            continue;
        }
        for Command { name, run, .. } in commands.iter() {
            if name == tokens[0] {
                let mut args = Vec::new();
                let mut kwargs = HashMap::new();
                for tok in tokens.into_iter().skip(1) {
                    if let Some((key, value)) = tok.split_once('=') {
                        kwargs.insert(String::from(key), String::from(value));
                    } else {
                        args.push(String::from(tok));
                    }
                }
                run(io.clone(), &mut wallet, args, kwargs).await;
                continue 'repl;
            }
        }
        cli_writeln!(
            io,
            "Unknown command. Type 'help' for a list of valid commands."
        );
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        hd,
        io::Tee,
        testing::{
            cli_match::*,
            mocks::{MockBackend, MockLedger, MockNetwork, MockStorage, MockSystem},
            SystemUnderTest,
        },
    };
    use async_std::{
        sync::{Arc, Mutex},
        task::spawn,
    };
    use futures::stream::{iter, StreamExt};
    use jf_cap::structs::{AssetCodeSeed, AssetDefinition};
    use pipe::{PipeReader, PipeWriter};
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    use reef::cap;
    use std::time::Instant;

    type MockCapLedger<'a> =
        Arc<Mutex<MockLedger<'a, cap::Ledger, MockNetwork<'a>, MockStorage<'a>>>>;

    struct MockArgs<'a> {
        io: SharedIO,
        key_stream: hd::KeyTree,
        ledger: MockCapLedger<'a>,
    }

    impl<'a> CLIArgs for MockArgs<'a> {
        fn key_gen_path(&self) -> Option<PathBuf> {
            None
        }

        fn storage_path(&self) -> Option<PathBuf> {
            None
        }

        fn io(&self) -> Option<SharedIO> {
            Some(self.io.clone())
        }

        fn use_tmp_storage(&self) -> bool {
            true
        }
    }

    struct MockCLI;

    impl<'a> CLI<'a> for MockCLI {
        type Ledger = cap::Ledger;
        type Backend = MockBackend<'a>;
        type Args = MockArgs<'a>;

        fn init_backend(
            _universal_param: &'a UniversalParam,
            args: Self::Args,
            _loader: &mut impl WalletLoader<Self::Ledger, Meta = LoaderMetadata>,
        ) -> Result<Self::Backend, WalletError<Self::Ledger>> {
            Ok(MockBackend::new(
                args.ledger.clone(),
                Default::default(),
                args.key_stream,
            ))
        }
    }

    async fn create_network<'a>(
        t: &mut MockSystem,
        initial_grants: &[u64],
    ) -> (MockCapLedger<'a>, Vec<hd::KeyTree>) {
        // Use `create_test_network` to create a ledger with some initial records.
        let (ledger, wallets) = t
            .create_test_network(&[(3, 3)], initial_grants.to_vec(), &mut Instant::now())
            .await;
        // Set `block_size` to `1` so we don't have to explicitly flush the ledger after each
        // transaction submission.
        ledger.lock().await.set_block_size(1).unwrap();
        // We don't actually care about the open wallets returned by `create_test_network`, because
        // the CLI does its own wallet loading. But we do want to get their key streams, so that
        // the wallets we create through the CLI can deterministically generate the keys that own
        // the initial records.
        let key_streams = iter(wallets)
            .then(|(wallet, _)| async move { wallet.lock().await.backend().key_stream() })
            .collect::<Vec<_>>()
            .await;
        (ledger, key_streams)
    }

    fn create_wallet(
        ledger: MockCapLedger<'static>,
        key_stream: hd::KeyTree,
    ) -> (Tee<PipeWriter>, Tee<PipeReader>) {
        let (io, input, output) = SharedIO::pipe();

        // Run a CLI interface for a wallet in the background.
        spawn(async move {
            let args = MockArgs {
                io,
                key_stream,
                ledger,
            };
            cli_main::<cap::Ledger, MockCLI>(args).await.unwrap();
        });

        // Wait for the CLI to start up and then return the input and output pipes.
        let input = Tee::new(input);
        let mut output = Tee::new(output);
        wait_for_prompt(&mut output);
        (input, output)
    }

    #[async_std::test]
    async fn test_view_freeze() {
        let mut t = MockSystem::default();
        let (ledger, key_streams) = create_network(&mut t, &[1000, 1000, 0]).await;

        // Create three wallet clients: one to mint and view an asset, one to make an anonymous
        // transfer, and one to receive an anonymous transfer. We will see if the viewer can
        // discover the output record of the anonymous transfer, in which it is not a participant.
        let (mut viewer_input, mut viewer_output) =
            create_wallet(ledger.clone(), key_streams[0].clone());
        let (mut sender_input, mut sender_output) =
            create_wallet(ledger.clone(), key_streams[1].clone());
        let (mut receiver_input, mut receiver_output) =
            create_wallet(ledger, key_streams[2].clone());

        // Get the viewer's funded address.
        writeln!(viewer_input, "gen_key spending scan_from=start wait=true").unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<addr>ADDR~.*)"]);
        let viewer_address = matches.get("addr");
        writeln!(viewer_input, "balance 0").unwrap();
        match_output(
            &mut viewer_output,
            &[format!("{} {}", viewer_address, 1000)],
        );

        // Get the sender's funded address.
        writeln!(sender_input, "gen_key spending scan_from=start wait=true").unwrap();
        let matches = match_output(&mut sender_output, &["(?P<addr>ADDR~.*)"]);
        let sender_address = matches.get("addr");
        writeln!(sender_input, "balance 0").unwrap();
        match_output(
            &mut sender_output,
            &[format!("{} {}", sender_address, 1000)],
        );

        // Get the receiver's (unfunded) address.
        writeln!(receiver_input, "gen_key spending").unwrap();
        let matches = match_output(&mut receiver_output, &["(?P<addr>ADDR~.*)"]);
        let receiver_address = matches.get("addr");

        // Generate a viewing key.
        writeln!(viewer_input, "gen_key viewing").unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<view_key>AUDPUBKEY~.*)"]);
        let view_key = matches.get("view_key");
        // Currently we only view assets that we can freeze, so we need a freeze key.
        writeln!(viewer_input, "gen_key freezing").unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<freeze_key>FREEZEPUBKEY~.*)"]);
        let freeze_key = matches.get("freeze_key");
        // Define an auditable asset.
        writeln!(
            viewer_input,
            "create_asset my_asset viewing_key={} freezing_key={} view_amount=true view_address=true view_blind=true",
            view_key, freeze_key
        )
        .unwrap();
        wait_for_prompt(&mut viewer_output);
        // Mint some of the asset on behalf of `sender` (the asset has numeric code 1, since the
        // native asset is always 0).
        writeln!(
            viewer_input,
            "mint 1 {} {} 1000 1",
            viewer_address, sender_address
        )
        .unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<txn>TXN~.*)"]);
        let receipt = matches.get("txn");
        await_transaction(
            &receipt,
            (&mut viewer_input, &mut viewer_output),
            &mut [(&mut sender_input, &mut sender_output)],
        );
        writeln!(sender_input, "balance 1").unwrap();
        match_output(&mut sender_output, &[format!("{} 1000", sender_address)]);

        // Make an anonymous transfer that doesn't involve the viewer (so we can check that the
        // viewer nonetheless discovers the details of the transaction).
        writeln!(
            sender_input,
            "transfer 1 {} {} 50 1",
            sender_address, receiver_address
        )
        .unwrap();
        let matches = match_output(&mut sender_output, &["(?P<txn>TXN~.*)"]);
        let receipt = matches.get("txn");
        await_transaction(
            &receipt,
            (&mut sender_input, &mut sender_output),
            &mut [
                (&mut receiver_input, &mut receiver_output),
                (&mut viewer_input, &mut viewer_output),
            ],
        );

        // View the transaction. We should find two unspent records: first the amount-50 transaction
        // output, and second the amount-950 change output. These records have UIDs 5 and 6, because
        // we already have 5 records: 3 initial grants, a mint output, and a mint fee change record.
        writeln!(viewer_input, "view 1").unwrap();
        match_output(
            &mut viewer_output,
            &[
                "^UID\\s+AMOUNT\\s+FROZEN\\s+OWNER$",
                format!("^5\\s+50\\s+false\\s+{}$", receiver_address).as_str(),
                format!("^6\\s+950\\s+false\\s+{}$", sender_address).as_str(),
            ],
        );
        // Filter by account.
        writeln!(viewer_input, "view 1 account={}", receiver_address).unwrap();
        match_output(
            &mut viewer_output,
            &["^UID\\s+AMOUNT\\s+FROZEN$", "^5\\s+50\\s+false$"],
        );
        writeln!(viewer_input, "view 1 account={}", sender_address).unwrap();
        match_output(
            &mut viewer_output,
            &["^UID\\s+AMOUNT\\s+FROZEN$", "^6\\s+950\\s+false$"],
        );

        // If we can see the record openings and we hold the freezer key, we should be able to
        // freeze them.
        writeln!(
            viewer_input,
            "freeze 1 {} {} 950 1",
            viewer_address, sender_address
        )
        .unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<txn>TXN~.*)"]);
        let receipt = matches.get("txn");
        await_transaction(
            &receipt,
            (&mut viewer_input, &mut viewer_output),
            &mut [(&mut sender_input, &mut sender_output)],
        );
        writeln!(viewer_input, "view 1").unwrap();
        // Note that the UID changes after freezing, because the freeze consume the unfrozen record
        // and creates a new frozen one.
        match_output(
            &mut viewer_output,
            &[
                "^UID\\s+AMOUNT\\s+FROZEN\\s+OWNER$",
                format!("^5\\s+50\\s+false\\s+{}$", receiver_address).as_str(),
                format!("^8\\s+950\\s+true\\s+{}$", sender_address).as_str(),
            ],
        );

        // Transfers that need the frozen record as an input should now fail.
        writeln!(
            sender_input,
            "transfer 1 {} {} 50 1",
            sender_address, receiver_address
        )
        .unwrap();
        // Search for error message with a slightly permissive regex to allow the CLI some freedom
        // in reporting a readable error.
        match_output(&mut sender_output, &["[Ii]nsufficient.*[Bb]alance"]);

        // Unfreezing the record makes it available again.
        writeln!(
            viewer_input,
            "unfreeze 1 {} {} 950 1",
            viewer_address, sender_address
        )
        .unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<txn>TXN~.*)"]);
        let receipt = matches.get("txn");
        await_transaction(
            &receipt,
            (&mut viewer_input, &mut viewer_output),
            &mut [(&mut sender_input, &mut sender_output)],
        );
        writeln!(viewer_input, "view 1").unwrap();
        match_output(
            &mut viewer_output,
            &[
                "^UID\\s+AMOUNT\\s+FROZEN\\s+OWNER$",
                format!("^5\\s+50\\s+false\\s+{}$", receiver_address).as_str(),
                format!("^10\\s+950\\s+false\\s+{}$", sender_address).as_str(),
            ],
        );
    }

    #[async_std::test]
    async fn test_import_asset() {
        let mut rng = ChaChaRng::from_seed([38; 32]);
        let seed = AssetCodeSeed::generate(&mut rng);
        let code = AssetCode::new_domestic(seed, "my_asset".as_bytes());
        let definition = AssetDefinition::new(code, AssetPolicy::default()).unwrap();

        let mut t = MockSystem::default();
        let (ledger, key_streams) = create_network(&mut t, &[0]).await;
        let (mut input, mut output) = create_wallet(ledger.clone(), key_streams[0].clone());

        // Load without mint info.
        writeln!(input, "import_asset definition:{}", definition).unwrap();
        wait_for_prompt(&mut output);
        writeln!(input, "asset {}", definition.code).unwrap();
        match_output(
            &mut output,
            &[
                format!("Asset {}", definition.code).as_str(),
                "Not viewable",
                "Not freezeable",
                "Minter: unknown",
            ],
        );

        // Update later with mint info.
        writeln!(
            input,
            "import_asset definition:{},seed:{},description:my_asset",
            definition, seed
        )
        .unwrap();
        wait_for_prompt(&mut output);
        // Asset 0 is the native asset, ours is asset 1.
        writeln!(input, "asset 1").unwrap();
        match_output(
            &mut output,
            &["my_asset", "Not viewable", "Not freezeable", "Minter: me"],
        );

        // Make sure the asset was only loaded once (the second command should have updated the
        // original instance).
        writeln!(input, "asset 2").unwrap();
        match_output(&mut output, &["invalid value for argument asset"]);
    }
}
