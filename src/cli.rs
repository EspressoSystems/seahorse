// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The generic CAP Keystore frontend
//!
//! This module "frontend" provides a framework for implementing command line interfaces for
//! ledger-specific instantiations of the [Keystore] type. Similar to the [Keystore] framework itself,
//! there is are traits which must be implemented to adapt this framework to a particular ledger
//! type, after which the implementor gains access to the full Seahorse CLI implementation.
//!
//! The [CLI] trait must be implemented for a particular ledger type and [KeystoreBackend]
//! implementation. In addition, the [CLIArgs] trait must be implemented to map your command line
//! arguments to the options and flags required by the general CLI implementation. After that,
//! [cli_main] can be used to run the CLI interactively.
use crate::{
    assets::Asset, events::EventIndex, io::SharedIO, loader::KeystoreLoader, reader::Reader,
    txn_builder::TransactionReceipt, BincodeSnafu, IoSnafu, KeystoreBackend, KeystoreError,
    RecordAmount, TransactionStatus,
};
use async_std::task::block_on;
use async_trait::async_trait;
use fmt::{Display, Formatter};
use futures::future::BoxFuture;
use jf_cap::{
    keys::{FreezerKeyPair, FreezerPubKey, UserKeyPair, ViewerKeyPair, ViewerPubKey},
    proof::UniversalParam,
    structs::{AssetCode, AssetPolicy, FreezeFlag, ReceiverMemo, RecordCommitment},
};
use net::{MerklePath, UserAddress, UserPubKey};
use primitive_types::U256;
use reef::Ledger;
use serde::{de::DeserializeOwned, Serialize};
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

/// The interface required of a particular ledger-specific instantiation.
#[async_trait]
pub trait CLI<'a> {
    /// The ledger for which we want to instantiate this CLI.
    type Ledger: 'static + Ledger;
    /// The [KeystoreBackend] implementation to use for the keystore.
    type Backend: 'a + KeystoreBackend<'a, Self::Ledger> + Send + Sync;
    /// The [KeystoreLoader] implementation to use to create or load the keystore.
    type Loader: KeystoreLoader<Self::Ledger, Meta = Self::Meta>;
    /// The type of metadata used by [Self::Loader].
    type Meta: 'a + Send + Serialize + DeserializeOwned + Clone + PartialEq;
    /// The type of command line options for use when configuring the CLI.
    type Args: CLIArgs;

    /// Create a backend for the keystore which is being controlled by the CLI.
    async fn init_backend(
        universal_param: &'a UniversalParam,
        args: Self::Args,
    ) -> Result<Self::Backend, KeystoreError<Self::Ledger>>;

    /// Create a loader in order to create or load a new keystore for the CLI.
    async fn init_loader(
        storage: PathBuf,
        input: Reader,
    ) -> Result<Self::Loader, KeystoreError<Self::Ledger>>;

    /// Add extra, ledger-specific commands to the generic CLI interface.
    ///
    /// This method is optional. By default it returns an empty list, in which case the CLI
    /// instantiation will still provide commands for all of the basic, ledger-agnostic keystore
    /// functionality.
    fn extra_commands() -> Vec<Command<'a, Self>>
    where
        Self: Sized,
    {
        vec![]
    }
}

/// CLI command line arguments.
pub trait CLIArgs {
    /// If specified, do not run the REPl, only generate a key pair in the given file.
    fn key_gen_path(&self) -> Option<PathBuf>;

    /// Path to use for the keystore's persistent storage.
    ///
    /// If not provided, the default path, `~/.espresso/<ledger-name>/keystore`, will be used.
    fn storage_path(&self) -> Option<PathBuf>;

    /// Override the default, terminal-based IO.
    ///
    /// If this method returns [Some], the CLI will use the provided IO adapters, without
    /// interactive line editing or password input hiding. Otherwise, it will use stdin (which must
    /// be a terminal) and stdout, with interactive line editing and password hiding.
    fn io(&self) -> Option<SharedIO>;

    /// If `true`, create a temporary directory for storage instead of using [CLIArgs::storage_path].
    fn use_tmp_storage(&self) -> bool;
}

pub type Keystore<'a, C> =
    crate::Keystore<'a, <C as CLI<'a>>::Backend, <C as CLI<'a>>::Ledger, <C as CLI<'a>>::Meta>;

/// A REPL command.
///
/// This struct can be created manually, but it is easier to use the [command!] macro, which
/// automatically parses a function specification to create the documentation for command
/// parameters.
pub struct Command<'a, C: CLI<'a>> {
    /// The name of the command, for display and lookup.
    pub name: String,
    /// The parameters of the command and their types, as strings, for display purposes in the
    /// `help` command.
    pub params: Vec<(String, String)>,
    /// The keyword parameters of the command and their types, as strings, for display purposes in
    /// the `help` command.
    pub kwargs: Vec<(String, String)>,
    /// A brief description of what the command does.
    pub help: String,
    /// Run the command with a list of arguments.
    pub run: CommandFunc<'a, C>,
}

pub type CommandFunc<'a, C> = Box<
    dyn Send
        + Sync
        + for<'l> Fn(
            SharedIO,
            &'l mut Keystore<'a, C>,
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

/// Types which can be parsed from a string relative to a particular [Keystore].Stream
pub trait CLIInput<'a, C: CLI<'a>>: Sized {
    fn parse_for_keystore(keystore: &mut Keystore<'a, C>, s: &str) -> Option<Self>;
}

macro_rules! cli_input_from_str {
    ($($t:ty),*) => {
        $(
            impl<'a, C: CLI<'a>> CLIInput<'a, C> for $t {
                fn parse_for_keystore(_keystore: &mut Keystore<'a, C>, s: &str) -> Option<Self> {
                    Self::from_str(s).ok()
                }
            }
        )*
    }
}

cli_input_from_str! {
    bool, u64, Asset, AssetCode, EventIndex, FreezerPubKey, MerklePath, PathBuf, ReceiverMemo,
    RecordAmount, RecordCommitment, String, UserAddress, UserPubKey, ViewerPubKey
}

impl<'a, C: CLI<'a>, L: Ledger> CLIInput<'a, C> for TransactionReceipt<L> {
    fn parse_for_keystore(_keystore: &mut Keystore<'a, C>, s: &str) -> Option<Self> {
        Self::from_str(s).ok()
    }
}

// Annoyingly, FromStr for U256 always interprets the input as hex. This implementation checks for a
// 0x prefix. If present, it interprets the remainder of the string as hex, otherwise it interprets
// the entire string as decimal.
impl<'a, C: CLI<'a>> CLIInput<'a, C> for U256 {
    fn parse_for_keystore(_wallet: &mut Keystore<'a, C>, s: &str) -> Option<Self> {
        if s.starts_with("0x") {
            s.parse().ok()
        } else {
            U256::from_dec_str(s).ok()
        }
    }
}

/// Convenience macro for panicking if output fails.
#[macro_export]
macro_rules! cli_writeln {
    ($($arg:expr),+ $(,)?) => { writeln!($($arg),+).expect("failed to write CLI output") };
}
/// Convenience macro for panicking if output fails.
#[macro_export]
macro_rules! cli_write {
    ($($arg:expr),+ $(,)?) => { write!($($arg),+).expect("failed to write CLI output") };
}

/// Create a [Command] from a help string and a function.
#[macro_export]
macro_rules! command {
    ($name:ident,
     $help:expr,
     $cli:ident,
     |$io:pat, $keystore:pat, $($arg:ident : $argty:ty),*
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
            run: Box::new(|mut io, keystore, args, kwargs| Box::pin(async move {
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
                    let $arg = match <$argty as CLIInput<$cli>>::parse_for_keystore(keystore, args.next().unwrap().as_str()) {
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
                        Some(val) => match <$kwargty as CLIInput<$cli>>::parse_for_keystore(keystore, val) {
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
                let $keystore = keystore;
                $run
            }))
        }
    };

    // Don't require a comma after $keystore if there are no additional args.
    ($name:ident, $help:expr, $cli:ident, |$io:pat, $keystore:pat| $run:expr) => {
        command!($name, $help, $cli, |$io, $keystore,| $run)
    };

    // Don't require keystore at all.
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

/// Types which can be listed in terminal output and parsed from a list index.
#[async_trait]
pub trait Listable<'a, C: CLI<'a>>: Sized {
    async fn list(keystore: &mut Keystore<'a, C>) -> Vec<ListItem<Self>>;

    fn list_sync(keystore: &mut Keystore<'a, C>) -> Vec<ListItem<Self>> {
        block_on(Self::list(keystore))
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
    fn parse_for_keystore(keystore: &mut Keystore<'a, C>, s: &str) -> Option<Self> {
        if let Ok(index) = usize::from_str(s) {
            // If the input looks like a list index, build the list for type T and get an element of
            // type T by indexing.
            let mut items = T::list_sync(keystore);
            if index < items.len() {
                Some(items.remove(index))
            } else {
                None
            }
        } else {
            // Otherwise, just parse a T directly.
            T::parse_for_keystore(keystore, s).map(|item| ListItem {
                item,
                index: 0,
                annotation: None,
            })
        }
    }
}

#[async_trait]
impl<'a, C: CLI<'a>> Listable<'a, C> for AssetCode {
    async fn list(keystore: &mut Keystore<'a, C>) -> Vec<ListItem<Self>> {
        // Get our viewing and freezing keys so we can check if the asset types are
        // viewable/freezable.
        let viewing_keys = keystore.viewer_pub_keys().await;
        let freezing_keys = keystore.freezer_pub_keys().await;

        // Get the keystore's asset library and convert to ListItems.
        keystore
            .assets()
            .await
            .into_iter()
            .enumerate()
            .map(|(index, asset)| ListItem {
                index,
                annotation: if asset.definition().code == AssetCode::native() {
                    Some(String::from("native"))
                } else {
                    // Annotate the listing with attributes indicating whether the asset is
                    // viewable, freezable, and mintable by us.
                    let mut attributes = String::new();
                    let policy = asset.definition().policy_ref();
                    if viewing_keys.contains(policy.viewer_pub_key()) {
                        attributes.push('v');
                    }
                    if freezing_keys.contains(policy.freezer_pub_key()) {
                        attributes.push('f');
                    }
                    if asset.mint_info().is_some() {
                        attributes.push('m');
                    }
                    if attributes.is_empty() {
                        None
                    } else {
                        Some(attributes)
                    }
                },
                item: asset.definition().code,
            })
            .collect()
    }
}

fn init_commands<'a, C: CLI<'a>>() -> Vec<Command<'a, C>> {
    let mut commands = C::extra_commands();
    commands.append(&mut vec![
        command!(
            address,
            "print all public addresses of this keystore",
            C,
            |io, keystore| {
                for pub_key in keystore.pub_keys().await {
                    cli_writeln!(io, "{}", UserAddress(pub_key.address()));
                }
            }
        ),
        command!(
            pub_key,
            "print all of the public keys of this keystore",
            C,
            |io, keystore| {
                for pub_key in keystore.pub_keys().await {
                    cli_writeln!(io, "{:?}", pub_key);
                }
            }
        ),
        command!(
            assets,
            "list assets known to the keystore",
            C,
            |io, keystore| {
                for item in <AssetCode as Listable<C>>::list(keystore).await {
                    cli_writeln!(io, "{}", item);
                }
                cli_writeln!(io, "(v=viewable, f=freezeable, m=mintable)");
            }
        ),
        command!(
            asset,
            "print information about an asset",
            C,
            |io, keystore, asset: ListItem<AssetCode>| {
                let asset = match keystore.asset(asset.item).await {
                    Some(asset) => asset.clone(),
                    None => {
                        cli_writeln!(io, "No such asset {}", asset.item);
                        return;
                    }
                };

                // Try to format the asset description as human-readable as possible.
                let desc = if let Some(mint_info) = &asset.mint_info() {
                    mint_info.fmt_description()
                } else if asset.definition().code == AssetCode::native() {
                    String::from("Native")
                } else {
                    String::from("Asset")
                };
                cli_writeln!(io, "{} {}", desc, asset.definition().code);

                // Print the viewer, noting if it is us.
                let policy = asset.definition().policy_ref();
                if policy.is_viewer_pub_key_set() {
                    let viewing_key = policy.viewer_pub_key();
                    if keystore.viewer_pub_keys().await.contains(viewing_key) {
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
                    if keystore.freezer_pub_keys().await.contains(freezer_key) {
                        cli_writeln!(io, "Freezer: me");
                    } else {
                        cli_writeln!(io, "Freezer: {}", *freezer_key);
                    }
                } else {
                    cli_writeln!(io, "Not freezeable");
                }

                // Print the minter, noting if it is us.
                if asset.mint_info().is_some() {
                    cli_writeln!(io, "Minter: me");
                } else if asset.definition().code == AssetCode::native() {
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
            |io, keystore, asset: ListItem<AssetCode>| {
                cli_writeln!(io, "Address Balance");
                for pub_key in keystore.pub_keys().await {
                    cli_writeln!(
                        io,
                        "{} {}",
                        UserAddress(pub_key.address()),
                        keystore.balance_breakdown(&pub_key.address(), &asset.item).await
                    );
                }
                cli_writeln!(
                    io,
                    "Total {}",
                    keystore.balance(&asset.item).await
                );
            }
        ),
        command!(
            transfer,
            "transfer some owned assets to another user's public key",
            C,
            |io, keystore, asset: ListItem<AssetCode>, to: UserPubKey, amount: RecordAmount, fee: RecordAmount;
             from: Option<UserAddress>, wait: Option<bool>| {
                let res = keystore.transfer(from.as_ref().map(|addr| &addr.0), &asset.item, &[(to, amount)], fee).await;
                finish_transaction::<C>(io, keystore, res, wait, "transferred").await;
            }
        ),
        command!(
            create_asset,
            "create a new asset",
            C,
            |io, keystore, desc: String; name: Option<String>, viewing_key: Option<ViewerPubKey>,
             freezing_key: Option<FreezerPubKey>, view_amount: Option<bool>,
             view_address: Option<bool>, view_blind: Option<bool>, viewing_threshold: Option<RecordAmount>|
            {
                let mut policy = AssetPolicy::default();
                if let Some(viewing_key) = viewing_key {
                    policy = policy.set_viewer_pub_key(viewing_key);
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
                    policy = policy.set_reveal_threshold(viewing_threshold.into());
                }
                match keystore.define_asset(name.unwrap_or_default(), desc.as_bytes(), policy).await {
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
            "mint an asset from an owned address to a user's public key",
            C,
            |io, keystore, asset: ListItem<AssetCode>, to: UserPubKey, amount: RecordAmount, fee: RecordAmount;
             fee_account: Option<UserAddress>, wait: Option<bool>| {
                let res = keystore.mint(fee_account.as_ref().map(|addr| &addr.0), fee, &asset.item, amount, to).await;
                finish_transaction::<C>(io, keystore, res, wait, "minted").await;
            }
        ),
        command!(
            freeze,
            "freeze assets owned by another user's address",
            C,
            |io, keystore, asset: ListItem<AssetCode>, target: UserAddress, amount: U256, fee: RecordAmount;
             fee_account: Option<UserAddress>, wait: Option<bool>|
            {
                let res = keystore.freeze(fee_account.as_ref().map(|addr| &addr.0), fee, &asset.item, amount, target.0).await;
                finish_transaction::<C>(io, keystore, res, wait, "frozen").await;
            }
        ),
        command!(
            unfreeze,
            "unfreeze previously frozen assets owned by another user's address",
            C,
            |io, keystore, asset: ListItem<AssetCode>, target: UserAddress, amount: U256, fee: RecordAmount;
             fee_account: Option<UserAddress>, wait: Option<bool>|
            {
                let res = keystore.unfreeze(fee_account.as_ref().map(|addr| &addr.0), fee, &asset.item, amount, target.0).await;
                finish_transaction::<C>(io, keystore, res, wait, "unfrozen").await;
            }
        ),
        command!(
            transactions,
            "list past transactions sent and received by this keystore",
            C,
            |io, keystore| {
                match keystore.transaction_history().await {
                    Ok(txns) => {
                        cli_writeln!(io, "Submitted Status Asset Type Sender Receiver Amount ...");
                        for txn in txns {
                            let status = match &txn.receipt() {
                                Some(receipt) => keystore
                                    .transaction_status(&receipt.uid)
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
                            let asset = if *txn.asset() == AssetCode::native() {
                                String::from("Native")
                            } else if let Some(asset) = keystore
                                .asset(*txn.asset())
                                .await
                            {
                                if let Some(mint_info) = asset.mint_info() {
                                    // If the description looks like it came from a string, interpret as
                                    // a string. Otherwise, encode the binary blob as tagged base64.
                                    match std::str::from_utf8(&mint_info.description) {
                                        Ok(s) => String::from(s),
                                        Err(_) => TaggedBase64::new("DESC", &mint_info.description)
                                            .unwrap()
                                            .to_string(),
                                    }
                                } else {
                                    txn.asset().to_string()
                                }
                            } else {
                                txn.asset().to_string()
                            };
                            let senders = if !txn.senders().is_empty() {
                                txn.senders()
                                    .iter()
                                    .map(|sender| UserAddress(sender.clone()).to_string())
                                    .collect::<Vec<String>>()
                            } else {
                                vec![String::from("unknown")]
                            };
                            cli_write!(
                                io,
                                "{} {} {} {} {:?} ",
                                txn.time(),
                                status,
                                asset,
                                txn.kind(),
                                senders
                            );
                            for (receiver, amount) in txn.receivers() {
                                cli_write!(io, "{} {} ", UserAddress(receiver.clone()), amount);
                            }
                            if let Some(receipt) = txn.receipt() {
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
            |io, keystore, receipt: TransactionReceipt<C::Ledger>| {
                match keystore.transaction_status(&receipt.uid).await {
                    Ok(status) => cli_writeln!(io, "{}", status),
                    Err(err) => cli_writeln!(io, "Error getting transaction status: {}", err),
                }
            }
        ),
        command!(
            wait,
            "wait for a transaction to complete",
            C,
            |io, keystore, receipt: TransactionReceipt<C::Ledger>| {
                match keystore.await_transaction(&receipt.uid).await {
                    Ok(status) => cli_writeln!(io, "{}", status),
                    Err(err) => cli_writeln!(io, "Error waiting for transaction: {}", err),
                }
            }
        ),
        command!(keys, "list keys tracked by this keystore", C, |io, keystore| {
            print_keys::<C>(io, keystore).await;
        }),
        command!(
            gen_key,
            "generate a new key",
            C,
            |io, keystore, key_type: KeyType;
             description: Option<String>, scan_from: Option<EventIndex>, wait: Option<bool>| {
                let description = description.unwrap_or_default();
                match key_type {
                    KeyType::Viewing => match keystore.generate_viewing_key(description).await {
                        Ok(pub_key) => cli_writeln!(io, "{}", pub_key),
                        Err(err) => cli_writeln!(io, "Error generating viewing key: {}", err),
                    },
                    KeyType::Freezing => match keystore.generate_freeze_key(description).await {
                        Ok(pub_key) => cli_writeln!(io, "{}", pub_key),
                        Err(err) => cli_writeln!(io, "Error generating freezing key: {}", err),
                    },
                    KeyType::Sending => match keystore.generate_user_key(description, scan_from).await {
                        Ok(pub_key) => {
                            if wait == Some(true) {
                                if let Err(err) = keystore.await_key_scan(&pub_key.address()).await {
                                    cli_writeln!(io, "Error waiting for key scan: {}", err);
                                }
                            }
                            // Output both the public key and the address when generating a
                            // sending key.
                            cli_writeln!(io, "{}", pub_key);
                            cli_writeln!(io, "{}", UserAddress(pub_key.address()));
                        }
                        Err(err) => cli_writeln!(io, "Error generating sending key: {}", err),
                    },
                }
            }
        ),
        command!(
            load_key,
            "load a key from a file",
            C,
            |io, keystore, key_type: KeyType, path: PathBuf;
             description: Option<String>, scan_from: Option<EventIndex>, wait: Option<bool>| {
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

                let description = description.unwrap_or_default();
                match key_type {
                    KeyType::Viewing => match bincode::deserialize::<ViewerKeyPair>(&bytes) {
                        Ok(key) => match keystore.add_viewing_key(key.clone(), description).await {
                            Ok(()) => cli_writeln!(io, "{}", key.pub_key()),
                            Err(err) => cli_writeln!(io, "Error saving viewing key: {}", err),
                        },
                        Err(err) => {
                            cli_writeln!(io, "Error loading viewing key: {}", err);
                        }
                    },
                    KeyType::Freezing => match bincode::deserialize::<FreezerKeyPair>(&bytes) {
                        Ok(key) => match keystore.add_freeze_key(key.clone(), description).await {
                            Ok(()) => cli_writeln!(io, "{}", key.pub_key()),
                            Err(err) => cli_writeln!(io, "Error saving freezing key: {}", err),
                        },
                        Err(err) => {
                            cli_writeln!(io, "Error loading freezing key: {}", err);
                        }
                    },
                    KeyType::Sending => match bincode::deserialize::<UserKeyPair>(&bytes) {
                        Ok(key) => match keystore.add_user_key(
                            key.clone(),
                            description,
                            scan_from.unwrap_or_default(),
                        ).await {
                            Ok(()) => {
                                if wait == Some(true) {
                                    if let Err(err) = keystore.await_key_scan(&key.address()).await {
                                        cli_writeln!(io, "Error waiting for key scan: {}", err);
                                        return
                                    }
                                } else{
                                    cli_writeln!(io,
                                        "Note: assets belonging to this key will become available
                                        after a scan of the ledger. This may take a long time. If
                                        you have the owner memo for a record you want to uses
                                        immediately, use import_memo.");
                                }
                                // Output both the public key and the address when loading a
                                // sending key.
                                cli_writeln!(io, "{}", key.pub_key());
                                cli_writeln!(io, "{}", UserAddress(key.address()));
                            }
                            Err(err) => cli_writeln!(io, "Error saving sending key: {}", err),
                        },
                        Err(err) => {
                            cli_writeln!(io, "Error loading sending key: {}", err);
                        }
                    },
                };
            }
        ),
        command!(
            import_memo,
            "import an owner memo belonging to this keystore",
            C,
            |io,
             keystore,
             memo: ReceiverMemo,
             comm: RecordCommitment,
             uid: u64,
             proof: MerklePath| {
                if let Err(err) = keystore.import_memo(memo, comm, uid, proof.0).await {
                    cli_writeln!(io, "{}", err);
                }
            }
        ),
        command!(
            info,
            "print general information about this keystore",
            C,
            |io, keystore| {
                cli_writeln!(io, "Addresses:");
                for pub_key in keystore.pub_keys().await {
                    cli_writeln!(io, "  {}", UserAddress(pub_key.address()));
                }
                print_keys::<C>(io, keystore).await;
            }
        ),
        command!(
            view,
            "list unspent records of viewable asset types",
            C,
            |io, keystore, asset: ListItem<AssetCode>; account: Option<UserAddress>| {
                let records = keystore
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
            |io, keystore, asset: Asset| {
                if let Err(err) = keystore.import_asset(asset).await {
                    cli_writeln!(io, "Error: {}", err);
                }
            }
        ),
        // The following commands are not part of the public interface, but are used for
        // synchronization in automated CLI tests.
        #[cfg(any(test, feature = "testing"))]
        command!(
            now,
            "print the index of the latest event processed by the keystore",
            C,
            |io, keystore| {
                cli_writeln!(io, "{}", keystore.now().await);
            }
        ),
        #[cfg(any(test, feature = "testing"))]
        command!(
            sync,
            "wait until the keystore has processed up to a given event index",
            C,
            |io, keystore, t: EventIndex| {
                if let Err(err) = keystore.sync(t).await {
                    cli_writeln!(io, "Error waiting for sync point {}: {}", t, err);
                }
            }
        ),
    ]);

    commands
}

async fn print_keys<'a, C: CLI<'a>>(io: &mut SharedIO, keystore: &Keystore<'a, C>) {
    cli_writeln!(io, "Sending keys:");
    for key in keystore.pub_keys().await {
        let account = keystore.sending_account(&key.address()).await.unwrap();
        cli_writeln!(io, "  {} {}", key, account.description);
    }
    cli_writeln!(io, "Viewing keys:");
    for key in keystore.viewer_pub_keys().await {
        let account = keystore.viewing_account(&key).await.unwrap();
        cli_writeln!(io, "  {} {}", key, account.description);
    }
    cli_writeln!(io, "Freezing keys:");
    for key in keystore.freezer_pub_keys().await {
        let account = keystore.freezing_account(&key).await.unwrap();
        cli_writeln!(io, "  {} {}", key, account.description);
    }
}

pub enum KeyType {
    Viewing,
    Freezing,
    Sending,
}

impl<'a, C: CLI<'a>> CLIInput<'a, C> for KeyType {
    fn parse_for_keystore(_keystore: &mut Keystore<'a, C>, s: &str) -> Option<Self> {
        match s {
            "view" | "viewing" => Some(Self::Viewing),
            "freeze" | "freezing" => Some(Self::Freezing),
            "send" | "sending" => Some(Self::Sending),
            _ => None,
        }
    }
}

pub async fn finish_transaction<'a, C: CLI<'a>>(
    io: &mut SharedIO,
    keystore: &Keystore<'a, C>,
    result: Result<TransactionReceipt<C::Ledger>, KeystoreError<C::Ledger>>,
    wait: Option<bool>,
    success_state: &str,
) {
    match result {
        Ok(receipt) => {
            if wait == Some(true) {
                match keystore.await_transaction(&receipt.uid).await {
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

/// Run the CLI based in the provided command line arguments.
pub async fn cli_main<'a, L: 'static + Ledger, C: CLI<'a, Ledger = L>>(
    args: C::Args,
) -> Result<(), KeystoreError<L>> {
    if let Some(path) = args.key_gen_path() {
        key_gen::<C>(path)
    } else {
        repl::<L, C>(args).await
    }
}

pub fn key_gen<'a, C: CLI<'a>>(mut path: PathBuf) -> Result<(), KeystoreError<C::Ledger>> {
    let key_pair = crate::new_key_pair();

    let mut file = File::create(path.clone()).context(IoSnafu)?;
    let bytes = bincode::serialize(&key_pair).context(BincodeSnafu)?;
    file.write_all(&bytes).context(IoSnafu)?;

    path.set_extension("pub");
    let mut file = File::create(path).context(IoSnafu)?;
    let bytes = bincode::serialize(&key_pair.pub_key()).context(BincodeSnafu)?;
    file.write_all(&bytes).context(IoSnafu)?;

    Ok(())
}

async fn repl<'a, L: 'static + Ledger, C: CLI<'a, Ledger = L>>(
    args: C::Args,
) -> Result<(), KeystoreError<L>> {
    let (storage, _tmp_dir) = match args.storage_path() {
        Some(storage) => (storage, None),
        None if !args.use_tmp_storage() => {
            let home = std::env::var("HOME").map_err(|_| KeystoreError::Failed {
                msg: String::from(
                    "HOME directory is not set. Please set your HOME directory, or specify \
                        a different storage location using --storage.",
                ),
            })?;
            let mut dir = PathBuf::from(home);
            dir.push(format!(
                ".espresso/{}/keystore",
                L::name()
                    .to_lowercase()
                    .replace('/', "_")
                    .replace('\\', "_")
            ));
            (dir, None)
        }
        None => {
            let tmp_dir = TempDir::new("keystore").context(IoSnafu)?;
            (PathBuf::from(tmp_dir.path()), Some(tmp_dir))
        }
    };

    let (mut io, mut input) = match args.io() {
        Some(io) => (io.clone(), Reader::automated(io)),
        None => (SharedIO::std(), Reader::interactive()),
    };
    cli_writeln!(
        io,
        "Welcome to the {} keystore, version {}",
        C::Ledger::name(),
        env!("CARGO_PKG_VERSION")
    );
    cli_writeln!(io, "(c) 2021 Espresso Systems, Inc.");

    let universal_param = Box::leak(Box::new(L::srs()));
    let backend = C::init_backend(universal_param, args).await?;

    // Loading the keystore takes a while. Let the user know that's expected.
    //todo !jeb.bearer Make it faster
    cli_writeln!(io, "connecting...");
    let mut loader = C::init_loader(storage, input.clone()).await?;
    let mut keystore = Keystore::<C>::new(backend, &mut loader).await?;
    cli_writeln!(io, "Type 'help' for a list of commands.");
    let commands = init_commands::<C>();

    'repl: while let Some(line) = input.read_line() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }
        if tokens[0] == "help" {
            for command in commands.iter() {
                cli_writeln!(io, "{}", command);
            }
            cli_writeln!(
                io,
                "General rule: When determining whether to use UserAddress or UserPubKey as the
                parameter, use UserAddress as an account identifier (to send an asset, get a
                balance, etc.), and UserPubKey as a transaction destination. An exception is when
                we can't reasonably know the UserPubKey of the destination (freezing or
                unfreezing), in which case we use UserAddress instead."
            );
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
                run(io.clone(), &mut keystore, args, kwargs).await;
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

#[cfg(all(test, feature = "slow-tests"))]
mod test {
    use super::*;
    use crate::{
        io::Tee,
        loader::{InteractiveLoader, MnemonicPasswordLogin},
        testing::{
            cli_match::*,
            mocks::{MockBackend, MockLedger, MockNetwork, MockSystem},
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
    use std::io::BufRead;
    use std::time::Instant;
    use tempdir::TempDir;

    type MockCapLedger<'a> = Arc<Mutex<MockLedger<'a, cap::Ledger, MockNetwork<'a>>>>;

    struct MockArgs<'a> {
        io: SharedIO,
        ledger: MockCapLedger<'a>,
        path: Option<PathBuf>,
    }

    impl<'a> CLIArgs for MockArgs<'a> {
        fn key_gen_path(&self) -> Option<PathBuf> {
            None
        }

        fn storage_path(&self) -> Option<PathBuf> {
            self.path.clone()
        }

        fn io(&self) -> Option<SharedIO> {
            Some(self.io.clone())
        }

        fn use_tmp_storage(&self) -> bool {
            true
        }
    }

    struct MockCLI;

    #[async_trait]
    impl<'a> CLI<'a> for MockCLI {
        type Ledger = cap::Ledger;
        type Backend = MockBackend<'a>;
        type Loader = InteractiveLoader;
        type Meta = MnemonicPasswordLogin;
        type Args = MockArgs<'a>;

        async fn init_backend(
            _universal_param: &'a UniversalParam,
            args: Self::Args,
        ) -> Result<Self::Backend, KeystoreError<Self::Ledger>> {
            Ok(MockBackend::new(args.ledger.clone()))
        }

        async fn init_loader(
            storage: PathBuf,
            input: Reader,
        ) -> Result<Self::Loader, KeystoreError<Self::Ledger>> {
            Ok(InteractiveLoader::new(storage, input))
        }
    }
    fn write_key_file(path: PathBuf, key: UserKeyPair) -> PathBuf {
        let full_path = path.clone().join("keys");
        let mut file = File::create(full_path.clone()).unwrap();
        let bytes = bincode::serialize(&key).unwrap();
        file.write_all(&bytes).unwrap();
        full_path
    }
    async fn create_network<'a>(
        t: &mut MockSystem,
        initial_grants: &[u64],
    ) -> (MockCapLedger<'a>, Vec<Vec<UserKeyPair>>) {
        // Use `create_test_network` to create a ledger with some initial records.
        let (ledger, keystores) = t
            .create_test_network(&[(3, 3)], initial_grants.to_vec(), &mut Instant::now())
            .await;
        // Set `block_size` to `1` so we don't have to explicitly flush the ledger after each
        // transaction submission.
        ledger.lock().await.set_block_size(1).unwrap();
        // We don't actually care about the open keystores returned by `create_test_network`, because
        // the CLI does its own keystore loading. But we do want to get their key streams, so that
        // the keystores we create through the CLI can deterministically generate the keys that own
        // the initial records.
        let key_streams = iter(keystores)
            .then(|(keystore, _, _)| async move {
                let mut keys = vec![];
                let pub_keys = keystore.pub_keys().await;
                for pub_key in pub_keys {
                    keys.push(
                        keystore
                            .get_user_private_key(&pub_key.address())
                            .await
                            .unwrap(),
                    );
                }
                keys
            })
            .collect::<Vec<_>>()
            .await;
        (ledger, key_streams)
    }

    fn create_keystore(
        ledger: MockCapLedger<'static>,
        path: PathBuf,
    ) -> (Tee<PipeWriter>, Tee<PipeReader>) {
        let (io, input, output) = SharedIO::pipe();

        // Run a CLI interface for a keystore in the background.
        spawn(async move {
            let args = MockArgs {
                io,
                ledger,
                path: Some(path),
            };
            cli_main::<cap::Ledger, MockCLI>(args).await.unwrap();
        });

        // Wait for the CLI to start up and then return the input and output pipes.
        let mut input = Tee::new(input);
        let mut output = Tee::new(output);
        wait_for_prompt(&mut output);
        // Loader wants to verify the keyphase.  Input 1 here to accept the generated phrase.
        writeln!(input, "1").unwrap();
        let mut line = String::new();
        // Enter a password for the loader
        output.read_line(&mut line).unwrap();
        writeln!(input, "password").unwrap();
        output.read_line(&mut line).unwrap();
        writeln!(input, "password").unwrap();
        wait_for_prompt(&mut output);

        (input, output)
    }

    fn add_funded_keys(
        input: &mut impl Write,
        output: &mut impl BufRead,
        private_keys: &Vec<UserKeyPair>,
        path: PathBuf,
    ) -> Vec<(String, String)> {
        let mut keys = vec![];
        for pk in private_keys {
            let file_name = write_key_file(path.clone(), pk.clone());
            writeln!(
                input,
                "load_key sending {} scan_from=start wait=true",
                file_name.to_str().unwrap()
            )
            .unwrap();
            let matches =
                match_output(output, &["(?P<pub_key>USERPUBKEY~.*)", "(?P<addr>ADDR~.*)"]);
            let pub_key = matches.get("pub_key");
            let address = matches.get("addr");
            keys.push((address, pub_key));
        }
        keys
    }

    #[async_std::test]
    async fn test_view_freeze() {
        let mut t = MockSystem::default();
        let (ledger, private_keys) = create_network(&mut t, &[2000, 2000, 0]).await;
        let tmp_dir1 = TempDir::new("keystore").unwrap();
        let tmp_dir2 = TempDir::new("keystore").unwrap();
        let tmp_dir3 = TempDir::new("keystore").unwrap();

        // Create three keystore clients: one to mint and view an asset, one to make an anonymous
        // transfer, and one to receive an anonymous transfer. We will see if the viewer can
        // discover the output record of the anonymous transfer, in which it is not a participant.
        let (mut viewer_input, mut viewer_output) =
            create_keystore(ledger.clone(), PathBuf::from(tmp_dir1.path()));
        let (mut sender_input, mut sender_output) =
            create_keystore(ledger.clone(), PathBuf::from(tmp_dir2.path()));
        let (mut receiver_input, mut receiver_output) =
            create_keystore(ledger, PathBuf::from(tmp_dir3.path()));

        // Get the viewer's address.
        let (viewer_address, _) = add_funded_keys(
            &mut viewer_input,
            &mut viewer_output,
            &private_keys[0],
            PathBuf::from(tmp_dir1.path()),
        )[0]
        .clone();

        // Get the sender's funded public key and address.
        let (sender_address, sender_pub_key) = add_funded_keys(
            &mut sender_input,
            &mut sender_output,
            &private_keys[1],
            PathBuf::from(tmp_dir1.path()),
        )[0]
        .clone();

        // Get the receiver's (unfunded) public key and address.
        writeln!(receiver_input, "gen_key sending").unwrap();
        let matches = match_output(
            &mut receiver_output,
            &["(?P<pub_key>USERPUBKEY~.*)", "(?P<addr>ADDR~.*)"],
        );
        let receiver_pub_key = matches.get("pub_key");
        let receiver_address = matches.get("addr");

        // Generate a viewing key.
        writeln!(viewer_input, "gen_key viewing").unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<view_key>AUDPUBKEY~.*)"]);
        let view_key = matches.get("view_key");
        // Currently we only view assets that we can freeze, so we need a freeze key.
        writeln!(viewer_input, "gen_key freezing").unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<freeze_key>FREEZEPUBKEY~.*)"]);
        let freeze_key = matches.get("freeze_key");
        // Define an viewable asset.
        writeln!(
            viewer_input,
            "create_asset my_asset viewing_key={} freezing_key={} view_amount=true view_address=true view_blind=true",
            view_key, freeze_key
        )
        .unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<asset_code>ASSET_CODE~.*)"]);
        let asset_code = matches.get("asset_code");
        // Mint some of the asset on behalf of `sender`.
        writeln!(
            viewer_input,
            "mint {} {} 1000 1 fee_account={}",
            asset_code, sender_pub_key, viewer_address,
        )
        .unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<txn>TXN~.*)"]);
        let receipt = matches.get("txn");
        await_transaction(
            &receipt,
            (&mut viewer_input, &mut viewer_output),
            &mut [(&mut sender_input, &mut sender_output)],
        );
        writeln!(sender_input, "balance {}", asset_code).unwrap();
        match_output(&mut sender_output, &[format!("{} 1000", sender_address)]);

        // Make an anonymous transfer that doesn't involve the viewer (so we can check that the
        // viewer nonetheless discovers the details of the transaction).
        writeln!(
            sender_input,
            "transfer {} {} 50 1 from={}",
            asset_code, receiver_pub_key, sender_address,
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
        // output, and second the amount-950 change output. These records have UIDs 7 and 8, because
        // we already have 7 records: 5 initial grants, a mint output, and a mint fee change record.
        writeln!(viewer_input, "view {}", asset_code).unwrap();
        match_output(
            &mut viewer_output,
            &[
                "^UID\\s+AMOUNT\\s+FROZEN\\s+OWNER$",
                format!("^7\\s+50\\s+false\\s+{}$", receiver_address).as_str(),
                format!("^8\\s+950\\s+false\\s+{}$", sender_address).as_str(),
            ],
        );
        // Filter by account.
        writeln!(
            viewer_input,
            "view {} account={}",
            asset_code, receiver_address
        )
        .unwrap();
        match_output(
            &mut viewer_output,
            &["^UID\\s+AMOUNT\\s+FROZEN$", "^7\\s+50\\s+false$"],
        );
        writeln!(
            viewer_input,
            "view {} account={}",
            asset_code, sender_address
        )
        .unwrap();
        match_output(
            &mut viewer_output,
            &["^UID\\s+AMOUNT\\s+FROZEN$", "^8\\s+950\\s+false$"],
        );

        // If we can see the record openings and we hold the freezer key, we should be able to
        // freeze them.
        writeln!(
            viewer_input,
            "freeze {} {} 950 1 fee_account={}",
            asset_code, sender_address, viewer_address,
        )
        .unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<txn>TXN~.*)"]);
        let receipt = matches.get("txn");
        await_transaction(
            &receipt,
            (&mut viewer_input, &mut viewer_output),
            &mut [(&mut sender_input, &mut sender_output)],
        );
        writeln!(viewer_input, "view {}", asset_code).unwrap();
        // Note that the UID changes after freezing, because the freeze consume the unfrozen record
        // and creates a new frozen one.
        match_output(
            &mut viewer_output,
            &[
                "^UID\\s+AMOUNT\\s+FROZEN\\s+OWNER$",
                format!("^7\\s+50\\s+false\\s+{}$", receiver_address).as_str(),
                format!("^10\\s+950\\s+true\\s+{}$", sender_address).as_str(),
            ],
        );

        // Transfers that need the frozen record as an input should now fail.
        writeln!(
            sender_input,
            "transfer {} {} 50 1 from={}",
            asset_code, receiver_pub_key, sender_address
        )
        .unwrap();
        // Search for error message with a slightly permissive regex to allow the CLI some freedom
        // in reporting a readable error.
        match_output(&mut sender_output, &["[Ii]nsufficient.*[Bb]alance"]);

        // Unfreezing the record makes it available again.
        writeln!(
            viewer_input,
            "unfreeze {} {} 950 1 fee_account={}",
            asset_code, sender_address, viewer_address,
        )
        .unwrap();
        let matches = match_output(&mut viewer_output, &["(?P<txn>TXN~.*)"]);
        let receipt = matches.get("txn");
        await_transaction(
            &receipt,
            (&mut viewer_input, &mut viewer_output),
            &mut [(&mut sender_input, &mut sender_output)],
        );
        writeln!(viewer_input, "view {}", asset_code).unwrap();
        match_output(
            &mut viewer_output,
            &[
                "^UID\\s+AMOUNT\\s+FROZEN\\s+OWNER$",
                format!("^7\\s+50\\s+false\\s+{}$", receiver_address).as_str(),
                format!("^12\\s+950\\s+false\\s+{}$", sender_address).as_str(),
            ],
        );
    }

    #[async_std::test]
    async fn test_import_asset() {
        let mut rng = ChaChaRng::from_seed([38; 32]);
        let seed = AssetCodeSeed::generate(&mut rng);
        let code = AssetCode::new_domestic(seed, "my_asset".as_bytes());
        let definition = AssetDefinition::new(code, AssetPolicy::default()).unwrap();
        let tmp_dir = TempDir::new("keystore").unwrap();

        let mut t = MockSystem::default();
        let (ledger, _keys) = create_network(&mut t, &[0]).await;
        let (mut input, mut output) =
            create_keystore(ledger.clone(), PathBuf::from(tmp_dir.path()));

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
            "import_asset definition:{},seed:{},mint_description:my_asset",
            definition, seed
        )
        .unwrap();
        wait_for_prompt(&mut output);
        writeln!(input, "asset {}", definition.code).unwrap();
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
