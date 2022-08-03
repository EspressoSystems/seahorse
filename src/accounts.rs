/// Keys and associated data.
use crate::{
    assets::Asset,
    events::{EventIndex, EventSource, LedgerEvent},
    key_scan::{BackgroundKeyScan, ScanOutputs},
    txn_builder::RecordInfo,
};
use arbitrary::{Arbitrary, Unstructured};
use arbitrary_wrappers::{ArbitraryFreezerKeyPair, ArbitraryUserKeyPair, ArbitraryViewerKeyPair};
use derivative::Derivative;
use espresso_macros::ser_test;
use jf_cap::{
    keys::{FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair, ViewerKeyPair, ViewerPubKey},
    structs::AssetCode,
    MerkleCommitment,
};
use primitive_types::U256;
use reef::{Ledger, TransactionHash};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

/// Keys with a public part.
pub trait KeyPair: Clone + Send + Sync {
    type PubKey: std::hash::Hash + Eq;
    fn pub_key(&self) -> Self::PubKey;
}

impl KeyPair for ViewerKeyPair {
    type PubKey = ViewerPubKey;

    fn pub_key(&self) -> Self::PubKey {
        self.pub_key()
    }
}

impl KeyPair for FreezerKeyPair {
    type PubKey = FreezerPubKey;

    fn pub_key(&self) -> Self::PubKey {
        self.pub_key()
    }
}

impl KeyPair for UserKeyPair {
    // The PubKey here is supposed to be a conceptual "primary key" for looking up UserKeyPairs. We
    // typically want to look up UserKeyPairs by Address, not PubKey, because if we have a PubKey we
    // can always get an Address to do the lookup.
    type PubKey = UserAddress;

    fn pub_key(&self) -> Self::PubKey {
        self.address()
    }
}

/// An account with its key as the primary key.
// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Account<L: Ledger, Key> {
    key: Key,
    /// The account description.
    pub description: String,
    /// Whether the account is used.
    pub used: bool,
    /// Optional ledger scan.
    pub scan: Option<BackgroundKeyScan<L>>,
    /// The list of assets owned by the account.
    pub assets: Vec<Asset>,
    /// The list of records owned by the account.
    pub records: Vec<RecordInfo>,
    /// The table of balances with corresponding asset code.
    pub balances: HashMap<AssetCode, U256>,
    /// Optional status of a ledger scan for this account's key.
    ///
    /// If a ledger scan using this account's key is in progress, `scan_status` contains the index
    /// of the next event to be scanned and the index of the last event in the scan's range of
    /// interest, in that order. Note that the former may be greater than the latter, since the scan
    /// will not complete until it has caught with the main event loop, which may have advanced past
    /// the end of the range of interest.
    pub scan_status: Option<(EventIndex, EventIndex)>,
    /// The time when the account was created.
    created_time: DateTime<Local>,
    /// The last time when the account was modified.
    modified_time: DateTime<Local>,
}

impl Account {
    #![allow(dead_code)]

    /// Get the account key.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Get the account public key.
    pub fn pub_key(&self) -> &Key::PubKey {
        &self.key.pub_key()
    }

    /// Get the account description.
    pub fn description(&self) -> String {
        &self.description
    }

    /// Check whether the account is used.
    pub fn used(&self) -> bool {
        &self.used
    }

    /// Get the optional ledger scan.
    pub fn scan(&self) -> Option<BackgroundKeyScan<L>> {
        &self.scan
    }

    /// Get the list of assets.
    pub fn assets(&self) -> Vec<Asset> {
        &self.assets
    }

    /// Get the list of records.
    pub fn records(&self) -> Vec<RecordInfo> {
        &self.records
    }

    /// Get the table of balances.
    pub fn balances(&self) -> HashMap<AssetCode, U256> {
        &self.balances
    }

    /// Get the optional scan status.
    pub fn scan_status(&self) -> Option<(EventIndex, EventIndex)> {
        &self.scan_status
    }

    /// Get the created time.
    pub fn created_time(&self) -> DateTime<Local> {
        self.created_time
    }

    /// Get the modified time.
    pub fn modified_time(&self) -> DateTime<Local> {
        self.modified_time
    }
}

impl<L: Ledger, Key: KeyPair> PartialEq<Self> for Account<L, Key> {
    fn eq(&self, other: &Self) -> bool {
        // We assume that the private keys are equal if the public keys are.
        self.key.pub_key() == other.key.pub_key()
            && self.description == other.description
            && self.used == other.used
            && self.scan == other.scan
            && self.assets == other.assets
            && self.records == other.records
            && self.balances == other.balances
            && self.scan_status = other.scan_status
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for Account<L, ViewerKeyPair>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let time = Local::now();
        Ok(Self {
            key: u.arbitrary::<ArbitraryViewerKeyPair>()?.into(),
            description: u.arbitrary()?,
            used: u.arbitrary()?,
            scan: u.arbitrary()?,
            assets: u.arbitrary()?,
            records: u.arbitrary()?,
            balances: u.arbitrary()?,
            scan_status: u.arbitrary()?,
            created_time: time,
            modified_time: time,
        })
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for Account<L, FreezerKeyPair>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary::<ArbitraryFreezerKeyPair>()?.into(),
            description: u.arbitrary()?,
            used: u.arbitrary()?,
            scan: u.arbitrary()?,
            assets: u.arbitrary()?,
            records: u.arbitrary()?,
            balances: u.arbitrary()?,
            scan_status: u.arbitrary()?,
            created_time: time,
            modified_time: time,
        })
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for Account<L, UserKeyPair>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary::<ArbitraryUserKeyPair>()?.into(),
            description: u.arbitrary()?,
            used: u.arbitrary()?,
            scan: u.arbitrary()?,
            assets: u.arbitrary()?,
            records: u.arbitrary()?,
            balances: u.arbitrary()?,
            scan_status: u.arbitrary()?,
            created_time: time,
            modified_time: time,
        })
    }
}

pub type AccountsStore = KeyValueStore<Key::PubKey, Account>;

/// An editor to create or update the account or accounts store.
pub struct AccountEditor<'a> {
    account: Account,
    store: &'a mut AccountsStore,
}

impl<'a> AccountEditor<'a> {
    /// Create an account editor.
    fn new(store: &'a mut AccountsStore, account: Account) -> Self {
        Self { account, store }
    }

    /// Update the ledger scan.
    pub(crate) async fn update_scan(
        &mut self,
        event: LedgerEvent<L>,
        source: EventSource,
        records_commitment: MerkleCommitment,
    ) -> Self {
        let mut scan = self.account.scan.take().unwrap();
        scan.handle_event(event, source);
        // Check if the scan is complete.
        if let Err(scan) = scan.finalize(records_commitment) {
            self.account.scan = Some(scan);
        }
        Self
    }

    /// Save the account to the store.
    ///
    /// Returns the stored account.
    pub fn save<L: Ledger>(&mut self) -> Result<Account, KeystoreError<L>> {
        self.store.store(&self.account.key.pub_key, &self.account)?;
        Ok(self.account.clone())
    }
}

impl<'a> Deref for AccountEditor<'a> {
    type Target = Account;

    fn deref(&self) -> &Account {
        &self.account
    }
}

impl<'a> DerefMut for AccountEditor<'a> {
    fn deref_mut(&mut self) -> &mut Account {
        &mut self.account
    }
}

/// Accounts stored in an accounts store.
pub struct Accounts {
    /// A key-value store for accounts.
    store: AccountsStore,
}

impl Accounts {
    #![allow(dead_code)]

    /// Load an accounts store.
    pub fn new<L: Ledger>(store: AccountsStore) -> Result<Self, KeystoreError<L>> {
        Ok(Self { store })
    }

    /// Iterate through the accounts.
    pub fn iter(&self) -> impl Iterator<Item = Account> + '_ {
        self.store.iter().cloned()
    }

    /// Get the account by the public key from the store.
    pub fn get<L: Ledger>(&self, pub_key: &Key::PubKey) -> Result<Account, KeystoreError<L>> {
        self.store.load(pub_key)
    }

    /// Get a mutable account editor by the public key from the store.
    pub fn get_mut<L: Ledger>(
        &mut self,
        pub_key: &Key::PubKey,
    ) -> Result<AccountEditor<'_>, KeystoreError<L>> {
        let mut account = self.get(pub_key)?;
        Ok(AssetEditor::new(&mut self.store, account))
    }

    /// Commit the store version.
    pub fn commit<L: Ledger>(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert<L: Ledger>(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.revert_version()?)
    }

    /// Create an account.
    ///
    /// Returns the editor for the created account.
    pub fn create<L: Ledger>(
        &mut self,
        key: Key,
        description: String,
        assets: Vec<Asset>,
        records: Vec<RecordInfo>,
    ) -> Result<AccountEditor<'_>, KeystoreError<L>> {
        let mut balances = HashMap::new();
        for rec in &records {
            *balances
                .entry(rec.ro.asset_def.code)
                .or_insert_with(U256::zero) += rec.amount().into();
        }
        let time = Local::now();
        let account = Account {
            key,
            description,
            used: false,
            scan: None,
            assets,
            records,
            balances,
            scan_status: None,
            created_time: time,
            modified_time: time,
        };
        let mut editor = AccountEditor::new(self.store, asset.clone());
        editor.save::<L>()?;
        Ok(editor)
    }

    /// Update the ledger scan of an account.
    pub(crate) async fn update_scan(
        &mut self,
        pub_key: &Key::PubKey,
        event: LedgerEvent<L>,
        source: EventSource,
        records_commitment: MerkleCommitment,
    ) -> Result<AccountEditor<'_>, KeystoreError<L>> {
        let mut editor = self.get_mut(pub_key)?;
        editor.update_scan()?;
        editor.save::<L>()?;
        Ok(editor)
    }

    /// Deletes an account from the store.
    ///
    /// Returns the deleted account.
    pub fn delete<L: Ledger>(&mut self, pub_key: &Key::PubKey) -> Result<Asset, KeystoreError<L>> {
        Ok(self.store.delete(pub_key)?)
    }
}
