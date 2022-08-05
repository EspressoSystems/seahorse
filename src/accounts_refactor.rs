/// Keys and associated data.
use crate::{
    events::{EventSource, LedgerEvent},
    key_scan::BackgroundKeyScan,
    key_value_store::KeyValueStore,
    txn_builder::RecordInfo,
    KeystoreError,
};
use chrono::{DateTime, Local};
use jf_cap::{
    keys::{FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair, ViewerKeyPair, ViewerPubKey},
    structs::AssetCode,
    MerkleCommitment,
};
use primitive_types::U256;
use reef::Ledger;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

/// Keys with a public part.
pub trait KeyPair: Clone + Send + Sync {
    type PubKey: Clone + DeserializeOwned + Hash + Eq + Serialize;
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(bound = "Key: DeserializeOwned + Serialize")]
pub struct Account<L: Ledger, Key: KeyPair> {
    key: Key,
    /// The account description.
    pub description: String,
    /// Whether the account is used.
    pub used: bool,
    /// Optional ledger scan.
    pub scan: Option<BackgroundKeyScan<L>>,
    /// The list of asset codes of the account.
    pub assets: Vec<AssetCode>,
    /// Records of the account.
    pub records: Vec<RecordInfo>,
    /// The table of balances with corresponding asset code.
    pub balances: HashMap<AssetCode, U256>,
    /// The time when the account was created.
    created_time: DateTime<Local>,
    /// The last time when the account was modified.
    modified_time: DateTime<Local>,
}

impl<L: Ledger, Key: KeyPair> Account<L, Key> {
    #![allow(dead_code)]

    /// Get the account key.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Get the account public key.
    pub fn pub_key(&self) -> Key::PubKey {
        self.key.pub_key()
    }

    /// Get the account description.
    pub fn description(&self) -> String {
        self.description.clone()
    }

    /// Check whether the account is used.
    pub fn used(&self) -> bool {
        self.used
    }

    /// Get the optional ledger scan.
    pub fn scan(&self) -> Option<BackgroundKeyScan<L>> {
        self.scan.clone()
    }

    /// Get the list of asset codes.
    pub fn assets(&self) -> Vec<AssetCode> {
        self.assets.clone()
    }

    /// Get the list of records.
    pub fn records(&self) -> Vec<RecordInfo> {
        self.records.clone()
    }

    /// Get the table of balances.
    pub fn balances(&self) -> HashMap<AssetCode, U256> {
        self.balances.clone()
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

pub type AccountsStore<L, Key, PubKey> = KeyValueStore<PubKey, Account<L, Key>>;

/// An editor to create or update the account or accounts store.
pub struct AccountEditor<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> {
    account: Account<L, Key>,
    store: &'a mut AccountsStore<L, Key, Key::PubKey>,
}

impl<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> AccountEditor<'a, L, Key> {
    /// Create an account editor.
    fn new(
        store: &'a mut AccountsStore<L, Key, Key::PubKey>,
        account: Account<L, Key>,
    ) -> AccountEditor<'a, L, Key> {
        Self { account, store }
    }

    /// Set the account as used.
    pub fn set_used(mut self) -> Self {
        self.account.used = true;
        self.account.modified_time = Local::now();
        self
    }

    /// Set the account as unused.
    pub fn set_unused(mut self) -> Self {
        self.account.used = false;
        self.account.modified_time = Local::now();
        self
    }

    /// Set the optional ledger scan.
    pub fn set_scan(mut self, scan: Option<BackgroundKeyScan<L>>) -> Self {
        self.account.scan = scan;
        self.account.modified_time = Local::now();
        self
    }

    /// Set the ledger scan.
    pub fn with_name(mut self, scan: BackgroundKeyScan<L>) -> Self {
        self.account.scan = Some(scan);
        self.account.modified_time = Local::now();
        self
    }

    /// Clear the leger scan.
    pub fn clear_name(mut self) -> Self {
        self.account.scan = None;
        self.account.modified_time = Local::now();
        self
    }

    /// Update the ledger scan.
    pub(crate) async fn update_scan(
        mut self,
        event: LedgerEvent<L>,
        source: EventSource,
        records_commitment: MerkleCommitment,
    ) -> Result<AccountEditor<'a, L, Key>, KeystoreError<L>> {
        let mut scan = match self.account.scan.take() {
            Some(scan) => scan,
            None => return Err(KeystoreError::ScanNotFound),
        };
        scan.handle_event(event, source);
        // Check if the scan is complete.
        if let Err(scan) = scan.finalize(records_commitment) {
            self.account.scan = Some(scan);
        }
        Ok(self)
    }

    /// Save the account to the store.
    ///
    /// Returns the stored account.
    pub fn save(&mut self) -> Result<Account<L, Key>, KeystoreError<L>> {
        self.store.store(&self.account.pub_key(), &self.account)?;
        Ok(self.account.clone())
    }
}

impl<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> Deref
    for AccountEditor<'_, L, Key>
{
    type Target = Account<L, Key>;

    fn deref(&self) -> &Account<L, Key> {
        &self.account
    }
}

impl<'a, L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> DerefMut
    for AccountEditor<'_, L, Key>
{
    fn deref_mut(&mut self) -> &mut Account<L, Key> {
        &mut self.account
    }
}

/// Accounts stored in an accounts store.
pub struct Accounts<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> {
    /// A key-value store for accounts.
    store: AccountsStore<L, Key, Key::PubKey>,
}

impl<L: Ledger, Key: KeyPair + DeserializeOwned + Serialize> Accounts<L, Key> {
    #![allow(dead_code)]

    /// Load an accounts store.
    pub fn new(store: AccountsStore<L, Key, Key::PubKey>) -> Result<Self, KeystoreError<L>> {
        Ok(Self { store })
    }

    /// Iterate through the accounts.
    pub fn iter(&self) -> impl Iterator<Item = Account<L, Key>> + '_ {
        self.store.iter().cloned()
    }

    /// Get the account by the public key from the store.
    pub fn get(&self, pub_key: &Key::PubKey) -> Result<Account<L, Key>, KeystoreError<L>> {
        Ok(self.store.load(pub_key)?)
    }

    /// Get a mutable account editor by the public key from the store.
    pub fn get_mut(
        &mut self,
        pub_key: &Key::PubKey,
    ) -> Result<AccountEditor<L, Key>, KeystoreError<L>> {
        let account = self.get(pub_key)?;
        Ok(AccountEditor::new(&mut self.store, account))
    }

    /// Commit the store version.
    pub fn commit(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.commit_version()?)
    }

    /// Revert the store version.
    pub fn revert(&mut self) -> Result<(), KeystoreError<L>> {
        Ok(self.store.revert_version()?)
    }

    /// Create an account.
    ///
    /// Returns the editor for the created account.
    pub fn create(
        &mut self,
        key: Key,
        description: String,
        assets: Vec<AssetCode>,
        records: Vec<RecordInfo>,
    ) -> Result<AccountEditor<L, Key>, KeystoreError<L>> {
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
            created_time: time,
            modified_time: time,
        };
        let mut editor = AccountEditor::new(&mut self.store, account);
        editor.save()?;
        Ok(editor)
    }

    /// Update the ledger scan of an account.
    pub(crate) async fn update_scan(
        &mut self,
        pub_key: &Key::PubKey,
        event: LedgerEvent<L>,
        source: EventSource,
        records_commitment: MerkleCommitment,
    ) -> Result<AccountEditor<'_, L, Key>, KeystoreError<L>> {
        let mut editor = self.get_mut(pub_key)?;
        editor = editor
            .update_scan(event, source, records_commitment)
            .await?;
        editor.save()?;
        Ok(editor)
    }

    /// Deletes an account from the store.
    ///
    /// Returns the deleted account.
    pub fn delete(&mut self, pub_key: &Key::PubKey) -> Result<Account<L, Key>, KeystoreError<L>> {
        Ok(self.store.delete(pub_key)?)
    }
}
