/// Keys and associated data.
use crate::{
    events::{EventIndex, EventSource, LedgerEvent},
    key_scan::{BackgroundKeyScan, ScanOutputs},
    txn_builder::RecordInfo,
    AssetInfo,
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
use reef::{Ledger, TransactionHash};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

/// The persistent representation of an account.
#[ser_test(
    arbitrary,
    ark(false),
    types(reef::cap::Ledger, ViewerKeyPair),
    types(reef::cap::Ledger, FreezerKeyPair),
    types(reef::cap::Ledger, UserKeyPair)
)]
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Clone(bound = "L: Ledger, Key: Clone"),
    Debug(bound = "L: Ledger, Key: Debug")
)]
#[serde(bound = "L: Ledger, Key: Serialize + DeserializeOwned")]
pub struct Account<L: Ledger, Key> {
    pub(crate) key: Key,
    pub(crate) description: String,
    pub(crate) used: bool,
    pub(crate) scan: Option<BackgroundKeyScan<L>>,
}

impl<L: Ledger, Key> Account<L, Key> {
    pub fn new(key: Key, description: String) -> Self {
        Self {
            key,
            description,
            used: false,
            scan: None,
        }
    }

    pub(crate) async fn update_scan(
        &mut self,
        event: LedgerEvent<L>,
        source: EventSource,
        records_commitment: MerkleCommitment,
    ) -> Option<(UserKeyPair, ScanOutputs<L>)> {
        let mut scan = self.scan.take().unwrap();
        scan.handle_event(event, source);
        // Check if the scan is complete.
        match scan.finalize(records_commitment) {
            Ok(result) => Some(result),
            Err(scan) => {
                self.scan = Some(scan);
                None
            }
        }
    }
}

impl<L: Ledger, Key: KeyPair> PartialEq<Self> for Account<L, Key> {
    fn eq(&self, other: &Self) -> bool {
        // We assume that the private keys are equal if the public keys are.
        self.key.pub_key() == other.key.pub_key()
            && self.description == other.description
            && self.used == other.used
            && self.scan == other.scan
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for Account<L, ViewerKeyPair>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary::<ArbitraryViewerKeyPair>()?.into(),
            description: u.arbitrary()?,
            used: u.arbitrary()?,
            scan: u.arbitrary()?,
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
        })
    }
}

/// An account bundled with all of its related information.
#[derive(Clone, Debug)]
pub struct AccountInfo<Key: KeyPair> {
    pub address: Key::PubKey,
    pub description: String,
    pub used: bool,
    pub assets: Vec<AssetInfo>,
    pub records: Vec<RecordInfo>,
    /// The table of balances with corresponding asset code.
    pub balances: HashMap<AssetCode, u64>,
    /// The status of a ledger scan for this account's key.
    ///
    /// If a ledger scan using this account's key is in progress, `scan_status` contains the index
    /// of the next event to be scanned and the index of the last event in the scan's range of
    /// interest, in that order. Note that the former may be greater than the latter, since the scan
    /// will not complete until it has caught with the main event loop, which may have advanced past
    /// the end of the range of interest.
    pub scan_status: Option<(EventIndex, EventIndex)>,
}

impl<Key: KeyPair> AccountInfo<Key> {
    pub fn new<L: Ledger>(
        account: Account<L, Key>,
        assets: Vec<AssetInfo>,
        records: Vec<RecordInfo>,
    ) -> Self {
        let mut balances = HashMap::new();
        for rec in &records {
            *balances.entry(rec.ro.asset_def.code).or_insert(0) += rec.ro.amount;
        }
        Self {
            address: account.key.pub_key(),
            description: account.description,
            used: account.used,
            balances,
            assets,
            records,
            scan_status: account.scan.map(|scan| (scan.status())),
        }
    }
}

impl<Key: KeyPair> PartialEq<Self> for AccountInfo<Key> {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.description == other.description
            && self.used == other.used
            && self.assets == other.assets
            && self.records == other.records
            && self.balances == other.balances
            && self.scan_status == other.scan_status
    }
}

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
    // can always get and Address to do the lookup.
    type PubKey = UserAddress;

    fn pub_key(&self) -> Self::PubKey {
        self.address()
    }
}
