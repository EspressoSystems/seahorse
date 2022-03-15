use crate::{txn_builder::RecordInfo, AssetInfo};
use arbitrary::{Arbitrary, Unstructured};
use arbitrary_wrappers::{ArbitraryAuditorKeyPair, ArbitraryFreezerKeyPair, ArbitraryUserKeyPair};
use espresso_macros::ser_test;
use jf_cap::keys::{
    AuditorKeyPair, AuditorPubKey, FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair,
};
use serde::{Deserialize, Serialize};

#[ser_test(
    arbitrary,
    ark(false),
    types(AuditorKeyPair),
    types(FreezerKeyPair),
    types(UserKeyPair)
)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account<Key> {
    pub(crate) key: Key,
    pub(crate) description: String,
    pub(crate) used: bool,
}

impl<Key> Account<Key> {
    pub fn new(key: Key, description: String) -> Self {
        Self {
            key,
            description,
            used: false,
        }
    }
}

impl<Key: KeyPair> PartialEq<Self> for Account<Key> {
    fn eq(&self, other: &Self) -> bool {
        // We assume that the private keys are equal if the public keys are.
        self.key.pub_key() == other.key.pub_key()
            && self.description == other.description
            && self.used == other.used
    }
}

impl<'a> Arbitrary<'a> for Account<AuditorKeyPair> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary::<ArbitraryAuditorKeyPair>()?.into(),
            description: u.arbitrary()?,
            used: u.arbitrary()?,
        })
    }
}

impl<'a> Arbitrary<'a> for Account<FreezerKeyPair> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary::<ArbitraryFreezerKeyPair>()?.into(),
            description: u.arbitrary()?,
            used: u.arbitrary()?,
        })
    }
}

impl<'a> Arbitrary<'a> for Account<UserKeyPair> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary::<ArbitraryUserKeyPair>()?.into(),
            description: u.arbitrary()?,
            used: u.arbitrary()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AccountInfo<Key: KeyPair> {
    pub address: Key::PubKey,
    pub description: String,
    pub used: bool,
    pub assets: Vec<AssetInfo>,
    pub records: Vec<RecordInfo>,
    pub balance: u64,
}

impl<Key: KeyPair> AccountInfo<Key> {
    pub fn new(account: Account<Key>, assets: Vec<AssetInfo>, records: Vec<RecordInfo>) -> Self {
        Self {
            address: account.key.pub_key(),
            description: account.description,
            used: account.used,
            balance: records.iter().map(|rec| rec.ro.amount).sum(),
            assets,
            records,
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
            && self.balance == other.balance
    }
}

pub trait KeyPair: Clone + Send + Sync {
    type PubKey: std::hash::Hash + Eq;
    fn pub_key(&self) -> Self::PubKey;
}

impl KeyPair for AuditorKeyPair {
    type PubKey = AuditorPubKey;

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
