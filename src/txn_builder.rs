// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Transaction building.
//!
//! This module defines the subset of ledger state required by a keystore to build transactions, and
//! provides an interface for building them.
use crate::records::{Record, Records};
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use derive_more::*;
use espresso_macros::ser_test;
use jf_cap::structs::FreezeFlag;
use jf_cap::{
    errors::TxnApiError,
    keys::{FreezerPubKey, UserAddress, UserKeyPair, UserPubKey, ViewerPubKey},
    structs::{Amount, AssetCode},
};
use jf_utils::tagged_blob;

use num_bigint::{BigInt, Sign};
use num_traits::identities::{One, Zero};
use primitive_types::U256;
#[cfg(test)]
use reef::cap;
use reef::{traits::Ledger, types::*};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::ops::Mul;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Default,
    Hash,
    Eq,
    From,
    Into,
    Add,
    AddAssign,
    Sub,
    SubAssign,
    MulAssign,
    Div,
    DivAssign,
    Rem,
    RemAssign,
    PartialOrd,
    Ord,
    Sum,
    Deserialize,
    Serialize,
    Display,
    FromStr,
    LowerHex,
)]
#[serde(from = "u128", into = "u128")]
#[from(types(u128, u64, u32, u8))]
#[into(types(u128))]
pub struct RecordAmount(pub Amount);

impl RecordAmount {
    pub fn max() -> Self {
        (2u128.pow(127) - 1).into()
    }

    pub fn is_positive(&self) -> bool {
        !self.is_zero()
    }
}

impl Zero for RecordAmount {
    fn zero() -> Self {
        0u128.into()
    }

    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

impl One for RecordAmount {
    fn one() -> Self {
        1u128.into()
    }
}

impl<T: Into<RecordAmount>> Mul<T> for RecordAmount {
    type Output = Self;

    fn mul(self, other: T) -> Self {
        (u128::from(self) * u128::from(other.into())).into()
    }
}

impl From<RecordAmount> for U256 {
    fn from(amt: RecordAmount) -> U256 {
        u128::from(amt).into()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ConvertRecordAmountError {
    OutOfRange,
}

impl TryFrom<U256> for RecordAmount {
    type Error = ConvertRecordAmountError;

    fn try_from(u: U256) -> Result<Self, Self::Error> {
        if u <= Self::max().into() {
            Ok(u.as_u128().into())
        } else {
            Err(ConvertRecordAmountError::OutOfRange)
        }
    }
}

impl TryFrom<BigInt> for RecordAmount {
    type Error = ConvertRecordAmountError;

    fn try_from(i: BigInt) -> Result<Self, Self::Error> {
        if i >= 0u64.into() {
            bigint_to_u256(i).try_into()
        } else {
            Err(ConvertRecordAmountError::OutOfRange)
        }
    }
}

// This is to make numeric literal inference work.
//
// When an integer literal without a suffix is provided, it defaults to `i32`. Where an
// Into<RecordAmount> is required, such as in the wallet's public transaction building interface,
// this trait impl can be used to do the conversion.
impl From<i32> for RecordAmount {
    fn from(i: i32) -> Self {
        assert!(i >= 0);
        (i as u128).into()
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum TransactionError {
    InsufficientBalance {
        asset: AssetCode,
        required: U256,
        actual: U256,
    },
    Fragmentation {
        asset: AssetCode,
        amount: U256,
        suggested_amount: U256,
        max_records: usize,
    },
    TooManyOutputs {
        asset: AssetCode,
        max_records: usize,
        num_receivers: usize,
        num_change_records: usize,
    },
    InvalidSize {
        asset: AssetCode,
        num_inputs_required: usize,
        num_inputs_actual: usize,
        num_outputs_required: usize,
        num_outputs_actual: usize,
    },
    NoFitKey {
        num_inputs: usize,
        num_outputs: usize,
    },
    CryptoError {
        source: TxnApiError,
    },
    InvalidViewerKey {
        my_key: ViewerPubKey,
        asset_key: ViewerPubKey,
    },
    InvalidFreezerKey {
        my_key: FreezerPubKey,
        asset_key: FreezerPubKey,
    },
}

/// Find records which can be the input to a transaction, matching the given parameters.
pub fn input_records<'a, L: Ledger + 'a>(
    records: &'a Records,
    asset: &'a AssetCode,
    owner: &'a UserAddress,
    frozen: FreezeFlag,
    now: u64,
) -> Option<impl Iterator<Item = Record> + 'a> {
    let spendable = records.get_spendable::<L>(&*asset, owner, frozen);
    spendable.map(|r| r.into_iter().filter(move |record| !record.on_hold(now)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,
    AwaitingMemos,
    Retired,
    Rejected,
    Unknown,
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::AwaitingMemos => write!(f, "accepted, waiting for owner memos"),
            Self::Retired => write!(f, "accepted"),
            Self::Rejected => write!(f, "rejected"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl TransactionStatus {
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Retired | Self::Rejected)
    }

    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Retired)
    }
}

#[ser_test(arbitrary, types(cap::Ledger))]
#[tagged_blob("TXUID")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TransactionUID<L: Ledger>(pub TransactionHash<L>);

impl<L: Ledger> PartialEq<TransactionUID<L>> for TransactionUID<L> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<L: Ledger> Eq for TransactionUID<L> {}

impl<L: Ledger> Hash for TransactionUID<L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.0, state)
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for TransactionUID<L>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

pub struct TransferSpec<'a> {
    /// List of key_pairs that will be used to find the records for the transfer.
    ///
    /// The list may contain multiple key_pairs, or only one key_pair in which case only the
    /// associated records can be transferred.
    pub sender_key_pairs: &'a Vec<UserKeyPair>,
    pub asset: &'a AssetCode,
    pub receivers: &'a [(UserPubKey, RecordAmount, bool)],
    pub fee: RecordAmount,
    pub bound_data: Vec<u8>,
    pub xfr_size_requirement: Option<(usize, usize)>,
}

// (block_id, txn_id, [(uid, remember)])
pub type CommittedTxn<'a> = (u64, u64, &'a mut [(u64, bool)]);
// a never expired target
pub const UNEXPIRED_VALID_UNTIL: u64 = 2u64.pow(jf_cap::constants::MAX_TIMESTAMP_LEN as u32) - 1;

pub(crate) fn bigint_to_u256(i: BigInt) -> U256 {
    let (sign, mut digits) = i.to_u64_digits();
    assert_ne!(sign, Sign::Minus);
    assert!(digits.len() <= 4);
    digits.resize(4, 0);
    U256(digits.try_into().unwrap())
}
