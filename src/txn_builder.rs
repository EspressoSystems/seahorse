// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Transaction building.
//!
//! This module defines the subset of ledger state required by a keystore to build transactions, and
//! provides an interface for building them.
use crate::{
    events::EventIndex,
    sparse_merkle_tree::SparseMerkleTree,
    transactions::{SignedMemos, Transaction, TransactionParams, Transactions},
    KeystoreError,
};
use arbitrary::{Arbitrary, Unstructured};
use arbitrary_wrappers::*;
use ark_serialize::*;
use chrono::Local;
use derive_more::*;
use espresso_macros::ser_test;
use jf_cap::{
    errors::TxnApiError,
    freeze::{FreezeNote, FreezeNoteInput},
    keys::{FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair, UserPubKey, ViewerPubKey},
    mint::MintNote,
    proof::freeze::FreezeProvingKey,
    proof::{mint::MintProvingKey, transfer::TransferProvingKey},
    sign_receiver_memos,
    structs::{
        Amount, AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, FeeInput, FreezeFlag,
        Nullifier, ReceiverMemo, RecordCommitment, RecordOpening, TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    AccMemberWitness, KeyPair, MerkleLeafProof, Signature,
};
use jf_utils::tagged_blob;
use key_set::KeySet;
use num_bigint::{BigInt, Sign};
use num_traits::identities::{One, Zero};
use primitive_types::U256;
use rand_chacha::ChaChaRng;
#[cfg(test)]
use reef::cap;
use reef::{
    traits::{Ledger, Transaction as _, TransactionKind as _, Validator as _},
    types::*,
};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;
use std::ops::{Index, IndexMut, Mul};

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

#[ser_test(arbitrary, ark(false))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct RecordInfo {
    pub ro: RecordOpening,
    pub uid: u64,
    pub nullifier: Nullifier,
    // if Some(t), this record is on hold until the validator timestamp surpasses `t`, because this
    // record has been used as an input to a transaction that is not yet confirmed.
    pub hold_until: Option<u64>,
}

impl RecordInfo {
    pub fn on_hold(&self, now: u64) -> bool {
        matches!(self.hold_until, Some(t) if t > now)
    }

    pub fn hold_until(&mut self, until: u64) {
        self.hold_until = Some(until);
    }

    pub fn unhold(&mut self) {
        self.hold_until = None;
    }

    pub fn amount(&self) -> RecordAmount {
        self.ro.amount.into()
    }
}

impl<'a> Arbitrary<'a> for RecordInfo {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            ro: u.arbitrary::<ArbitraryRecordOpening>()?.into(),
            uid: u.arbitrary()?,
            nullifier: u.arbitrary::<ArbitraryNullifier>()?.into(),
            hold_until: u.arbitrary()?,
        })
    }
}

#[ser_test(ark(false))]
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(from = "Vec<RecordInfo>", into = "Vec<RecordInfo>")]
pub struct RecordDatabase {
    // all records in the database, by uid. We use a BTreeMap so that equivalent databases have a
    // consistent ordering for iteration and comparison.
    record_info: BTreeMap<u64, RecordInfo>,
    // record (size, uid) indexed by asset type, owner, and freeze status, for easy allocation as
    // transfer or freeze inputs. The records for each asset are ordered by increasing size, which
    // makes it easy to implement a worst-fit allocator that minimizes fragmentation.
    asset_records: HashMap<(AssetCode, UserAddress, FreezeFlag), BTreeSet<(RecordAmount, u64)>>,
    // record uids indexed by nullifier, for easy removal when confirmed as transfer inputs
    nullifier_records: HashMap<Nullifier, u64>,
}

impl RecordDatabase {
    // Panic if the auxiliary indexes are not consistent with the authoritative `record_info`.
    #[cfg(any(test, debug_assertions))]
    fn check(&self) {
        for (uid, record) in &self.record_info {
            assert_eq!(*uid, record.uid);
            assert!(self.asset_records[&(
                record.ro.asset_def.code,
                record.ro.pub_key.address(),
                record.ro.freeze_flag
            )]
                .contains(&(record.amount(), *uid)));
            assert_eq!(*uid, self.nullifier_records[&record.nullifier]);
        }
        assert_eq!(
            self.record_info.len(),
            self.asset_records
                .values()
                .map(|set| set.len())
                .sum::<usize>()
        );
        assert_eq!(self.record_info.len(), self.nullifier_records.len());
    }

    pub fn iter(&self) -> impl Iterator<Item = &RecordInfo> {
        self.record_info.values()
    }

    /// Find records which can be the input to a transaction, matching the given parameters.
    pub fn input_records<'a>(
        &'a self,
        asset: &AssetCode,
        owner: &UserAddress,
        frozen: FreezeFlag,
        now: u64,
    ) -> impl Iterator<Item = &'a RecordInfo> {
        self.asset_records
            .get(&(*asset, owner.clone(), frozen))
            .into_iter()
            .flatten()
            .rev()
            .filter_map(move |(_, uid)| {
                let record = &self.record_info[uid];
                if record.on_hold(now) {
                    // Skip records that are on hold
                    None
                } else {
                    Some(record)
                }
            })
    }
    /// Find a record with exactly the requested amount, which can be the input to a transaction,
    /// matching the given parameters.
    pub fn input_record_with_amount(
        &self,
        asset: &AssetCode,
        owner: &UserAddress,
        frozen: FreezeFlag,
        amount: RecordAmount,
        now: u64,
    ) -> Option<&RecordInfo> {
        let unspent_records = self.asset_records.get(&(*asset, owner.clone(), frozen))?;
        let exact_matches = unspent_records.range((amount, 0)..(amount + 1u64.into(), 0));
        for (match_amount, uid) in exact_matches {
            assert_eq!(*match_amount, amount);
            let record = &self.record_info[uid];
            assert_eq!(record.amount(), amount);
            if record.on_hold(now) {
                continue;
            }
            return Some(record);
        }

        None
    }

    pub fn record_with_nullifier(&self, nullifier: &Nullifier) -> Option<&RecordInfo> {
        let uid = self.nullifier_records.get(nullifier)?;
        self.record_info.get(uid)
    }

    pub fn record_with_nullifier_mut(&mut self, nullifier: &Nullifier) -> Option<&mut RecordInfo> {
        let uid = self.nullifier_records.get(nullifier)?;
        self.record_info.get_mut(uid)
    }

    pub fn insert(&mut self, ro: RecordOpening, uid: u64, key_pair: &UserKeyPair) {
        assert_eq!(key_pair.pub_key(), ro.pub_key);
        let nullifier = key_pair.nullify(
            ro.asset_def.policy_ref().freezer_pub_key(),
            uid,
            &RecordCommitment::from(&ro),
        );
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    pub fn insert_freezable(&mut self, ro: RecordOpening, uid: u64, key_pair: &FreezerKeyPair) {
        let nullifier = key_pair.nullify(&ro.pub_key.address(), uid, &RecordCommitment::from(&ro));
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    pub fn insert_with_nullifier(&mut self, ro: RecordOpening, uid: u64, nullifier: Nullifier) {
        self.insert_record(RecordInfo {
            ro,
            uid,
            nullifier,
            hold_until: None,
        });
    }

    pub fn insert_record(&mut self, rec: RecordInfo) {
        if let Some(old) = self.record_info.insert(rec.uid, rec.clone()) {
            assert_eq!(rec, old);
            return;
        }
        self.asset_records
            .entry((
                rec.ro.asset_def.code,
                rec.ro.pub_key.address(),
                rec.ro.freeze_flag,
            ))
            .or_insert_with(BTreeSet::new)
            .insert((rec.ro.amount.into(), rec.uid));
        self.nullifier_records.insert(rec.nullifier, rec.uid);

        #[cfg(any(test, debug_assertions))]
        self.check();
    }

    pub fn remove_by_nullifier(&mut self, nullifier: Nullifier) -> Option<RecordInfo> {
        self.nullifier_records.remove(&nullifier).map(|uid| {
            let record = self.record_info.remove(&uid).unwrap();

            // Remove the record from `asset_records`, and if the sub-collection it was in becomes
            // empty, remove the whole collection.
            let asset_key = &(
                record.ro.asset_def.code,
                record.ro.pub_key.address(),
                record.ro.freeze_flag,
            );
            let asset_records = self.asset_records.get_mut(asset_key).unwrap();
            assert!(asset_records.remove(&(record.amount(), uid)));
            if asset_records.is_empty() {
                self.asset_records.remove(asset_key);
            }

            #[cfg(any(test, debug_assertions))]
            self.check();

            record
        })
    }
}

impl Index<Nullifier> for RecordDatabase {
    type Output = RecordInfo;
    fn index(&self, index: Nullifier) -> &RecordInfo {
        self.record_with_nullifier(&index).unwrap()
    }
}

impl IndexMut<Nullifier> for RecordDatabase {
    fn index_mut(&mut self, index: Nullifier) -> &mut RecordInfo {
        self.record_with_nullifier_mut(&index).unwrap()
    }
}

impl FromIterator<RecordInfo> for RecordDatabase {
    fn from_iter<T: IntoIterator<Item = RecordInfo>>(iter: T) -> Self {
        let mut db = Self::default();
        for info in iter {
            db.insert_record(info)
        }
        db
    }
}

impl From<Vec<RecordInfo>> for RecordDatabase {
    fn from(records: Vec<RecordInfo>) -> Self {
        records.into_iter().collect()
    }
}

impl From<RecordDatabase> for Vec<RecordInfo> {
    fn from(db: RecordDatabase) -> Self {
        db.record_info.into_values().collect()
    }
}

impl<'a> Arbitrary<'a> for RecordDatabase {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<Vec<RecordInfo>>()?))
    }
}

impl PartialEq<Self> for RecordDatabase {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(any(test, debug_assertions))]
        self.check();

        self.record_info == other.record_info
    }
}

impl Debug for RecordDatabase {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let hline = String::from_iter(std::iter::repeat('-').take(80));
        writeln!(f, "{}", hline)?;
        for (i, record) in self.iter().enumerate() {
            writeln!(f, "Record {}", i + 1)?;
            writeln!(f, "  Owner: {}", record.ro.pub_key)?;
            writeln!(f, "  Asset: {}", record.ro.asset_def.code)?;
            writeln!(f, "  Amount: {}", record.ro.amount)?;
            writeln!(f, "  UID: {}", record.uid)?;
            writeln!(f, "  Nullifier: {}", record.nullifier)?;
            writeln!(f, "  On hold until: {:?}", record.hold_until)?;
            writeln!(f, "{}", hline)?;
        }
        Ok(())
    }
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

#[ser_test(arbitrary, types(cap::Ledger), ark(false))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TransactionState<L: Ledger> {
    // sequence number of the last event processed
    pub now: EventIndex,
    // validator
    pub validator: Validator<L>,
    // all records we care about, including records we own, records we have viewed, and records we
    // can freeze or unfreeze
    pub records: RecordDatabase,
    // sparse nullifier set Merkle tree mirrored from validators
    pub nullifiers: NullifierSet<L>,
    // sparse record Merkle tree mirrored from validators
    pub record_mt: SparseMerkleTree,
}

impl<L: Ledger> PartialEq<Self> for TransactionState<L> {
    fn eq(&self, other: &Self) -> bool {
        self.now == other.now
            && self.validator == other.validator
            && self.records == other.records
            && self.nullifiers == other.nullifiers
            && self.record_mt == other.record_mt
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for TransactionState<L>
where
    Validator<L>: Arbitrary<'a>,
    NullifierSet<L>: Arbitrary<'a>,
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            now: u.arbitrary()?,
            validator: u.arbitrary()?,
            records: u.arbitrary()?,
            nullifiers: u.arbitrary()?,
            record_mt: u.arbitrary()?,
        })
    }
}

impl<L: Ledger> TransactionState<L> {
    pub fn balance(&self, asset: &AssetCode, pub_key: &UserPubKey, frozen: FreezeFlag) -> U256 {
        self.records
            .input_records(asset, &pub_key.address(), frozen, self.validator.now())
            .fold(U256::zero(), |sum, record| sum + record.amount())
    }

    pub fn block_height(&self) -> u64 {
        self.validator.now()
    }

    pub fn define_asset<'b>(
        &'b mut self,
        rng: &mut ChaChaRng,
        description: &'b [u8],
        policy: AssetPolicy,
    ) -> Result<(AssetCodeSeed, AssetDefinition), TransactionError> {
        let seed = AssetCodeSeed::generate(rng);
        let code = AssetCode::new_domestic(seed, description);
        let asset_definition = AssetDefinition::new(code, policy).context(CryptoSnafu)?;
        Ok((seed, asset_definition))
    }

    pub fn add_pending_transaction(
        &mut self,
        transactions: &mut Transactions<L>,
        txn: &reef::Transaction<L>,
        mut info: TransactionParams<L>,
    ) -> Result<Transaction<L>, KeystoreError<L>> {
        let now = self.validator.now();
        let timeout = now + (L::record_root_history() as u64);
        let uid = TransactionUID(txn.hash());

        for nullifier in txn.input_nullifiers() {
            // hold the record corresponding to this nullifier until the transaction is committed,
            // rejected, or expired.
            if let Some(record) = self.records.record_with_nullifier_mut(&nullifier) {
                assert!(!record.on_hold(now));
                record.hold_until(timeout);
            }
        }
        info.timeout = Some(timeout);
        let stored_txn = transactions.create(uid, info);
        Ok(stored_txn?.clone())
    }

    pub fn clear_pending_transaction<'t>(
        &mut self,
        transactions: &mut Transactions<L>,
        txn: &reef::Transaction<L>,
        res: &Option<CommittedTxn<'t>>,
    ) -> Option<Transaction<L>> {
        let now = self.validator.now();

        let pending = transactions.get(&TransactionUID::<L>(txn.hash())).ok();
        for nullifier in txn.input_nullifiers() {
            if let Some(record) = self.records.record_with_nullifier_mut(&nullifier) {
                if pending.is_some() {
                    // If we started this transaction, all of its inputs should have been on hold,
                    // to preserve the invariant that all input nullifiers of all pending
                    // transactions are on hold.
                    assert!(record.on_hold(now));

                    if res.is_none() {
                        // If the transaction was not accepted for any reason, its nullifiers have
                        // not been spent, so remove the hold we placed on them.
                        record.unhold();
                    }
                } else {
                    // This isn't even our transaction.
                    assert!(!record.on_hold(now));
                }
            }
        }

        pending
    }

    pub fn transfer<'a, 'k>(
        &mut self,
        spec: TransferSpec<'k>,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        rng: &mut ChaChaRng,
    ) -> Result<(TransferNote, TransactionParams<L>), TransactionError> {
        if *spec.asset == AssetCode::native() {
            self.transfer_native(spec, proving_keys, rng)
        } else {
            self.transfer_non_native(spec, proving_keys, rng)
        }
    }

    fn transfer_native<'a, 'k>(
        &mut self,
        spec: TransferSpec<'k>,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        rng: &mut ChaChaRng,
    ) -> Result<(TransferNote, TransactionParams<L>), TransactionError> {
        let total_output_amount: U256 = spec
            .receivers
            .iter()
            .fold(U256::zero(), |sum, (_, amount, _)| sum + *amount)
            + spec.fee;

        // find input records which account for at least the total amount, and possibly some change.
        let records = self.find_records(
            &AssetCode::native(),
            spec.sender_key_pairs,
            FreezeFlag::Unfrozen,
            total_output_amount,
            None,
        )?;
        let mut inputs = Vec::new();
        let mut input_ros = Vec::new();
        for (owner_key_pair, input_records, _) in &records {
            // prepare inputs
            for (ro, uid) in input_records {
                let acc_member_witness = self.get_merkle_proof(*uid);
                inputs.push(TransferNoteInput {
                    ro: ro.clone(),
                    acc_member_witness,
                    owner_keypair: owner_key_pair,
                    cred: None,
                });
                input_ros.push(ro.clone());
            }
        }

        // prepare outputs, excluding fee change (which will be automatically generated)
        let mut outputs = Vec::new();
        for (pub_key, amount, _) in spec.receivers.iter() {
            outputs.push(RecordOpening::new(
                rng,
                (*amount).into(),
                AssetDefinition::native(),
                pub_key.clone(),
                FreezeFlag::Unfrozen,
            ));
        }

        // find a proving key which can handle this transaction size
        let (proving_key, dummy_inputs) = Self::xfr_proving_key(
            rng,
            records[0].0.pub_key(),
            proving_keys,
            &AssetDefinition::native(),
            &mut inputs,
            &mut outputs,
            spec.xfr_size_requirement,
            false,
        )?;

        // pad with dummy inputs if necessary
        let dummy_inputs = (0..dummy_inputs)
            .map(|_| RecordOpening::dummy(rng, FreezeFlag::Unfrozen))
            .collect::<Vec<_>>();
        for (ro, owner_key_pair) in &dummy_inputs {
            let dummy_input = TransferNoteInput {
                ro: ro.clone(),
                acc_member_witness: AccMemberWitness::dummy(L::merkle_height()),
                owner_keypair: owner_key_pair,
                cred: None,
            };
            inputs.push(dummy_input);
        }

        // generate transfer note and receiver memos
        let (note, kp, fee_change_ro) = TransferNote::generate_native(
            rng,
            inputs,
            &outputs,
            spec.fee.into(),
            UNEXPIRED_VALID_UNTIL,
            proving_key,
        )
        .context(CryptoSnafu)?;

        let fee_change = fee_change_ro.amount;
        let outputs: Vec<_> = vec![fee_change_ro]
            .into_iter()
            .chain(outputs.into_iter())
            .collect();
        let gen_memos =
            // Always generate a memo for the fee change.
            std::iter::once(true)
            // Generate memos for the receiver outputs if they are not to be burned.
            .chain(spec.receivers.iter().map(|(_, _, burn)| !*burn));
        let (memos, sig) = self.generate_memos(&outputs, gen_memos, rng, &kp)?;

        // Build auxiliary info.
        let owner_addresses = spec
            .sender_key_pairs
            .iter()
            .map(|key_pair| key_pair.address())
            .collect::<Vec<UserAddress>>();
        let txn_params = TransactionParams {
            timeout: None,
            status: TransactionStatus::Pending,
            signed_memos: Some(SignedMemos { memos, sig }),
            inputs: input_ros,
            outputs,
            time: Local::now(),
            asset: AssetCode::native(),
            kind: TransactionKind::<L>::send(),
            senders: owner_addresses,
            receivers: spec
                .receivers
                .iter()
                .map(|(pub_key, amount, _)| (pub_key.address(), *amount))
                .collect(),
            fee_change: Some(fee_change.into()),
            asset_change: Some(RecordAmount::zero()),
        };
        Ok((note, txn_params))
    }

    fn transfer_non_native<'a, 'k>(
        &mut self,
        spec: TransferSpec<'k>,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        rng: &mut ChaChaRng,
    ) -> Result<(TransferNote, TransactionParams<L>), TransactionError> {
        assert_ne!(
            *spec.asset,
            AssetCode::native(),
            "call `transfer_native()` instead"
        );
        let total_output_amount: U256 = spec
            .receivers
            .iter()
            .fold(U256::zero(), |sum, (_, amount, _)| sum + *amount);

        // find input records of the asset type to spend (this does not include the fee input)
        let records = self.find_records(
            spec.asset,
            spec.sender_key_pairs,
            FreezeFlag::Unfrozen,
            total_output_amount,
            None,
        )?;

        let asset = records[0].1[0].0.asset_def.clone();

        let mut inputs = Vec::new();
        let mut input_ros = Vec::new();
        let mut change_ro = None;
        for (owner_key_pair, input_records, change) in &records {
            // prepare inputs
            for (ro, uid) in input_records.iter() {
                let witness = self.get_merkle_proof(*uid);
                inputs.push(TransferNoteInput {
                    ro: ro.clone(),
                    acc_member_witness: witness,
                    owner_keypair: owner_key_pair,
                    cred: None, // TODO support credentials
                });
                input_ros.push(ro.clone());
            }

            // change in the asset type being transfered (not fee change)
            if change.is_positive() {
                let me = owner_key_pair.pub_key();
                change_ro = Some(RecordOpening::new(
                    rng,
                    (*change).into(),
                    asset.clone(),
                    me,
                    FreezeFlag::Unfrozen,
                ));
            }
        }
        let fee_input = self.find_fee_input(spec.sender_key_pairs, spec.fee)?;

        // prepare outputs, excluding fee change (which will be automatically generated)
        let mut outputs = Vec::new();
        for (pub_key, amount, _) in spec.receivers.iter() {
            outputs.push(RecordOpening::new(
                rng,
                (*amount).into(),
                asset.clone(),
                pub_key.clone(),
                FreezeFlag::Unfrozen,
            ));
        }
        if let Some(ro) = change_ro.clone() {
            outputs.push(ro);
        }

        // find a proving key which can handle this transaction size
        let (proving_key, dummy_inputs) = Self::xfr_proving_key(
            rng,
            records[0].0.pub_key(),
            proving_keys,
            &asset,
            &mut inputs,
            &mut outputs,
            spec.xfr_size_requirement,
            change_ro.is_some(),
        )?;

        // pad with dummy inputs if necessary
        let rng = &mut rng.clone();
        let dummy_inputs = (0..dummy_inputs)
            .map(|_| RecordOpening::dummy(rng, FreezeFlag::Unfrozen))
            .collect::<Vec<_>>();
        for (ro, owner_key_pair) in &dummy_inputs {
            let dummy_input = TransferNoteInput {
                ro: ro.clone(),
                acc_member_witness: AccMemberWitness::dummy(L::merkle_height()),
                owner_keypair: owner_key_pair,
                cred: None,
            };
            inputs.push(dummy_input);
        }

        // generate transfer note and receiver memos
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(rng, fee_input, spec.fee.into()).unwrap();
        let (note, sig_key_pair) = TransferNote::generate_non_native(
            rng,
            inputs,
            &outputs,
            fee_info,
            UNEXPIRED_VALID_UNTIL,
            proving_key,
            spec.bound_data.clone(),
        )
        .context(CryptoSnafu)?;

        let fee_change = fee_out_rec.amount;
        let asset_change = match &change_ro {
            Some(ro) => ro.amount.into(),
            None => RecordAmount::zero(),
        };
        let outputs: Vec<_> = vec![fee_out_rec]
            .into_iter()
            .chain(outputs.into_iter())
            .collect();
        let gen_memos =
            // Always generate a memo for the fee change. 
            std::iter::once(true)
            // Generate memos for the receiver outputs if they are not to be burned.
            .chain(spec.receivers.iter().map(|(_, _, burn)| !*burn))
            // Generate a memo for the change output if there is one.
            .chain(change_ro.map(|_| true));
        let (memos, sig) = self.generate_memos(&outputs, gen_memos, rng, &sig_key_pair)?;

        // Build auxiliary info.
        let owner_addresses = spec
            .sender_key_pairs
            .iter()
            .map(|key_pair| key_pair.address())
            .collect::<Vec<UserAddress>>();
        let txn_params = TransactionParams {
            timeout: None,
            status: TransactionStatus::Pending,
            signed_memos: Some(SignedMemos { memos, sig }),
            inputs: input_ros,
            outputs,
            time: Local::now(),
            asset: asset.code,
            kind: TransactionKind::<L>::send(),
            senders: owner_addresses,
            receivers: spec
                .receivers
                .iter()
                .map(|(pub_key, amount, _)| (pub_key.address(), *amount))
                .collect(),
            fee_change: Some(fee_change.into()),
            asset_change: Some(asset_change),
        };
        Ok((note, txn_params))
    }

    fn generate_memos(
        &mut self,
        records: &[RecordOpening],
        include: impl IntoIterator<Item = bool>,
        rng: &mut ChaChaRng,
        sig_key_pair: &KeyPair,
    ) -> Result<(Vec<Option<ReceiverMemo>>, Signature), TransactionError> {
        let memos: Vec<_> = records
            .iter()
            // Any remaining outputs beyond the length of `include` are dummy outputs. We do want to
            // generate memos for these, as not doing so could reveal to observers that these
            // outputs are dummies, which is supposed to be private information.
            .zip(include.into_iter().chain(std::iter::repeat(true)))
            .map(|(ro, include)| {
                if include {
                    Ok(Some(
                        ReceiverMemo::from_ro(rng, ro, &[]).context(CryptoSnafu)?,
                    ))
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sig = sign_receiver_memos(
            sig_key_pair,
            &memos.iter().flatten().cloned().collect::<Vec<_>>(),
        )
        .context(CryptoSnafu)?;

        Ok((memos, sig))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mint<'a>(
        &mut self,
        sending_keys: &[UserKeyPair],
        proving_key: &MintProvingKey<'a>,
        fee: RecordAmount,
        asset: &(AssetDefinition, AssetCodeSeed, Vec<u8>),
        amount: RecordAmount,
        receiver: UserPubKey,
        rng: &mut ChaChaRng,
    ) -> Result<(MintNote, TransactionParams<L>), TransactionError> {
        let (asset_def, seed, asset_description) = asset;
        let mint_record = RecordOpening::new(
            rng,
            amount.into(),
            asset_def.clone(),
            receiver.clone(),
            FreezeFlag::Unfrozen,
        );

        let fee_input = self.find_fee_input(sending_keys, fee)?;
        let fee_rec = fee_input.ro.clone();
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(rng, fee_input, fee.into()).unwrap();
        let rng = rng;
        let (note, sig_key_pair) = jf_cap::mint::MintNote::generate(
            rng,
            mint_record.clone(),
            *seed,
            asset_description.as_slice(),
            fee_info,
            proving_key,
        )
        .context(CryptoSnafu)?;
        let outputs = vec![fee_out_rec, mint_record];
        let (memos, sig) = self.generate_memos(&outputs, vec![true, true], rng, &sig_key_pair)?;

        // Build auxiliary info.
        let txn_params = TransactionParams {
            timeout: None,
            status: TransactionStatus::Pending,
            signed_memos: Some(SignedMemos { memos, sig }),
            inputs: vec![fee_rec.clone()],
            outputs,
            time: Local::now(),
            asset: asset_def.code,
            kind: TransactionKind::<L>::send(),
            senders: vec![fee_rec.pub_key.address()],
            receivers: vec![(receiver.address(), amount)],
            fee_change: Some(fee_rec.amount.into()),
            asset_change: Some(RecordAmount::zero()),
        };
        Ok((note, txn_params))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn freeze_or_unfreeze<'a>(
        &mut self,
        sending_keys: &[UserKeyPair],
        freezer_key_pair: &FreezerKeyPair,
        proving_keys: &KeySet<FreezeProvingKey<'a>, key_set::OrderByOutputs>,
        fee: RecordAmount,
        asset: &AssetDefinition,
        amount: U256,
        owner: UserAddress,
        outputs_frozen: FreezeFlag,
        rng: &mut ChaChaRng,
    ) -> Result<(FreezeNote, TransactionParams<L>), TransactionError> {
        // find input records of the asset type to freeze (this does not include the fee input)
        let inputs_frozen = match outputs_frozen {
            FreezeFlag::Frozen => FreezeFlag::Unfrozen,
            FreezeFlag::Unfrozen => FreezeFlag::Frozen,
        };
        let (input_records, _) = self.find_records_with_pub_key(
            &asset.code,
            &owner,
            inputs_frozen,
            amount,
            None,
            false,
        )?;

        // prepare inputs
        let mut inputs = vec![];
        for (ro, uid) in input_records.iter() {
            let witness = self.get_merkle_proof(*uid);
            inputs.push(FreezeNoteInput {
                ro: ro.clone(),
                acc_member_witness: witness,
                keypair: freezer_key_pair,
            })
        }
        let fee_input = self.find_fee_input(sending_keys, fee)?;
        let fee_address = fee_input.owner_keypair.address();

        // find a proving key which can handle this transaction size
        let proving_key =
            Self::freeze_proving_key(rng, proving_keys, asset, &mut inputs, freezer_key_pair)?;

        // generate transfer note and receiver memos
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(rng, fee_input, fee.into()).unwrap();
        let (note, sig_key_pair, outputs) =
            FreezeNote::generate(rng, inputs, fee_info, proving_key).context(CryptoSnafu)?;
        let fee_change = fee_out_rec.amount;
        let outputs = std::iter::once(fee_out_rec)
            .chain(outputs)
            .collect::<Vec<_>>();
        let gen_memos = outputs.iter().map(|_| true);
        let (memos, sig) = self.generate_memos(&outputs, gen_memos, rng, &sig_key_pair)?;

        // Build auxiliary info.
        let txn_params = TransactionParams {
            timeout: None,
            status: TransactionStatus::Pending,
            signed_memos: Some(SignedMemos { memos, sig }),
            inputs: input_records.iter().cloned().map(|(ro, _)| ro).collect(),
            outputs,
            time: Local::now(),
            asset: asset.code,
            kind: match outputs_frozen {
                FreezeFlag::Frozen => TransactionKind::<L>::freeze(),
                FreezeFlag::Unfrozen => TransactionKind::<L>::unfreeze(),
            },
            senders: vec![fee_address],
            receivers: input_records
                .iter()
                .map(|(ro, _)| (owner.clone(), ro.amount.into()))
                .collect(),
            fee_change: Some(fee_change.into()),
            asset_change: Some(RecordAmount::zero()),
        };
        Ok((note, txn_params))
    }

    pub fn forget_merkle_leaf(&mut self, leaf: u64) {
        self.record_mt.forget(leaf);
    }

    #[must_use]
    pub fn remember_merkle_leaf(&mut self, leaf: u64, proof: &MerkleLeafProof) -> bool {
        self.record_mt.remember(leaf, proof).is_ok()
    }

    pub fn append_merkle_leaves(&mut self, comms: impl IntoIterator<Item = RecordCommitment>) {
        self.record_mt.extend(comms)
    }

    /// Returns a list of record openings and UIDs, and the change amount.
    ///
    /// `allow_insufficient`
    /// * If true, the change amount may be negative, meaning the provided address doesn't have
    /// sufficient balance, which isn't necessarily an error since a total balance can be
    /// aggragated by multiple addresses.
    /// * Otherwise, the change amount must be nonnegative.
    #[allow(clippy::type_complexity)]
    fn find_records_with_pub_key(
        &self,
        asset: &AssetCode,
        owner: &UserAddress,
        frozen: FreezeFlag,
        amount: U256,
        max_records: Option<usize>,
        allow_insufficient: bool,
    ) -> Result<(Vec<(RecordOpening, u64)>, BigInt), TransactionError> {
        let now = self.validator.now();

        // If we have a record with the exact size required, use it to avoid
        // fragmenting big records into smaller change records. First make
        // sure the amount can be converted to a RecordAmount, since if it is
        // too big for a single record, then of course we don not have a
        // record of exactly the right size.
        if let Ok(amount) = amount.try_into() {
            if let Some(record) = self
                .records
                .input_record_with_amount(asset, owner, frozen, amount, now)
            {
                return Ok((vec![(record.ro.clone(), record.uid)], BigInt::zero()));
            }
        }

        // Take the biggest records we have until they exceed the required amount, as a heuristic to
        // try and get the biggest possible change record. This is a simple algorithm that
        // guarantees we will always return the minimum number of blocks, and thus we always succeed
        // in making a transaction if it is possible to do so within the allowed number of inputs.
        //
        // This algorithm is not optimal, though. For instance, it's possible we might be able to
        // make exact change using combinations of larger and smaller blocks. We can replace this
        // with something more sophisticated later.
        let mut result = vec![];
        let mut current_amount = U256::zero();
        for record in self.records.input_records(asset, owner, frozen, now) {
            // Skip 0-amount records; they take up slots in the transaction inputs without
            // contributing to the total amount we're trying to consume.
            if record.amount().is_zero() {
                continue;
            }

            if let Some(max_records) = max_records {
                if result.len() >= max_records {
                    // Too much fragmentation: we can't make the required amount using few enough
                    // records. This should be less likely once we implement a better allocation
                    // strategy (or, any allocation strategy).
                    //
                    // In this case, we could either simply return an error, or we could
                    // automatically generate a merge transaction to defragment our assets.
                    // Automatically merging assets would implicitly incur extra transaction fees,
                    // so for now we do the simple, uncontroversial thing and error out.
                    return Err(TransactionError::Fragmentation {
                        asset: *asset,
                        amount,
                        suggested_amount: current_amount,
                        max_records,
                    });
                }
            }
            current_amount += record.amount().into();
            result.push((record.ro.clone(), record.uid));
            if current_amount >= amount {
                return Ok((
                    result,
                    u256_to_signed(current_amount) - u256_to_signed(amount),
                ));
            }
        }

        if allow_insufficient {
            Ok((
                result,
                u256_to_signed(current_amount) - u256_to_signed(amount),
            ))
        } else {
            Err(TransactionError::InsufficientBalance {
                asset: *asset,
                required: amount,
                actual: current_amount,
            })
        }
    }

    #[allow(clippy::type_complexity)]
    fn find_records<'l>(
        &self,
        asset: &AssetCode,
        owner_key_pairs: &'l [UserKeyPair],
        frozen: FreezeFlag,
        amount: U256,
        max_records: Option<usize>,
    ) -> Result<Vec<(&'l UserKeyPair, Vec<(RecordOpening, u64)>, RecordAmount)>, TransactionError>
    {
        let mut records = Vec::new();
        let mut target_amount = amount;

        for owner_key_pair in owner_key_pairs {
            let (input_records, change) = self.find_records_with_pub_key(
                asset,
                &owner_key_pair.pub_key().address(),
                frozen,
                target_amount,
                max_records.map(|max| max - records.len()),
                true,
            )?;
            // A nonnegative change indicates that we've find sufficient records.
            if change >= BigInt::zero() {
                records.push((
                    owner_key_pair,
                    input_records,
                    change
                        .try_into()
                        .expect("got change from more than one record"),
                ));
                return Ok(records);
            }
            if !input_records.is_empty() {
                records.push((owner_key_pair, input_records, RecordAmount::zero()));
            }
            target_amount = bigint_to_u256(-change);
        }

        Err(TransactionError::InsufficientBalance {
            asset: *asset,
            required: amount,
            actual: amount - target_amount,
        })
    }

    /// find a record of the native asset type with enough funds to pay a transaction fee
    ///
    /// The record will be owned by one of the given key pairs.
    fn find_fee_input<'l>(
        &self,
        key_pairs: &'l [UserKeyPair],
        fee: RecordAmount,
    ) -> Result<FeeInput<'l>, TransactionError> {
        let (ro, uid, owner_keypair) = if fee.is_zero() {
            // For 0 fees, the allocation scheme is different than for other kinds of allocations.
            // For one thing, CAP requires one fee input record even if the amount of the record is
            // zero. This differs from other kinds of input records. For transfer inputs, for
            // example, the only thing that matters is the total input amount.
            //
            // Also, when the fee is 0, we know we are going to get the entirety of the fee back as
            // change when the transaction finalizes, so we don't have to worry about avoiding
            // fragmentation due to records being broken up into change. Therefore it is better to
            // use the _smallest_ available record, so the least amount of native balance is on hold
            // while the transaction is pending, rather than the largest available record to try and
            // avoid fragmentation.
            //
            // We can handle both of these constraints by simply finding the smallest native record
            // in any of the available accounts.
            let now = self.validator.now();
            key_pairs
                .iter()
                .flat_map(|key| {
                    // List the spendable native records for this key, and tag them with `key` so
                    // that when we collect records from multiple keys, we remember which key owns
                    // each record.
                    self.records
                        .input_records(
                            &AssetCode::native(),
                            &key.address(),
                            FreezeFlag::Unfrozen,
                            now,
                        )
                        .map(move |record| (record.ro.clone(), record.uid, key))
                })
                // Find the smallest record among all the records from all the keys.
                .min_by_key(|(ro, _, _)| ro.amount)
                // If there weren't any records at all, we simply cannot pay the fee -- even though
                // the fee amount is 0!
                .ok_or(TransactionError::InsufficientBalance {
                    asset: AssetCode::native(),
                    required: fee.into(),
                    actual: U256::zero(),
                })?
        } else {
            // When the fee is nonzero, fee allocation is just like allocation of any other input,
            // and we can call out to the regular record allocation algorithm (using
            // `max_records == Some(1)`, since we cannot break fees into multiple records).
            let mut records = self.find_records(
                &AssetCode::native(),
                key_pairs,
                FreezeFlag::Unfrozen,
                fee.into(),
                Some(1),
            )?;
            assert_eq!(records.len(), 1);
            let (owner_keypair, mut records, _) = records.remove(0);
            assert_eq!(records.len(), 1);
            let (ro, uid) = records.remove(0);
            (ro, uid, owner_keypair)
        };

        Ok(FeeInput {
            ro,
            acc_member_witness: self.get_merkle_proof(uid),
            owner_keypair,
        })
    }

    fn get_merkle_proof(&self, leaf: u64) -> AccMemberWitness {
        // The transaction builder never needs a Merkle proof that isn't guaranteed to already be in the Merkle
        // tree, so this unwrap() should never fail.
        self.record_mt
            .acc_member_witness(leaf)
            .expect_ok()
            .unwrap()
            .1
    }

    // Find a proving key large enough to prove the given transaction, returning the number of dummy
    // inputs needed to pad the transaction.
    //
    // `any_key` - Any key used for padding dummy outputs.
    //
    // `proving_keys` should always be `&self.proving_key`. This is a non-member function in order
    // to prove to the compiler that the result only borrows from `&self.proving_key`, not all of
    // `&self`.
    //
    // `xfr_size_requirement` - If specified, the proving keys must be the exact size.
    #[allow(clippy::too_many_arguments)]
    fn xfr_proving_key<'a, 'k>(
        rng: &mut ChaChaRng,
        any_key: UserPubKey,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        asset: &AssetDefinition,
        inputs: &mut Vec<TransferNoteInput<'k>>,
        outputs: &mut Vec<RecordOpening>,
        xfr_size_requirement: Option<(usize, usize)>,
        change_record: bool,
    ) -> Result<(&'k TransferProvingKey<'a>, usize), TransactionError> {
        let total_output_amount = outputs
            .iter()
            .fold(U256::zero(), |sum, ro| sum + RecordAmount::from(ro.amount));
        // non-native transfers have an extra fee input, which is not included in `inputs`.
        let fee_inputs = if *asset == AssetDefinition::native() {
            0
        } else {
            1
        };
        // both native and non-native transfers have an extra fee change output which is
        // automatically generated and not included in `outputs`.
        let fee_outputs = 1;

        let min_num_inputs = inputs.len() + fee_inputs;
        let min_num_outputs = outputs.len() + fee_outputs;
        match xfr_size_requirement {
            Some((input_size, output_size)) => {
                if (input_size, output_size) != (min_num_inputs, min_num_outputs) {
                    return Err(TransactionError::InvalidSize {
                        asset: asset.code,
                        num_inputs_required: input_size,
                        num_inputs_actual: min_num_inputs,
                        num_outputs_required: output_size,
                        num_outputs_actual: min_num_outputs,
                    });
                }
                match proving_keys.exact_fit_key(input_size, output_size) {
                    Some(key) => Ok((key, 0)),
                    None => Err(TransactionError::NoFitKey {
                        num_inputs: input_size,
                        num_outputs: output_size,
                    }),
                }
            }
            None => {
                let (key_inputs, key_outputs, proving_key) = proving_keys
                    .best_fit_key(min_num_inputs, min_num_outputs)
                    .map_err(|(max_inputs, max_outputs)| {
                        if max_outputs >= min_num_outputs {
                            // If there is a key that can fit the correct number of outputs had we only
                            // managed to find fewer inputs, call this a fragmentation error.
                            TransactionError::Fragmentation {
                                asset: asset.code,
                                amount: total_output_amount,
                                suggested_amount: inputs
                                    .iter()
                                    .take(max_inputs - fee_inputs)
                                    .fold(U256::zero(), |sum, input| {
                                        sum + RecordAmount::from(input.ro.amount)
                                    }),
                                max_records: max_inputs,
                            }
                        } else {
                            // Otherwise, we just have too many outputs for any of our available keys. There
                            // is nothing we can do about that on the transaction builder side.
                            TransactionError::TooManyOutputs {
                                asset: asset.code,
                                max_records: max_outputs,
                                num_receivers: outputs.len() - change_record as usize,
                                num_change_records: 1 + change_record as usize,
                            }
                        }
                    })?;
                assert!(min_num_inputs <= key_inputs);
                assert!(min_num_outputs <= key_outputs);

                if min_num_outputs < key_outputs {
                    // pad with dummy (0-amount) outputs,leaving room for the fee change output
                    loop {
                        outputs.push(RecordOpening::new(
                            rng,
                            0u64.into(),
                            asset.clone(),
                            any_key.clone(),
                            FreezeFlag::Unfrozen,
                        ));
                        if outputs.len() >= key_outputs - fee_outputs {
                            break;
                        }
                    }
                }

                // Return the required number of dummy inputs. We can't easily create the dummy inputs here,
                // because it requires creating a new dummy key pair and then borrowing from the key pair to
                // form the transfer input, so the key pair must be owned by the caller.
                let dummy_inputs = key_inputs.saturating_sub(min_num_inputs);
                Ok((proving_key, dummy_inputs))
            }
        }
    }

    fn freeze_proving_key<'a, 'k>(
        rng: &mut ChaChaRng,
        proving_keys: &'k KeySet<FreezeProvingKey<'a>, key_set::OrderByOutputs>,
        asset: &AssetDefinition,
        inputs: &mut Vec<FreezeNoteInput<'k>>,
        key_pair: &'k FreezerKeyPair,
    ) -> Result<&'k FreezeProvingKey<'a>, TransactionError> {
        let total_output_amount = inputs.iter().fold(U256::zero(), |sum, input| {
            sum + RecordAmount::from(input.ro.amount)
        });

        let num_inputs = inputs.len() + 1; // make sure to include fee input
        let num_outputs = num_inputs; // freeze transactions always have equal outputs and inputs
        let (key_inputs, key_outputs, proving_key) = proving_keys
            .best_fit_key(num_inputs, num_outputs)
            .map_err(|(max_inputs, _)| {
                TransactionError::Fragmentation {
                    asset: asset.code,
                    amount: total_output_amount,
                    suggested_amount: inputs
                        .iter()
                        .take(max_inputs - 1) // leave room for fee input
                        .fold(U256::zero(), |sum, input| {
                            sum + RecordAmount::from(input.ro.amount)
                        }),
                    max_records: max_inputs,
                }
            })?;
        assert!(num_inputs <= key_inputs);
        assert!(num_outputs <= key_outputs);

        if num_inputs < key_inputs {
            // pad with dummy inputs, leaving room for the fee input

            loop {
                let (ro, _) = RecordOpening::dummy(rng, FreezeFlag::Unfrozen);
                inputs.push(FreezeNoteInput {
                    ro,
                    acc_member_witness: AccMemberWitness::dummy(L::merkle_height()),
                    keypair: key_pair,
                });
                if inputs.len() >= key_inputs - 1 {
                    break;
                }
            }
        }

        Ok(proving_key)
    }
}

fn u256_to_signed(u: U256) -> BigInt {
    let mut bytes = [0; 32];
    u.to_little_endian(&mut bytes);
    BigInt::from_bytes_le(Sign::Plus, &bytes)
}

fn bigint_to_u256(i: BigInt) -> U256 {
    let (sign, mut digits) = i.to_u64_digits();
    assert_ne!(sign, Sign::Minus);
    assert!(digits.len() <= 4);
    digits.resize(4, 0);
    U256(digits.try_into().unwrap())
}
