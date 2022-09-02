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
    events::{EventIndex, EventSource, LedgerEvent},
    input_records,
    key_scan::BackgroundKeyScan,
    receive_attached_records, received_memos,
    records::Records,
    sparse_merkle_tree::SparseMerkleTree,
    transactions::{SignedMemos, Transaction, TransactionParams},
    try_open_memos,
    txn_builder::{bigint_to_u256, TransactionStatus, TransferSpec},
    view_transaction, Captures, CommittedTxn, CryptoSnafu, EncryptingResourceAdapter, EventSummary,
    KeystoreBackend, KeystoreError, KeystoreModel, MintInfo, RecordAmount, TransactionError,
    TransactionUID,
};
use ark_std::future::Future;
use atomic_store::{AtomicStoreLoader, RollingLog};
use chrono::Local;
use futures::stream::Stream;
use jf_cap::{
    freeze::{FreezeNote, FreezeNoteInput},
    keys::{FreezerKeyPair, UserAddress, UserKeyPair, UserPubKey, ViewerKeyPair},
    mint::MintNote,
    proof::freeze::FreezeProvingKey,
    proof::{mint::MintProvingKey, transfer::TransferProvingKey},
    sign_receiver_memos,
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, FeeInput, FreezeFlag, ReceiverMemo,
        RecordCommitment, RecordOpening, TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    AccMemberWitness, KeyPair, MerkleLeafProof, MerklePath, Signature, TransactionNote,
};
use key_set::{KeySet, OrderByOutputs, ProverKeySet};
use num_bigint::{BigInt, Sign};
use num_traits::identities::Zero;
use primitive_types::U256;
use rand_chacha::ChaChaRng;
use reef::{
    traits::{
        Block as _, NullifierSet as _, Transaction as _, TransactionKind as _, ValidationError,
        Validator as _,
    },
    types::*,
    TransactionKind, Validator, *,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt;
use std::convert::TryInto;
use std::iter::repeat;
use std::sync::Arc;

/// A never expired target.
pub const UNEXPIRED_VALID_UNTIL: u64 = 2u64.pow(jf_cap::constants::MAX_TIMESTAMP_LEN as u32) - 1;
const ATOMIC_STORE_RETAINED_ENTRIES: u32 = 5;

// #[ser_test(arbitrary, types(cap::Ledger), ark(false))]
// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Clone, Deserialize, Serialize)]
#[serde(bound = "")]
/// The state of the global ledger.
pub struct LedgerState<'a, L: Ledger> {
    // For persistence, the fields in this struct are grouped into two categories based on how they
    // can be efficiently saved to disk:
    // 1. Static data, which never changes once a keystore is created, and so can be written to a
    //    single, static file.
    // 2. Dynamic data, which changes frequently and requires some kind of persistent snapshotting.

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // Static data
    //
    // The proving keys are ordered by number of outputs first and number of inputs second, because
    // the keystore is less flexible with respect to number of outputs. If we are building a
    // transaction and find we have too many inputs we can always generate a merge transaction to
    // defragment, but if the user requests a transaction with N independent outputs, there is
    // nothing we can do to decrease that number. So when searching for an appropriate proving key,
    // we will want to find a key with enough outputs first, and then worry about the number of
    // inputs.
    //
    // We keep the prover keys in an Arc because they are large, constant, and depend only on the
    // universal parameters of the system. This allows sharing them, which drastically decreases the
    // memory requirements of applications that create multiple keystores. This is not very realistic
    // for real applications, but it is very important for tests and costs little.
    //
    /// Proving keys.
    ///
    /// These are the keys used to generate Plonk proofs. There is one key for each transaction
    /// type (mint, freezes with varying numbers of input records, and transfers with varying
    /// numbers of input and output records). The supported transaction types must match the
    /// transaction types supported by the verifying keys maintained by validators.
    ///
    /// These keys are constructed when the keystore is created, and they never change afterwards.
    pub proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // Dynamic data
    //
    /// Index of the last event processed.
    pub now: EventIndex,
    /// The Validator.
    pub validator: Validator<L>,
    /// Sparse record Merkle tree mirrored from validators.
    pub record_mt: SparseMerkleTree,
    /// Sparse nullifier set Merkle tree mirrored from validators
    pub nullifiers: NullifierSet<L>,
}

impl<'a, L: 'static + Ledger> LedgerState<'a, L> {
    /// Get the proving keys.
    pub fn proving_keys(&self) -> Arc<ProverKeySet<'a, key_set::OrderByOutputs>> {
        self.proving_keys.clone()
    }

    /// Get the event index.
    pub fn now(&self) -> EventIndex {
        self.now
    }

    /// Increment the index of the given event source.
    pub fn increment_now(&mut self, source: EventSource) {
        self.now += EventIndex::from_source(source, 1);
    }

    /// Get the validator.
    pub fn validator(&self) -> &Validator<L> {
        &self.validator
    }

    /// Get the nullifiers.
    pub fn nullifiers(&self) -> &NullifierSet<L> {
        &self.nullifiers
    }

    /// Get the record Merkle tree.
    pub fn record_mt(&self) -> &SparseMerkleTree {
        &self.record_mt
    }

    pub fn block_height(&self) -> u64 {
        self.validator.now()
    }

    pub fn transfer<'k>(
        &mut self,
        records: &mut Records,
        spec: TransferSpec<'k>,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        rng: &mut ChaChaRng,
    ) -> Result<(TransferNote, TransactionParams<L>), KeystoreError<L>> {
        if *spec.asset == AssetCode::native() {
            self.transfer_native(records, spec, proving_keys, rng)
        } else {
            self.transfer_non_native(records, spec, proving_keys, rng)
        }
    }

    fn transfer_native<'k>(
        &mut self,
        records: &mut Records,
        spec: TransferSpec<'k>,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        rng: &mut ChaChaRng,
    ) -> Result<(TransferNote, TransactionParams<L>), KeystoreError<L>> {
        let total_output_amount: U256 = spec
            .receivers
            .iter()
            .fold(U256::zero(), |sum, (_, amount, _)| sum + *amount)
            + spec.fee;

        // find input records which account for at least the total amount, and possibly some change.
        let records = self.find_records(
            records,
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

    fn transfer_non_native<'k>(
        &mut self,
        records_db: &mut Records,
        spec: TransferSpec<'k>,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        rng: &mut ChaChaRng,
    ) -> Result<(TransferNote, TransactionParams<L>), KeystoreError<L>> {
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
            records_db,
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
        let fee_input = self.find_fee_input(records_db, spec.sender_key_pairs, spec.fee)?;

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
    ) -> Result<(Vec<Option<ReceiverMemo>>, Signature), KeystoreError<L>> {
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
            .collect::<Result<Vec<_>, KeystoreError<L>>>()?;
        let sig = sign_receiver_memos(
            sig_key_pair,
            &memos.iter().flatten().cloned().collect::<Vec<_>>(),
        )
        .context(CryptoSnafu)?;

        Ok((memos, sig))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        &mut self,
        records: &mut Records,
        sending_keys: &[UserKeyPair],
        proving_key: &MintProvingKey<'a>,
        fee: RecordAmount,
        asset: &(AssetDefinition, AssetCodeSeed, Vec<u8>),
        amount: RecordAmount,
        receiver: UserPubKey,
        rng: &mut ChaChaRng,
    ) -> Result<(MintNote, TransactionParams<L>), KeystoreError<L>> {
        let (asset_def, seed, asset_description) = asset;
        let mint_record = RecordOpening::new(
            rng,
            amount.into(),
            asset_def.clone(),
            receiver.clone(),
            FreezeFlag::Unfrozen,
        );

        let fee_input = self.find_fee_input(records, sending_keys, fee)?;
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
    pub fn freeze_or_unfreeze(
        &mut self,
        records: &mut Records,
        sending_keys: &[UserKeyPair],
        freezer_key_pair: &FreezerKeyPair,
        proving_keys: &KeySet<FreezeProvingKey<'a>, key_set::OrderByOutputs>,
        fee: RecordAmount,
        asset: &AssetDefinition,
        amount: U256,
        owner: UserAddress,
        outputs_frozen: FreezeFlag,
        rng: &mut ChaChaRng,
    ) -> Result<(FreezeNote, TransactionParams<L>), KeystoreError<L>> {
        // find input records of the asset type to freeze (this does not include the fee input)
        let inputs_frozen = match outputs_frozen {
            FreezeFlag::Frozen => FreezeFlag::Unfrozen,
            FreezeFlag::Unfrozen => FreezeFlag::Frozen,
        };
        let (input_records, _) = self.find_records_with_pub_key(
            records,
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
        let fee_input = self.find_fee_input(records, sending_keys, fee)?;
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
    #[allow(clippy::too_many_arguments)]
    fn find_records_with_pub_key(
        &self,
        records: &Records,
        asset: &AssetCode,
        owner: &UserAddress,
        frozen: FreezeFlag,
        amount: U256,
        max_records: Option<usize>,
        allow_insufficient: bool,
    ) -> Result<(Vec<(RecordOpening, u64)>, BigInt), KeystoreError<L>> {
        let now = self.validator.now();

        // If we have a record with the exact size required, use it to avoid
        // fragmenting big records into smaller change records. First make
        // sure the amount can be converted to a RecordAmount, since if it is
        // too big for a single record, then of course we don not have a
        // record of exactly the right size.
        if let Ok(amount) = amount.try_into() {
            if let Some(record) = records
                .get_spendable_with_amount::<L>(asset, owner, frozen, amount, now)
                .unwrap()
            {
                return Ok((
                    vec![(record.record_opening().clone(), record.uid())],
                    BigInt::zero(),
                ));
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
        if let Some(inputs) = input_records::<L>(records, asset, owner, frozen, now) {
            for record in inputs {
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
                        }
                        .into());
                    }
                }
                current_amount += record.amount().into();
                result.push((record.record_opening().clone(), record.uid()));
                if current_amount >= amount {
                    return Ok((
                        result,
                        u256_to_signed(current_amount) - u256_to_signed(amount),
                    ));
                }
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
            }
            .into())
        }
    }

    #[allow(clippy::type_complexity)]
    fn find_records<'l>(
        &self,
        records_db: &mut Records,
        asset: &AssetCode,
        owner_key_pairs: &'l [UserKeyPair],
        frozen: FreezeFlag,
        amount: U256,
        max_records: Option<usize>,
    ) -> Result<Vec<(&'l UserKeyPair, Vec<(RecordOpening, u64)>, RecordAmount)>, KeystoreError<L>>
    {
        let mut records = Vec::new();
        let mut target_amount = amount;

        for owner_key_pair in owner_key_pairs {
            let (input_records, change) = self.find_records_with_pub_key(
                records_db,
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
        }
        .into())
    }

    /// find a record of the native asset type with enough funds to pay a transaction fee
    ///
    /// The record will be owned by one of the given key pairs.
    fn find_fee_input<'l>(
        &self,
        records: &mut Records,
        key_pairs: &'l [UserKeyPair],
        fee: RecordAmount,
    ) -> Result<FeeInput<'l>, KeystoreError<L>> {
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
                    if let Some(inputs) = input_records::<L>(
                        records,
                        &AssetCode::native(),
                        &key.address(),
                        FreezeFlag::Unfrozen,
                        now,
                    ) {
                        inputs
                            .map(move |record| (record.record_opening().clone(), record.uid(), key))
                            .collect::<Vec<_>>()
                    } else {
                        vec![]
                    }
                })
                // Find the smallest record among all the records from all the keys.
                .min_by_key(|(ro, _, _)| ro.amount)
                // If there weren't any records at all, we simply cannot pay the fee -- even though
                // the fee amount is 0!
                .ok_or_else(|| {
                    KeystoreError::from(TransactionError::InsufficientBalance {
                        asset: AssetCode::native(),
                        required: fee.into(),
                        actual: U256::zero(),
                    })
                })?
        } else {
            // When the fee is nonzero, fee allocation is just like allocation of any other input,
            // and we can call out to the regular record allocation algorithm (using
            // `max_records == Some(1)`, since we cannot break fees into multiple records).
            let mut records = self.find_records(
                records,
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
    fn xfr_proving_key<'k>(
        rng: &mut ChaChaRng,
        any_key: UserPubKey,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        asset: &AssetDefinition,
        inputs: &mut Vec<TransferNoteInput<'k>>,
        outputs: &mut Vec<RecordOpening>,
        xfr_size_requirement: Option<(usize, usize)>,
        change_record: bool,
    ) -> Result<(&'k TransferProvingKey<'a>, usize), KeystoreError<L>> {
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
                    return Err(KeystoreError::from(TransactionError::InvalidSize {
                        asset: asset.code,
                        num_inputs_required: input_size,
                        num_inputs_actual: min_num_inputs,
                        num_outputs_required: output_size,
                        num_outputs_actual: min_num_outputs,
                    }));
                }
                match proving_keys.exact_fit_key(input_size, output_size) {
                    Some(key) => Ok((key, 0)),
                    None => Err(KeystoreError::from(TransactionError::NoFitKey {
                        num_inputs: input_size,
                        num_outputs: output_size,
                    })),
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
                            .into()
                        } else {
                            // Otherwise, we just have too many outputs for any of our available keys. There
                            // is nothing we can do about that on the transaction builder side.
                            KeystoreError::from(TransactionError::TooManyOutputs {
                                asset: asset.code,
                                max_records: max_outputs,
                                num_receivers: outputs.len() - change_record as usize,
                                num_change_records: 1 + change_record as usize,
                            })
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

    fn freeze_proving_key<'k>(
        rng: &mut ChaChaRng,
        proving_keys: &'k KeySet<FreezeProvingKey<'a>, key_set::OrderByOutputs>,
        asset: &AssetDefinition,
        inputs: &mut Vec<FreezeNoteInput<'k>>,
        key_pair: &'k FreezerKeyPair,
    ) -> Result<&'k FreezeProvingKey<'a>, KeystoreError<L>> {
        let total_output_amount = inputs.iter().fold(U256::zero(), |sum, input| {
            sum + RecordAmount::from(input.ro.amount)
        });

        let num_inputs = inputs.len() + 1; // make sure to include fee input
        let num_outputs = num_inputs; // freeze transactions always have equal outputs and inputs
        let (key_inputs, key_outputs, proving_key) = proving_keys
            .best_fit_key(num_inputs, num_outputs)
            .map_err(|(max_inputs, _)| {
                KeystoreError::from(TransactionError::Fragmentation {
                    asset: asset.code,
                    amount: total_output_amount,
                    suggested_amount: inputs
                        .iter()
                        .take(max_inputs - 1) // leave room for fee input
                        .fold(U256::zero(), |sum, input| {
                            sum + RecordAmount::from(input.ro.amount)
                        }),
                    max_records: max_inputs,
                })
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

    pub fn balance<Meta: Serialize + DeserializeOwned + Send>(
        &self,
        model: &KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        asset: &AssetCode,
        frozen: FreezeFlag,
    ) -> U256 {
        let mut balance = U256::zero();
        for address in model.sending_accounts.iter_pub_keys() {
            balance += self.balance_breakdown(model, &address, asset, frozen);
        }
        balance
    }

    pub fn balance_breakdown<Meta: Serialize + DeserializeOwned + Send>(
        &self,
        model: &KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        address: &UserAddress,
        asset: &AssetCode,
        frozen: FreezeFlag,
    ) -> U256 {
        let spendable = model.records.get_spendable::<L>(asset, address, frozen);
        if let Some(records) = spendable {
            records
                .filter(move |record| !record.on_hold(self.block_height()))
                .fold(U256::zero(), |sum, record| sum + record.amount())
        } else {
            U256::zero()
        }
    }

    pub(crate) async fn handle_event<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        event: LedgerEvent<L>,
        source: EventSource,
    ) -> Result<EventSummary<L>, KeystoreError<L>> {
        self.now += EventIndex::from_source(source, 1);
        let mut summary = EventSummary::default();
        match event {
            LedgerEvent::Commit {
                block,
                block_id,
                state_comm,
            } => {
                // Don't trust the network connection that provided us this event; validate it
                // against our local mirror of the ledger and bail out if it is invalid.
                let mut uids = match self.validator.validate_and_apply(block.clone()) {
                    Ok(uids) => {
                        if state_comm != self.validator.commit() {
                            // Received a block which validates, but our state commitment does not
                            // match that of the event source. Since the block validates, we will
                            // accept it, but this must indicate that the event source is lying or
                            // mistaken about the state commitment. This would be a good time to
                            // switch to a different query server or something, but for now we'll
                            // just log the problem.
                            tracing::error!("received valid block with invalid state commitment");
                        }

                        // Get a list of new uids and whether we want to remember them in our record
                        // Merkle tree. Initially, set `remember` to false for all uids, to maximize
                        // sparseness. If any of the consumers of this block (for example, the
                        // viewer component, or the owner of this keystore) care about a uid, they
                        // will set its `remember` flag to true.
                        uids.into_iter().map(|uid| (uid, false)).collect::<Vec<_>>()
                    }
                    Err(val_err) => {
                        //todo !jeb.bearer handle this case more robustly. If we get here, it means
                        // the event stream has lied to us, so recovery is quite tricky and may
                        // require us to fail over to a different query service.
                        panic!("received invalid block: {:?}, {:?}", block, val_err);
                    }
                };

                // Update our full copies of sparse validator data structures to be consistent with
                // the validator state.
                for txn in block.txns() {
                    let nullifiers = txn.input_nullifiers();
                    // Remove spent records.
                    for n in &nullifiers {
                        if let Ok(record) = model.records.delete_by_nullifier::<L>(n) {
                            self.forget_merkle_leaf(record.uid());
                        }
                    }
                }
                // Insert new records.
                self.append_merkle_leaves(
                    block
                        .txns()
                        .into_iter()
                        .flat_map(|txn| txn.output_commitments()),
                );
                // Update nullifier set
                let nullifier_proofs = block
                    .txns()
                    .into_iter()
                    .flat_map(|txn| txn.proven_nullifiers())
                    .collect::<Vec<_>>();
                if self.nullifiers.multi_insert(&nullifier_proofs).is_err() {
                    //todo !jeb.bearer handle this case more robustly. If we get here, it means the
                    // event stream has lied to us, so recovery is quite tricky and may require us
                    // to fail over to a different query service.
                    panic!("received block with invalid nullifier proof");
                }

                for (txn_id, txn) in block.txns().into_iter().enumerate() {
                    // Split the uids corresponding to this transaction off the front of `uids`.
                    let mut this_txn_uids = uids;
                    uids = this_txn_uids.split_off(txn.output_len());
                    assert_eq!(this_txn_uids.len(), txn.output_len());

                    // If this transaction contains record openings for all of its outputs,
                    // consider it retired immediately, do not wait for memos.
                    let retired = txn.output_openings().is_some();

                    // Add the spent nullifiers to the summary. Map each nullifier to one of the
                    // output UIDs of the same transaction, so that we can tell when the memos
                    // arrive for the transaction which spent this nullifier (completing the
                    // transaction's life cycle) by looking at the UIDs attached to the memos.
                    // TODO !keyao Stop identifying transactions by input nullifier and instead use hashes.
                    // (https://github.com/SpectrumXYZ/cape/issues/275.)
                    if !txn.input_nullifiers().is_empty() {
                        summary.spent_nullifiers.extend(
                            txn.input_nullifiers()
                                .into_iter()
                                .zip(repeat(this_txn_uids[0].0)),
                        );
                        if retired {
                            summary.retired_nullifiers.push(txn.input_nullifiers()[0]);
                        }
                    }

                    // Different concerns within the keystore consume transactions in different ways.
                    // Now we give each concern a chance to consume this transaction, performing any
                    // processing they need to do and possibly setting the `remember` flag for
                    // output records they care about.
                    //
                    // This is a transaction we submitted and have been
                    // awaiting confirmation.
                    let mut self_published = false;
                    if let Some(pending) = self
                        .clear_pending_transaction(
                            model,
                            &txn,
                            Some((block_id, txn_id as u64, &mut this_txn_uids)),
                        )
                        .await
                    {
                        let status = if retired {
                            TransactionStatus::Retired
                        } else {
                            TransactionStatus::AwaitingMemos
                        };
                        summary.updated_txns.push((pending.uid().clone(), status));
                        model
                            .transactions
                            .get_mut(pending.uid())
                            .unwrap()
                            .add_pending_uids(
                                &this_txn_uids
                                    .iter()
                                    .zip(pending.memos().unwrap().memos.iter())
                                    .filter_map(|((uid, _), memo)| memo.as_ref().map(|_| *uid))
                                    .into_iter()
                                    .collect::<Vec<u64>>(),
                            )
                            .set_status(status)
                            .save()
                            .unwrap();
                        model
                            .backend
                            .finalize(pending, Some((block_id, txn_id as u64)))
                            .await;
                        self_published = true;
                    }

                    // This is someone else's transaction but we can view it.
                    view_transaction(model, &txn, &mut this_txn_uids).await?;

                    // If this transaction has record openings attached, check if they are for us
                    // and add them immediately, without waiting for memos.
                    if let Err(err) = receive_attached_records(
                        model,
                        &txn,
                        &mut this_txn_uids,
                        !self_published,
                        // Only add to history if we didn't send this same transaction
                    )
                    .await
                    {
                        tracing::error!(
                            "Error saving records attached to transaction {}:{}: {}",
                            block_id,
                            txn_id,
                            err
                        );
                    }

                    // Prune the record Merkle tree of records we don't care about.
                    for (uid, remember) in this_txn_uids {
                        if !remember {
                            self.forget_merkle_leaf(uid);
                        }
                    }
                }

                // Some transactions may have expired when we stepped the validator state. Remove
                // them from our pending transaction data structures.
                //
                // This maintains the invariant that everything in `pending_transactions` must
                // correspond to an on-hold record, because everything which corresponds to a record
                // whose hold just expired will be removed from the set now.
                match model.transactions.remove_expired(self.block_height()) {
                    Ok(txns) => {
                        for txn in txns {
                            summary
                                .updated_txns
                                .push((txn.uid().clone(), TransactionStatus::Rejected));
                            model.backend.finalize(txn, None).await;
                        }
                    }
                    Err(err) => {
                        println!(
                            "Error removing expired transaction from storage.  Block: {},  Error: {}",
                            block_id, err
                        );
                    }
                }
            }
            LedgerEvent::Memos {
                outputs,
                transaction,
            } => {
                let completed =
                    received_memos(outputs.iter().map(|info| info.2), &mut model.transactions);
                let self_published = !completed.is_empty();
                summary.updated_txns.extend(
                    completed
                        .into_iter()
                        .map(|txn_uid| (txn_uid, TransactionStatus::Retired))
                        .collect::<Vec<_>>(),
                );

                summary
                    .received_memos
                    .extend(outputs.iter().map(|(memo, _, uid, _)| (memo.clone(), *uid)));
                for key in &model
                    .sending_accounts
                    .iter_keys()
                    .collect::<Vec<UserKeyPair>>()
                {
                    let records =
                        try_open_memos(model, key, &outputs, transaction.clone(), !self_published)
                            .await?;
                    if let Err(err) = self.add_records(model, key, records).await {
                        tracing::error!("error saving received records: {}", err);
                    }
                }
            }
            LedgerEvent::Reject { block, error } => {
                for mut txn in block.txns() {
                    summary
                        .rejected_nullifiers
                        .append(&mut txn.input_nullifiers());
                    if let Some(pending) = self.clear_pending_transaction(model, &txn, None).await {
                        // Try to resubmit if the error is recoverable.
                        let uid = pending.uid();
                        if error.is_bad_nullifier_proof() {
                            if self.update_nullifier_proofs(model, &mut txn).await.is_ok()
                                && self
                                    .submit_elaborated_transaction(model, txn, None)
                                    .await
                                    .is_ok()
                            {
                                // The transaction has been successfully resubmitted. It is still in
                                // the same state (pending) so we don't need to add it to
                                // `updated_txns`.
                            } else {
                                // If we failed to resubmit, then the rejection is final.
                                summary
                                    .updated_txns
                                    .push((uid.clone(), TransactionStatus::Rejected));
                                model.backend.finalize(pending, None).await;
                            }
                        } else {
                            summary
                                .updated_txns
                                .push((uid.clone(), TransactionStatus::Rejected));
                            model.backend.finalize(pending, None).await;
                        }
                    }
                }
            }
        };

        model.ledger_state_store.update_dynamic(self)?;
        Ok(summary)
    }

    pub async fn add_records<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        key_pair: &UserKeyPair,
        records: Vec<(RecordOpening, u64, MerklePath)>,
    ) -> Result<(), KeystoreError<L>> {
        for (record, uid, proof) in records {
            let comm = RecordCommitment::from(&record);
            if !self
                .remember_merkle_leaf(uid, &MerkleLeafProof::new(comm.to_field_element(), proof))
            {
                return Err(KeystoreError::BadMerkleProof {
                    commitment: comm,
                    uid,
                });
            }

            // Add the asset type if it is not already in the asset library.
            model.assets_mut().create(record.asset_def.clone(), None)?;

            // Mark the account receiving the record as used.
            model
                .sending_accounts
                .get_mut(&key_pair.address())
                .unwrap()
                .set_used()
                .save()?;
            // Save the record.
            model.records.create::<L>(
                uid,
                record.clone(),
                key_pair.nullify(
                    record.asset_def.policy_ref().freezer_pub_key(),
                    uid,
                    &RecordCommitment::from(&record),
                ),
            )?;
        }
        Ok(())
    }

    pub async fn import_memo<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        memo: ReceiverMemo,
        comm: RecordCommitment,
        uid: u64,
        proof: MerklePath,
    ) -> Result<(), KeystoreError<L>> {
        for key in model
            .sending_accounts
            .iter_keys()
            .collect::<Vec<UserKeyPair>>()
        {
            let records = try_open_memos(
                model,
                &key,
                &[(memo.clone(), comm, uid, proof.clone())],
                None,
                false,
            )
            .await?;
            if !records.is_empty() {
                return self.add_records(model, &key, records).await;
            }
        }

        Err(KeystoreError::<L>::CannotDecryptMemo {})
    }

    async fn clear_pending_transaction<'t, Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        txn: &reef::Transaction<L>,
        res: Option<CommittedTxn<'t>>,
    ) -> Option<Transaction<L>> {
        let now = self.block_height();
        let pending = model
            .transactions
            .get(&TransactionUID::<L>(txn.hash()))
            .ok();
        for nullifier in txn.input_nullifiers() {
            if let Ok(record) = model.records.with_nullifier_mut::<L>(&nullifier) {
                if pending.is_some() {
                    // If we started this transaction, all of its inputs should have been on hold,
                    // to preserve the invariant that all input nullifiers of all pending
                    // transactions are on hold.
                    assert!(record.on_hold(now));

                    if res.is_none() {
                        // If the transaction was not accepted for any reason, its nullifiers have
                        // not been spent, so remove the hold we placed on them.
                        record.unhold().save::<L>().ok();
                    }
                } else {
                    // This isn't even our transaction.
                    assert!(!record.on_hold(now));
                }
            }
        }

        // If this was a successful transaction, add all of its frozen/unfrozen outputs to our
        // freezable database (for freeze/unfreeze transactions).
        if let Some((_, _, uids)) = res {
            if let Some(pending) = &pending {
                if pending.kind().clone() == TransactionKind::<L>::freeze()
                    || pending.kind().clone() == TransactionKind::<L>::unfreeze()
                {
                    // the first uid corresponds to the fee change output, which is not one of the
                    // `freeze_outputs`, so we skip that one
                    for ((uid, remember), ro) in uids.iter_mut().zip(pending.outputs()).skip(1) {
                        let key_pair = model
                            .freezing_accounts
                            .get(ro.asset_def.policy_ref().freezer_pub_key())
                            .unwrap()
                            .key()
                            .clone();
                        model
                            .records
                            .create::<L>(
                                *uid,
                                ro.clone(),
                                key_pair.nullify(
                                    &ro.pub_key.address(),
                                    *uid,
                                    &RecordCommitment::from(ro),
                                ),
                            )
                            .ok();
                        *remember = true;
                    }
                }
            }
        }
        pending
    }

    async fn update_nullifier_proofs<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        txn: &mut reef::Transaction<L>,
    ) -> Result<(), KeystoreError<L>> {
        let mut proofs = Vec::new();
        for n in txn.input_nullifiers() {
            let (spent, proof) = model
                .backend
                .get_nullifier_proof(&mut self.nullifiers, n)
                .await?;
            if spent {
                return Err(KeystoreError::<L>::NullifierAlreadyPublished { nullifier: n });
            }
            proofs.push(proof);
        }
        txn.set_proofs(proofs);
        Ok(())
    }

    // This function ran into the same mystifying compiler behavior as
    // `submit_elaborated_transaction`, where the default async desugaring loses track of the `Send`
    // impl for the result type. As with the other function, this can be fixed by manually
    // desugaring the type signature.
    pub fn define_asset<'b, Meta: Serialize + DeserializeOwned + Send + Send>(
        &'b mut self,
        model: &'b mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        name: String,
        description: &'b [u8],
        policy: AssetPolicy,
    ) -> impl 'b + Captures<'a> + Future<Output = Result<AssetDefinition, KeystoreError<L>>> + Send
    where
        'a: 'b,
    {
        async move {
            let seed = AssetCodeSeed::generate(&mut model.rng);
            let code = AssetCode::new_domestic(seed, description);
            let definition = AssetDefinition::new(code, policy).context(CryptoSnafu)?;
            let mint_info = MintInfo {
                seed,
                description: description.to_vec(),
            };

            model
                .assets_mut()
                .create(definition.clone(), Some(mint_info.clone()))?
                .with_name(name)
                .with_description(mint_info.fmt_description())
                .save()?;

            // If the asset is viewable/freezable, mark the appropriate viewing/freezing accounts
            // `used`.
            let policy = definition.policy_ref();
            if policy.is_viewer_pub_key_set() {
                if let Ok(account) = model.viewing_accounts.get_mut(policy.viewer_pub_key()) {
                    account.set_used().save()?;
                }
            }
            if policy.is_freezer_pub_key_set() {
                if let Ok(account) = model.freezing_accounts.get_mut(policy.freezer_pub_key()) {
                    account.set_used().save()?;
                }
            }
            model.ledger_state_store.update_dynamic(self)?;
            Ok(definition)
        }
    }

    // Add a new user key and set up a scan of the ledger to import records belonging to this key.
    //
    // `user_key` can be provided to add an arbitrary key, not necessarily derived from this
    // keystore's deterministic key stream. Otherwise, the next key in the key stream will be derived
    // and added.
    //
    // If `scan_from` is provided, a new ledger scan will be created and the corresponding event
    // stream will be returned. Note that the caller is responsible for actually starting the task
    // which processes this scan, since the Keystore (not the LedgerState) has the data structures
    // needed to manage tasks (the AsyncScope, mutexes, etc.).
    pub(crate) async fn add_sending_account<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        user_key: Option<UserKeyPair>,
        description: String,
        scan_from: Option<EventIndex>,
    ) -> Result<
        (
            UserKeyPair,
            Option<impl 'a + Stream<Item = (LedgerEvent<L>, EventSource)> + Send + Unpin>,
        ),
        KeystoreError<L>,
    > {
        let (user_key, index) = match user_key {
            Some(user_key) => {
                if model.sending_accounts.get(&user_key.address()).is_ok() {
                    // For other key types, adding a key that already exists is a no-op. However,
                    // because of the background ledger scans associated with user keys, we want to
                    // report an error, since the user may have attempted to add the same key with
                    // two different `scan_from` parameters, and we have not actually started the
                    // second scan in this case.
                    return Err(KeystoreError::<L>::UserKeyExists {
                        pub_key: user_key.pub_key(),
                    });
                }
                (user_key, None)
            }
            None => {
                // It is possible that we already have some of the keys that will be yielded by the
                // deterministic key stream. For example, the user could create a second keystore with
                // the same mnemonic, generate some keys, and then manually add those keys to this
                // keystore. If `user_key` is not provided, this function is required to generate a
                // new key, so keep incrementing the key stream state and generating keys until we
                // find one that is new.
                loop {
                    let index = model.sending_accounts.next_index();
                    let user_key = model
                        .user_key_stream
                        .derive_user_key_pair(&index.to_le_bytes());
                    if model.sending_accounts.get(&user_key.address()).is_err() {
                        break (user_key, Some(index));
                    }
                }
            }
        };

        let (scan, events) = if let Some(scan_from) = scan_from {
            // Get the stream of events for the background scan worker task to process.
            let (frontier, next_event) = model.backend.get_initial_scan_state(scan_from).await?;
            let events = model.backend.subscribe(next_event, None).await;

            // Create a background scan of the ledger to import records belonging to this key.
            let scan = BackgroundKeyScan::new(
                user_key.clone(),
                next_event,
                scan_from,
                self.now(),
                SparseMerkleTree::sparse(frontier),
            );
            (Some(scan), Some(events))
        } else {
            (None, None)
        };

        // Add a new account to our set of accounts and update our persistent data structures and
        // remote services.
        model
            .sending_accounts
            .create(user_key.clone(), index)?
            .with_description(description)
            .set_scan(scan)
            .save()?;
        model.ledger_state_store.update_dynamic(self)?;
        // If we successfully updated our data structures, register the key with the
        // network. The storage transaction will revert if this fails.
        model.backend.register_user_key(&user_key).await?;
        Ok((user_key, events))
    }

    // `viewing_key` can be provided to add an arbitrary key, not necessarily derived from this
    // keystore's deterministic key stream. Otherwise, the next key in the key stream will be derived
    // and added.
    pub(crate) async fn add_viewing_account<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        viewing_key: Option<ViewerKeyPair>,
        description: String,
    ) -> Result<ViewerKeyPair, KeystoreError<L>> {
        let (viewing_key, index) = match viewing_key {
            Some(viewing_key) => {
                if model.viewing_accounts.get(&viewing_key.pub_key()).is_ok() {
                    return Ok(viewing_key);
                }
                (viewing_key, None)
            }
            None => {
                let index = model.viewing_accounts.next_index();
                let viewing_key = model
                    .viewer_key_stream
                    .derive_viewer_key_pair(&index.to_le_bytes());
                (viewing_key, Some(index))
            }
        };

        model
            .viewing_accounts
            .create(viewing_key.clone(), index)?
            .with_description(description)
            .save()?;
        model.ledger_state_store.update_dynamic(self)?;
        Ok(viewing_key)
    }

    // `freezing_key` can be provided to add an arbitrary key, not necessarily derived from this
    // keystore's deterministic key stream. Otherwise, the next key in the key stream will be derived
    // and added.
    pub(crate) async fn add_freezing_account<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        freezing_key: Option<FreezerKeyPair>,
        description: String,
    ) -> Result<FreezerKeyPair, KeystoreError<L>> {
        let (freezing_key, index) = match freezing_key {
            Some(freezing_key) => {
                if model.freezing_accounts.get(&freezing_key.pub_key()).is_ok() {
                    return Ok(freezing_key);
                }
                (freezing_key, None)
            }
            None => {
                let index = model.viewing_accounts.next_index();
                let freezing_key = model
                    .freezer_key_stream
                    .derive_freezer_key_pair(&index.to_le_bytes());
                (freezing_key, Some(index))
            }
        };

        model
            .freezing_accounts
            .create(freezing_key.clone(), index)?
            .with_description(description)
            .save()?;
        model.ledger_state_store.update_dynamic(self)?;

        Ok(freezing_key)
    }

    pub fn build_transfer<'k, Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        spec: TransferSpec<'k>,
    ) -> Result<(TransferNote, TransactionParams<L>), KeystoreError<L>> {
        self.transfer(
            &mut model.records,
            spec,
            &self.proving_keys().xfr,
            &mut model.rng,
        )
    }

    pub async fn build_mint<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        minter: Option<&UserAddress>,
        fee: RecordAmount,
        asset_code: &AssetCode,
        amount: RecordAmount,
        receiver: UserPubKey,
    ) -> Result<(MintNote, TransactionParams<L>), KeystoreError<L>> {
        let asset = model
            .assets
            .get::<L>(asset_code)
            .map_err(|_| KeystoreError::<L>::UndefinedAsset { asset: *asset_code })?;
        let MintInfo { seed, description } =
            asset
                .mint_info()
                .ok_or_else(|| KeystoreError::<L>::AssetNotMintable {
                    asset: asset.definition().clone(),
                })?;
        let sending_keys = match minter {
            Some(addr) => vec![model.sending_accounts.get(addr)?.key().clone()],
            None => model.sending_accounts.iter_keys().collect(),
        };
        let proving_keys = &self.proving_keys().mint;
        self.mint(
            &mut model.records,
            &sending_keys,
            proving_keys,
            fee,
            &(asset.definition().clone(), seed, description),
            amount,
            receiver,
            &mut model.rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_freeze<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        fee_address: Option<&UserAddress>,
        fee: RecordAmount,
        asset: &AssetCode,
        amount: U256,
        owner: UserAddress,
        outputs_frozen: FreezeFlag,
    ) -> Result<(FreezeNote, TransactionParams<L>), KeystoreError<L>> {
        let asset = model
            .assets
            .get::<L>(asset)
            .map_err(|_| KeystoreError::<L>::UndefinedAsset { asset: *asset })?
            .definition()
            .clone();
        let freeze_key = match model
            .freezing_accounts
            .get(asset.policy_ref().freezer_pub_key())
        {
            Ok(account) => account.key().clone(),
            _ => return Err(KeystoreError::<L>::AssetNotFreezable { asset }),
        };
        let sending_keys = match fee_address {
            Some(addr) => vec![model.sending_accounts.get(addr)?.key().clone()],
            None => model.sending_accounts.iter_keys().collect(),
        };
        let proving_keys = &self.proving_keys().freeze;
        self.freeze_or_unfreeze(
            &mut model.records,
            &sending_keys,
            &freeze_key,
            proving_keys,
            fee,
            &asset,
            amount,
            owner,
            outputs_frozen,
            &mut model.rng,
        )
    }

    pub async fn submit_transaction<Meta: Serialize + DeserializeOwned + Send>(
        &mut self,
        model: &mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        note: TransactionNote,
        info: TransactionParams<L>,
    ) -> Result<TransactionUID<L>, KeystoreError<L>> {
        let mut nullifier_pfs = Vec::new();
        for n in note.nullifiers() {
            let (spent, proof) = model
                .backend
                .get_nullifier_proof(&mut self.nullifiers, n)
                .await?;
            if spent {
                return Err(KeystoreError::<L>::NullifierAlreadyPublished { nullifier: n });
            }
            nullifier_pfs.push(proof);
        }

        let txn = reef::Transaction::<L>::cap(note, nullifier_pfs);
        self.submit_elaborated_transaction(model, txn, Some(info))
            .await
    }

    // For reasons that are not clearly understood, the default async desugaring for this function
    // loses track of the fact that the result type implements Send, which causes very confusing
    // error messages farther up the call stack (apparently at the point where this function is
    // monomorphized) which do not point back to this location. This is likely due to a bug in type
    // inference, or at least a deficiency around async sugar combined with a bug in diagnostics.
    //
    // As a work-around, we do the desugaring manually so that we can explicitly specify that the
    // return type implements Send. The return type also captures a reference with lifetime 'a,
    // which is different from (but related to) the lifetime 'b of the returned Future, and
    // `impl 'a + 'b + ...` does not work, so we use the work-around described at
    // https://stackoverflow.com/questions/50547766/how-can-i-get-impl-trait-to-use-the-appropriate-lifetime-for-a-mutable-reference
    // to indicate the captured lifetime using the Captures trait.
    pub(crate) fn submit_elaborated_transaction<
        'b,
        Meta: Serialize + DeserializeOwned + Send + Send,
    >(
        &'b mut self,
        model: &'b mut KeystoreModel<'a, L, impl KeystoreBackend<'a, L>, Meta>,
        txn: reef::Transaction<L>,
        info: Option<TransactionParams<L>>,
    ) -> impl 'b + Captures<'a> + Future<Output = Result<TransactionUID<L>, KeystoreError<L>>> + Send
    where
        'a: 'b,
    {
        async move {
            let stored_txn = if let Some(mut info) = info {
                let now = self.block_height();
                let timeout = now + (L::record_root_history() as u64);
                let uid = TransactionUID(txn.hash());
                for nullifier in txn.input_nullifiers() {
                    // hold the record corresponding to this nullifier until the transaction is committed,
                    // rejected, or expired.
                    if let Ok(record) = model.records.with_nullifier_mut::<L>(&nullifier) {
                        assert!(!(*record).on_hold(now));
                        record.hold_until(timeout).save::<L>()?;
                    }
                }
                info.timeout = Some(timeout);
                let stored_txn = model.transactions.create(uid, info)?;
                model.ledger_state_store.update_dynamic(self)?;
                stored_txn.clone()
            } else {
                model.transactions.get(&TransactionUID::<L>(txn.hash()))?
            };
            let uid = stored_txn.uid().clone();
            // If we succeeded in creating and persisting the pending transaction, submit it to the
            // validators.
            model.backend.submit(txn.clone(), stored_txn).await?;
            Ok(uid)
        }
    }
}

mod serde_ark_unchecked {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use serde::{
        de::{Deserialize, Deserializer},
        ser::{Serialize, Serializer},
    };
    use std::sync::Arc;

    pub fn serialize<S: Serializer, T: CanonicalSerialize>(
        t: &Arc<T>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        t.serialize_unchecked(&mut bytes).unwrap();
        Serialize::serialize(&bytes, s)
    }

    pub fn deserialize<'a, D: Deserializer<'a>, T: CanonicalDeserialize>(
        d: D,
    ) -> Result<Arc<T>, D::Error> {
        let bytes = <Vec<u8> as Deserialize<'a>>::deserialize(d)?;
        Ok(Arc::new(T::deserialize_unchecked(&*bytes).unwrap()))
    }
}

/// Serialization intermediate for the static part of a ledger state.
// // #[derive(Deserialize, Serialize, Debug)]
#[derive(Deserialize, Serialize)]
pub(crate) struct StaticState<'a> {
    #[serde(with = "serde_ark_unchecked")]
    proving_keys: Arc<ProverKeySet<'a, OrderByOutputs>>,
}

impl<'a, L: Ledger> From<&LedgerState<'a, L>> for StaticState<'a> {
    fn from(w: &LedgerState<'a, L>) -> Self {
        Self {
            proving_keys: w.proving_keys.clone(),
        }
    }
}

/// Serialization intermediate for the dynamic part of a ledger state.
// #[ser_test(arbitrary, types(cap::Ledger), ark(false))]
// #[derive(Debug, Derivative, Deserialize, Serialize)]
#[derive(Deserialize, Serialize)]
// #[derivative(PartialEq(bound = "L: Ledger"))]
#[serde(bound = "")]
pub(crate) struct DynamicState<L: Ledger> {
    now: EventIndex,
    validator: Validator<L>,
    record_mt: SparseMerkleTree,
    nullifiers: NullifierSet<L>,
}

impl<'a, L: Ledger> From<&LedgerState<'a, L>> for DynamicState<L> {
    fn from(w: &LedgerState<'a, L>) -> Self {
        Self {
            now: w.now,
            validator: w.validator.clone(),
            record_mt: w.record_mt.clone(),
            nullifiers: w.nullifiers.clone(),
        }
    }
}

// impl<'a, L: Ledger> Arbitrary<'a> for DynamicState<L>
// where
//     TransactionState<L>: Arbitrary<'a>,
//     TransactionHash<L>: Arbitrary<'a>,
// {
//     fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
//         Ok(Self {
//             txn_state: u.arbitrary()?,
//         })
//     }
// }

pub struct LedgerStateStore<'a, L: Ledger> {
    static_store: RollingLog<EncryptingResourceAdapter<StaticState<'a>>>,
    dynamic_store: RollingLog<EncryptingResourceAdapter<DynamicState<L>>>,
}

impl<'a, L: Ledger> LedgerStateStore<'a, L> {
    /// Create a ledger state store.
    pub(crate) fn new(
        loader: &mut AtomicStoreLoader,
        static_adaptor: EncryptingResourceAdapter<StaticState<'a>>,
        dynamic_adaptor: EncryptingResourceAdapter<DynamicState<L>>,
        fill_size: u64,
    ) -> Result<Self, KeystoreError<L>> {
        let static_store =
            RollingLog::load(loader, static_adaptor.cast(), "keystore_static", fill_size)
                .context(crate::PersistenceSnafu)?;

        let mut dynamic_store = RollingLog::load(
            loader,
            dynamic_adaptor.cast(),
            "keystore_dynamic",
            fill_size,
        )
        .context(crate::PersistenceSnafu)?;
        dynamic_store.set_retained_entries(ATOMIC_STORE_RETAINED_ENTRIES);

        Ok(Self {
            static_store,
            dynamic_store,
        })
    }

    pub fn load(&self) -> Result<LedgerState<'a, L>, KeystoreError<L>> {
        let static_state = self.static_store.load_latest()?;
        let dynamic_store = self.dynamic_store.load_latest()?;
        Ok(LedgerState {
            proving_keys: static_state.proving_keys.clone(),
            now: dynamic_store.now,
            validator: dynamic_store.validator.clone(),
            record_mt: dynamic_store.record_mt.clone(),
            nullifiers: dynamic_store.nullifiers,
        })
    }

    pub fn update(&mut self, ledger_state: &LedgerState<'a, L>) -> Result<(), KeystoreError<L>> {
        self.static_store
            .store_resource(&StaticState::<'a>::from(ledger_state))?;
        self.dynamic_store
            .store_resource(&DynamicState::<L>::from(ledger_state))?;
        Ok(())
    }

    pub fn update_dynamic(
        &mut self,
        ledger_state: &LedgerState<'a, L>,
    ) -> Result<(), KeystoreError<L>> {
        self.dynamic_store
            .store_resource(&DynamicState::<L>::from(ledger_state))?;
        Ok(())
    }

    pub fn commit(&mut self) -> Result<(), KeystoreError<L>> {
        self.static_store.commit_version()?;
        self.dynamic_store.commit_version()?;
        self.dynamic_store.prune_file_entries()?;
        Ok(())
    }

    pub fn revert(&mut self) -> Result<(), KeystoreError<L>> {
        self.static_store.revert_version()?;
        self.dynamic_store.revert_version()?;
        Ok(())
    }
}

fn u256_to_signed(u: U256) -> BigInt {
    let mut bytes = [0; 32];
    u.to_little_endian(&mut bytes);
    BigInt::from_bytes_le(Sign::Plus, &bytes)
}
