/// Ledger scanning utilities.
///
/// This module provides an interface for searching a ledger for records belonging to a particular
/// key. It is completely independent from the main ledger scanning functionality in `lib.rs` and
/// `txn_builder.rs`, which means it can be run asynchronously, and the results of an asnchronous
/// key-specific ledger scan can be folded back into the main keystore state once the scan
/// synchronizes with the main ledger follower.
use crate::{
    events::{EventIndex, EventSource, LedgerEvent},
    lw_merkle_tree::LWMerkleTree,
    transactions::TransactionParams,
    txn_builder::{TransactionStatus, TransactionUID},
};
use arbitrary::{Arbitrary, Unstructured};
use arbitrary_wrappers::ArbitraryUserKeyPair;
use chrono::Local;
use espresso_macros::ser_test;
use jf_cap::{
    keys::{UserAddress, UserKeyPair},
    structs::{FreezeFlag, Nullifier, RecordCommitment, RecordOpening},
    MerkleCommitment, MerkleLeafProof, MerklePath,
};
use reef::{
    traits::{Block as _, Transaction as _, TransactionKind as _},
    Ledger, TransactionHash, TransactionKind,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The information about each discovered record returned by a key-specific scan.
pub type ScannedRecord = (RecordOpening, u64, MerklePath);

/// All the outputs of a key-specific ledger scan.
///
/// A list of records discovered by the scan and a list of transaction history entries corresponding
/// to transactions received by the scan's key during the range of events considered by the scan.
#[derive(Debug)]
pub struct ScanOutputs<L: Ledger> {
    pub records: Vec<ScannedRecord>,
    pub history: Vec<(TransactionUID<L>, TransactionParams<L>)>,
}

/// The status of a ledger scan.
#[derive(Clone)]
pub enum ScanStatus<L: Ledger> {
    Finished {
        /// The scanned key.
        key: UserKeyPair,
        /// The list of records discovered by the scan.
        records: Vec<ScannedRecord>,
        /// The list of transaction history entries corresponding to transactions received by the
        /// scan.
        history: Vec<(TransactionUID<L>, TransactionParams<L>)>,
    },
    InProgress(BackgroundKeyScan<L>),
}

/// An in-progress scan of past ledger events.
///
/// When a key is added to a keystore, the keystore can optionally trigger a [BackgroundKeyScan] to
/// search the ledger for asset records belonging to this key. This is useful when recovering a
/// keystore from a mnemonic phrase. In this case, keys generated by the keystore are the same as the
/// keys belonging to the lost keystore being recovered, and so there may already exist records
/// belonging to these keys.
///
/// A scan has a stream of events and a range of event indices of interest. The stream always
/// includes the range of interest but may also include events before or after it. As the scan
/// progresses through the event stream, it maintains a collection of newly discovered records as
/// well as a lightweight Merkle tree with paths for each of the discovered records. The Merkle
/// tree allows it to update the paths as new commitments are added, and ultimately produce up-to-date
/// paths for each record it discovers.
///
/// The scan must be initialized with a Merkle frontier corresponding to the ledger state just
/// before the first event in its stream. This is the reason why the event stream is allowed to
/// include events before the range of interest: the Merkle frontier at some time before the first
/// event of interest must be fetched from the backend, but we don't want to require the backend to
/// store _every_ past frontier, so we allow it to return any frontier before the first event of
/// interest, including possibly the initial one. The scan will start processing events from just
/// after that frontier was valid, updating the frontier as it goes.
///
/// At each event, the scan will update its lightweight Merkle tree, including the paths for all of
/// its discovered records, by appending the new commitments to the tree. It will also check any
/// new nullifiers against its discovered records; if it finds a match, it will remove the
/// nullified records and prune their paths from the tree. In addition, if the event falls within
/// the range of interest, the scan will attempt to find new records belonging to its key in the
/// event, either by decrypting memos or by checking record openings included in plaintext in a
/// transaction. If it finds any records, it will add them to its collection, insert their paths
/// into its Merkle tree, and add a transaction history entry for the transaction of which it is a
/// recipient. It is able to create Merkle paths for the new records either by using the Merkle
/// paths included in `Memos` events, or by using the frontier at the time it appends the
/// commitment for an attached record opening to the tree.
#[ser_test(arbitrary, ark(false), types(reef::cap::Ledger))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "L: Ledger")]
pub struct BackgroundKeyScan<L: Ledger> {
    key: UserKeyPair,
    // The index of the next event in the event stream.
    next_event: EventIndex,
    // The first event of interest.
    from_event: EventIndex,
    // The first event after the range of interest.
    to_event: EventIndex,
    // Record openings we have discovered which belong to these key. These records are kept in a
    // separate pool until the scan is complete so that if the scan encounters an event which spends
    // some of these records, we can remove the spent records without ever reflecting them in the
    // keystore's balance.
    records: HashMap<Nullifier, (RecordOpening, u64)>,
    // New history entries for transactions we received during the scan.
    history: Vec<(TransactionUID<L>, TransactionParams<L>)>,
    // Lightweight Merkle tree containing paths for the commitments of each record in `records`.
    // This allows us to update the paths as we scan so that at the end of the scan, we have a path for
    // each record relative to the current Merkle root.
    records_mt: LWMerkleTree,
}

impl<L: Ledger> PartialEq<Self> for BackgroundKeyScan<L> {
    fn eq(&self, other: &Self) -> bool {
        self.key.pub_key() == other.key.pub_key()
            && self.next_event == other.next_event
            && self.to_event == other.to_event
            && self.records == other.records
            && self.history == other.history
            && self.records_mt == other.records_mt
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for BackgroundKeyScan<L>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary::<ArbitraryUserKeyPair>()?.into(),
            next_event: u.arbitrary()?,
            from_event: u.arbitrary()?,
            to_event: u.arbitrary()?,
            records: Default::default(),
            history: Default::default(),
            records_mt: u.arbitrary()?,
        })
    }
}

impl<L: Ledger> BackgroundKeyScan<L> {
    pub fn new(
        key: UserKeyPair,
        next_event: EventIndex,
        from: EventIndex,
        to: EventIndex,
        records_mt: LWMerkleTree,
    ) -> Self {
        Self {
            key,
            next_event,
            from_event: from,
            to_event: to,
            records: Default::default(),
            history: Default::default(),
            records_mt,
        }
    }

    /// Attempt to finalize a key scan.
    ///
    /// If the key scan is up-to-date with the given Merkle commitment, it will return its keypair,
    /// all of the records it has discovered with Merkle paths relative to that commitment, as well
    /// as all of the transaction history entries added during the scan. This consumes the scan so
    /// it can not be used once it is finalized.
    ///
    /// If `merkle_commitment` does not match the scan's Merkle tree, meaning the scan is
    /// in progress, it returns `self` so that the scan can continue to be used.
    pub fn finalize(self, merkle_commitment: MerkleCommitment) -> ScanStatus<L> {
        if merkle_commitment == self.records_mt.commitment() {
            let mt = self.records_mt;
            let records = self
                .records
                .into_values()
                .map(|(ro, uid)| (ro, uid, mt.get_leaf(uid).expect_ok().unwrap().1.path))
                .collect();
            ScanStatus::Finished {
                key: self.key,
                records,
                history: self.history,
            }
        } else {
            ScanStatus::InProgress(self)
        }
    }

    pub fn address(&self) -> UserAddress {
        self.key.address()
    }

    pub fn next_event(&self) -> EventIndex {
        self.next_event
    }

    /// The status of a ledger scan.
    ///
    /// Returns (`next_event`, `to_event`) where `next_event` is the index of the next event to be
    /// scanned and `to_event` is the index of the last event in the scan's range of interest. Note
    /// that the `next_event` may be greater than `to_event`, since the scan will not complete until
    /// it has caught with the main event loop, which may have advanced past `to_event`.
    pub fn status(&self) -> (EventIndex, EventIndex) {
        (self.next_event, self.to_event)
    }

    pub fn handle_event(&mut self, event: LedgerEvent<L>, source: EventSource) {
        if self.from_event.index(source) <= self.next_event.index(source)
            && self.next_event.index(source) < self.to_event.index(source)
        {
            // If this event falls in the range from which we want to discover records, try and do
            // so.
            self.handle_event_in_range(event);
        } else {
            // Otherwise, just update our data structures.
            self.handle_event_out_of_range(event);
        }

        self.next_event += EventIndex::from_source(source, 1);
    }

    fn handle_event_in_range(&mut self, event: LedgerEvent<L>) {
        match event {
            LedgerEvent::Commit { block, .. } => {
                let mut uid = self.records_mt.num_leaves();

                // Add the record commitments from this block.
                self.records_mt.extend(
                    block
                        .txns()
                        .into_iter()
                        .flat_map(|txn| txn.output_commitments()),
                );

                for txn in block.txns() {
                    // Remove any records that were spent by this transaction.
                    for n in txn.input_nullifiers() {
                        if let Some((_, uid)) = self.records.remove(&n) {
                            // If we removed a record that we had already discovered, prune it's
                            // path from the Merkle tree.
                            self.records_mt.forget(uid);
                        }
                    }

                    if let Some(records) = txn.output_openings() {
                        // If the transaction exposes its records, add the records themselves if
                        // they belong to us; forget their Merkle paths if they do not.
                        let mut received_records = vec![];
                        for record in records {
                            let comm = RecordCommitment::from(&record);
                            if record.pub_key == self.key.pub_key() {
                                received_records.push(record.clone());
                                let nullifier = self.key.nullify(
                                    record.asset_def.policy_ref().freezer_pub_key(),
                                    uid,
                                    &comm,
                                );
                                // If the record belongs to us, add it to our records.
                                self.records.insert(nullifier, (record, uid));
                            } else {
                                self.records_mt.forget(uid);
                            }

                            uid += 1;
                        }
                        if !received_records.is_empty() {
                            self.history.push((
                                TransactionUID::<L>(txn.hash().clone()),
                                receive_history_entry(txn.kind(), &received_records),
                            ));
                        }
                    } else {
                        // If the transaction does not expose its records forget all of the Merkle
                        // paths we added for it. If we are a receiver of this transaction, we will
                        // remember the relevant paths later on when we get the owner memos.
                        for _ in txn.output_commitments() {
                            self.records_mt.forget(uid);
                            uid += 1;
                        }
                    }
                }
            }

            LedgerEvent::Memos {
                outputs,
                transaction,
                ..
            } => {
                let mut records = Vec::new();
                for (memo, comm, uid, proof) in outputs {
                    if let Ok(record_opening) = memo.decrypt(&self.key, &comm, &[]) {
                        if !record_opening.is_dummy() {
                            // If this record is for us (i.e. its corresponding memo decrypts under
                            // our key) and not a dummy, then add it to our received records.
                            records.push((
                                record_opening,
                                uid,
                                MerkleLeafProof::new(comm.to_field_element(), proof.clone()),
                            ));
                        }
                    }
                }

                // Add received records to our collection.
                for (ro, uid, proof) in &records {
                    let nullifier = self.key.nullify(
                        ro.asset_def.policy_ref().freezer_pub_key(),
                        *uid,
                        &RecordCommitment::from(ro),
                    );
                    if self.records_mt.remember(*uid, proof).is_ok() {
                        self.records.insert(nullifier, (ro.clone(), *uid));
                    } else {
                        tracing::error!("Got bad Merkle proof. Unable to add record {}", uid);
                    }
                }

                if !records.is_empty() {
                    // Add a history entry for the received transaction.
                    if let Some((_, _, hash, txn_kind)) = transaction {
                        self.history.push((
                            TransactionUID::<L>(hash),
                            receive_history_entry(
                                txn_kind,
                                &records.into_iter().map(|(ro, _, _)| ro).collect::<Vec<_>>(),
                            ),
                        ));
                    }
                }
            }

            LedgerEvent::Reject { .. } => {}
        }
    }

    fn handle_event_out_of_range(&mut self, event: LedgerEvent<L>) {
        if let LedgerEvent::Commit { block, .. } = event {
            // Remove records invalidated by the new block's nullifiers.
            for n in block
                .txns()
                .into_iter()
                .flat_map(|txn| txn.input_nullifiers())
            {
                if let Some((_, uid)) = self.records.remove(&n) {
                    // If we removed a record that we had already discovered, prune it's path from
                    // the Merkle tree.
                    self.records_mt.forget(uid);
                }
            }

            // Add new commitments to the Merkle tree in order to update the root, then forget the
            // new Merkle paths since we don't care about records in this range.
            let first_uid = self.records_mt.num_leaves();
            self.records_mt.extend(
                block
                    .txns()
                    .into_iter()
                    .flat_map(|txn| txn.output_commitments()),
            );
            for uid in first_uid..self.records_mt.num_leaves() {
                self.records_mt.forget(uid);
            }
        }
    }
}

pub fn receive_history_entry<L: Ledger>(
    kind: TransactionKind<L>,
    records: &[RecordOpening],
) -> TransactionParams<L> {
    // The last record is guaranteed not to be the fee change record. It contains useful
    // information about asset type and freeze state.
    let last_record = records.last().unwrap();
    let kind = if kind == TransactionKind::<L>::send() {
        TransactionKind::<L>::receive()
    } else if kind == TransactionKind::<L>::freeze()
        && last_record.freeze_flag == FreezeFlag::Unfrozen
    {
        TransactionKind::<L>::unfreeze()
    } else {
        kind
    };

    let txn_asset = last_record.asset_def.code;
    TransactionParams::<L> {
        timeout: None,
        status: TransactionStatus::Retired,
        signed_memos: None,
        inputs: Default::default(),
        outputs: records.to_vec(),
        time: Local::now(),
        asset: txn_asset,
        kind,
        // When we receive transactions, we can't tell from the protocol who sent it to us.
        senders: Vec::new(),
        receivers: records
            .iter()
            .filter_map(|ro| {
                if ro.asset_def.code == txn_asset {
                    Some((ro.pub_key.address(), ro.amount.into()))
                } else {
                    // Ignore records of the wrong asset type (e.g. the fee change output for a non-
                    // native asset transfer).
                    None
                }
            })
            .collect(),
        fee_change: None,
        asset_change: None,
    }
}
