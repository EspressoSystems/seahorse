// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Event definitions for ledger state changes.
use arbitrary::Arbitrary;
use espresso_macros::ser_test;
use jf_cap::{
    structs::{ReceiverMemo, RecordCommitment},
    MerklePath,
};
use reef::*;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::ops::{Add, AddAssign};
use std::str::FromStr;

/// A ledger state change.
#[derive(Clone, Debug, Serialize, Deserialize, strum_macros::IntoStaticStr)]
#[serde(bound = "")]
pub enum LedgerEvent<L: Ledger> {
    /// A new block was added to the ledger.
    ///
    /// Includes the block contents, the unique identifier for the block, and the new state
    /// commitment.
    Commit {
        block: Block<L>,
        block_id: u64,
        state_comm: StateCommitment<L>,
    },

    /// A proposed block was rejected.
    ///
    /// Includes the block contents and the reason for rejection.
    Reject {
        block: Block<L>,
        error: ValidationError<L>,
    },

    /// Receiver memos were posted for one or more previously accepted transactions.
    ///
    /// For each UTXO corresponding to the posted memos, includes the memo, the record commitment,
    /// the unique identifier for the record, and a proof that the record commitment exists in the
    /// current UTXO set.
    ///
    /// If these memos correspond to a committed transaction, the `(block_id, transaction_id)` are
    /// included in `transaction`.
    Memos {
        outputs: Vec<(ReceiverMemo, RecordCommitment, u64, MerklePath)>,
        transaction: Option<(u64, u64, TransactionKind<L>)>,
    },
}

/// An index into the [LedgerEvent] stream.
///
/// Keystores subscribe to events; this is how they keep in sync with the outside world. They need to
/// track their index into the event stream in case they get disconnected or closed, so that they
/// can resubscribe starting at the appropriate event when they reconnect.
///
/// However, "the" event stream is a conceptual thing, representing multiple actual streams which
/// come from different sources and are not ordered or indexed with respect to one another. In other
/// words, "the" event stream is multi-dimensional, and indexes into it are vectors of indexes into
/// each of the individual streams.
#[ser_test(arbitrary, ark(false))]
#[derive(Arbitrary, Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventIndex {
    // Index into the query service event stream (provides Commit and Reject events)
    query_service: usize,
    // Index into the bulletin board event stream (provides Memos events)
    bulletin_board: usize,
}

impl EventIndex {
    /// An [EventIndex] with the given index into the given event source, and 0 for other indices.
    pub fn from_source(source: EventSource, index: usize) -> Self {
        Self::default().add_from_source(source, index)
    }

    /// An [EventIndex] with the given indices.
    pub fn new(query_service: usize, bulletin_board: usize) -> Self {
        Self {
            query_service,
            bulletin_board,
        }
    }

    /// Get the index into a particular event stream.
    pub fn index(&self, source: EventSource) -> usize {
        match source {
            EventSource::QueryService => self.query_service,
            EventSource::BulletinBoard => self.bulletin_board,
        }
    }

    /// Add to the index into a particular event stream, leaving other indices unchanged.
    ///
    /// Returns a new [EventIndex], the original index is unmodified.
    #[must_use]
    pub fn add_from_source(mut self, source: EventSource, amount: usize) -> Self {
        match source {
            EventSource::QueryService => self.query_service += amount,
            EventSource::BulletinBoard => self.bulletin_board += amount,
        };
        self
    }
}

impl PartialOrd<Self> for EventIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            Some(Ordering::Equal)
        } else if self.query_service <= other.query_service
            && self.bulletin_board <= other.bulletin_board
        {
            Some(Ordering::Less)
        } else if other.query_service <= self.query_service
            && other.bulletin_board <= self.bulletin_board
        {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

impl Add<Self> for EventIndex {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            query_service: self.query_service + rhs.query_service,
            bulletin_board: self.bulletin_board + rhs.bulletin_board,
        }
    }
}

impl AddAssign<Self> for EventIndex {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Display for EventIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}={},{}={}",
            EventSource::QueryService,
            self.query_service,
            EventSource::BulletinBoard,
            self.bulletin_board
        )
    }
}

impl FromStr for EventIndex {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // This parse method is meant for a friendly, discoverable CLI interface. It parses a comma-
        // separated list of key-value pairs, like `query_service=42`. The result starts as a
        // default EventIndex, and is successively modified according to each key value pair. This
        // allows the fields to be specified in any order, or not at all.
        //
        // For convenience, it will also accept the string "start", indicating the all-zero event
        // index representing the start of all event streams.
        if s.trim() == "start" {
            return Ok(Self::default());
        }

        let mut ret = Self::default();
        for kv in s.split(',') {
            let (key, value) = match kv.split_once('=') {
                Some(split) => split,
                None => return Err(format!("expected key=value pair, got {}", kv)),
            };
            let ix = match value.parse() {
                Ok(ix) => ix,
                Err(_) => return Err(format!("expected integer, got {}", value)),
            };
            match key.parse() {
                Ok(EventSource::QueryService) => ret.query_service = ix,
                Ok(EventSource::BulletinBoard) => ret.bulletin_board = ix,
                Err(err) => return Err(err),
            }
        }
        Ok(ret)
    }
}

/// The event streams that the keystore can subscribe to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventSource {
    QueryService,
    BulletinBoard,
}

impl Display for EventSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::QueryService => "query_service",
                Self::BulletinBoard => "bulletin_board",
            }
        )
    }
}

impl FromStr for EventSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query_service" => Ok(Self::QueryService),
            "bulletin_board" => Ok(Self::BulletinBoard),
            _ => Err(format!(
                "expected 'query_service' or 'bulletin_board', got {}",
                s
            )),
        }
    }
}
