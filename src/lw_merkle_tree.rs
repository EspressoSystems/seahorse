// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Seahorse library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! A Merkle tree which supports arbitrarily sparse representations.

use arbitrary::{Arbitrary, Unstructured};
use arbitrary_wrappers::ArbitraryMerkleTree;
use jf_cap::{structs::RecordCommitment, AccMemberWitness, BaseField, MerkleTree};
use serde::{Deserialize, Serialize};

pub use jf_cap::{MerkleCommitment, MerkleFrontier, MerkleLeafProof, NodeValue};
pub use jf_primitives::merkle_tree::{FilledMTBuilder, LookupResult};

/// A lightweight Merkle tree which supports arbitrarily sparse representations.
///
/// A Merkle tree is an authenticated data structure representing a sequence of elements. It
/// supports appending new elements and querying for existing elements, much like a [Vec]. However,
/// a Merkle tree can also be _sparse_, where some elements which have been inserted in the sequence
/// are not actually represented in the data structure. Instead, they are represented by a
/// cryptographic hash. These hashes are concise, and many elements can be represented by a single
/// hash, so storing a Merkle tree sparsely in this way can dramatically reduce the storage
/// requirements of the tree. In the limit, a tree with height `H` can represent a sequence of `3^H`
/// elements using only `H` hashes.
///
/// Even when an element is not present in the actual representation of the sequence, do to
/// sparseness, another party who has access to a representation that _does_ contain the element in
/// question can prove to the party with the sparse tree that the element does exist in the sequence
/// at a specific index, using a [MerkleLeafProof]. The holder of the sparse tree can check this
/// proof -- if it is invalid, the operation will fail -- and then optionally use it to add the
/// missing element back into their representation of the sequence.
///
/// This data structure provides the basic Merkle tree operations such as appending and querying
/// elements, as well as fine controls over sparseness:
/// * [forget](Self::forget) can be used to prune an element that has been inserted in the tree
///   from the sparse representation of the tree, producing a proof that can be used to prove that
///   the forgotten element does still exist in the abstract sequence.
/// * [remember](Self::remember) can be used to check a membership proof (obtained from
///   [forget](Self::forget) or [get_leaf](Self::get_leaf)) and, if successful, add the element back
///   into the representation of the tree.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LWMerkleTree {
    tree: MerkleTree,
    // We can't forget the last leaf in a Merkle tree, because the tree always maintains the full
    // frontier (which includes the last leaf) as it is necessary to append more elements. Calling
    // forget on the underlying tree with the index of the last leaf does nothing, and doing this
    // repeatedly can eventually lead to a tree with a substantially large memory footprint than
    // intended. Instead, when the caller attempts to forget the last leaf of the tree, we just note
    // that we want to forget this leaf by setting `forget_last_leaf`. We will actually do the
    // forget operation when we append a new last leaf. In this way, we only maintain in memory at
    // most one more element than the caller would expect based on the `forget` calls they have
    // made.
    forget_last_leaf: bool,
}

impl From<MerkleTree> for LWMerkleTree {
    fn from(tree: MerkleTree) -> Self {
        Self {
            tree,
            // In this conversion, we want to create a lightweight Merkle tree which matches exactly the
            // representation of the given [MerkleTree]. In the given [MerkleTree], the last leaf is
            // included in the representation (since the last leaf is always included) so we
            // shouldn't forget it.
            forget_last_leaf: false,
        }
    }
}

impl From<LWMerkleTree> for MerkleTree {
    fn from(tree: LWMerkleTree) -> Self {
        tree.tree
    }
}

impl<'a> Arbitrary<'a> for LWMerkleTree {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            tree: u.arbitrary::<ArbitraryMerkleTree>()?.0,
            forget_last_leaf: u.arbitrary()?,
        })
    }
}

impl LWMerkleTree {
    /// Create a new Merkle with a specific height
    ///
    /// * `height` - height of the tree (number of hops from the root to a leaf). Returns [None] if
    ///   the capacity of the tree overflows a [u64]
    pub fn new(height: u8) -> Option<Self> {
        MerkleTree::new(height).map(Self::from)
    }

    /// Create a completely lightweight version of the given [MerkleTree].
    ///
    /// The resulting tree is merely a commitment to a sequence. It does not contain a
    /// representation of any actual elements, _even_ if those elements are represented in `tree`.
    /// For a conversion from [MerkleTree] which preserves semi-sparseness of the original tree, use
    /// `From<MerkleTree>`.
    pub fn sparse(mut tree: MerkleTree) -> Self {
        // Sparsify it.
        for i in 0..tree.num_leaves() {
            tree.forget(i);
        }
        Self {
            tree,
            forget_last_leaf: true,
        }
    }

    /// Recreates a completely lightweight Merkle tree from the rightmost leaf and proof to the root.
    ///
    /// Returns [None] if the capacity of the tree overflows a [u64]
    pub fn restore_from_frontier(
        commitment: MerkleCommitment,
        proof: &MerkleFrontier,
    ) -> Option<Self> {
        MerkleTree::restore_from_frontier(commitment, proof).map(Self::from)
    }

    /// Get a commitment to the abstract sequence represented by this Merkle tree.
    ///
    /// Two Merkle trees that have the same height and represent the same sequence will have the
    /// same commitment, regardless of sparseness. Merkle trees representing different sequences
    /// will have different commitments with overwhelming probability.
    pub fn commitment(&self) -> MerkleCommitment {
        self.tree.commitment()
    }

    /// Get the frontier of this Merkle tree.
    ///
    /// The frontier is a membership proof for the rightmost leaf. Since new elements are appended
    /// onto the right side of the tree, the frontier is all that is needed to append new elements
    /// to the tree. Indeed, [restore_from_frontier](Self::restore_from_frontier) can be used to
    /// create a new [LWMerkleTree] from just a frontier.
    pub fn frontier(&self) -> MerkleFrontier {
        self.tree.frontier()
    }

    /// Get the height of the tree.
    ///
    /// The height is fixed when the tree is created, and determines the maximum capacity of the
    /// tree: a tree with height `H` can contain at most `3^H` elements.
    pub fn height(&self) -> u8 {
        self.tree.height()
    }

    /// Get the number of elements, or leaves, which have been appended to the tree.
    pub fn num_leaves(&self) -> u64 {
        self.tree.num_leaves()
    }

    /// Append a new element to the sequence.
    ///
    /// * `elem` - element to insert in the tree
    pub fn push(&mut self, elem: BaseField) {
        self.tree.push(elem);
        // If we were planning to forget the old last leaf after appending a new leaf, do it now.
        if self.forget_last_leaf {
            self.tree.forget(self.num_leaves() - 2);
            self.forget_last_leaf = false;
        }
    }

    /// Returns the leaf value given a position
    ///
    /// * `pos` - leaf position
    /// * `returns` - Leaf value at the position. [LookupResult::EmptyLeaf] if the leaf position is
    ///   empty or invalid, [LookupResult::NotInMemory] if the leaf position has been forgotten.
    pub fn get_leaf(&self, pos: u64) -> LookupResult<(), MerkleLeafProof> {
        // `get_leaf` on the underlying tree will succeed if `pos` is the last leaf, even if the
        // last leaf is forgotten. This is inconsistent with the simple model of this data
        // structure's semantics, where `get_leaf` fails after `forget` succeeds, and it may lead to
        // confusing behavior, where `get_leaf` for otherwise-identical trees either succeeds or
        // fails based on the value of `forget_last_leaf`, a value which is hidden from the user.
        // Therefore, we need to check if the leaf we are querying is the last leaf which has
        // nominally been forgotten, and fail if it is.
        if self.forget_last_leaf && pos == self.num_leaves() - 1 {
            LookupResult::NotInMemory
        } else {
            self.tree.get_leaf(pos)
        }
    }

    /// Get a membership witness of a particular element for a CAP proof.
    pub fn acc_member_witness(&self, pos: u64) -> LookupResult<BaseField, AccMemberWitness> {
        // Like `get_leaf`, this function must fail deterinistically if the leaf we are retreiving
        // has been nominally forgotten, even if it is still accidentally in memory due to being a
        // part of the frontier.
        if self.forget_last_leaf && pos == self.num_leaves() - 1 {
            LookupResult::NotInMemory
        } else {
            AccMemberWitness::lookup_from_tree(&self.tree, pos)
        }
    }

    /// Trim the leaf at a given position from memory, if present.
    ///
    /// Return is identical to result if `self.get_leaf(pos)` were called before this call.
    pub fn forget(&mut self, pos: u64) -> LookupResult<(), MerkleLeafProof> {
        if pos < self.tree.num_leaves() - 1 {
            self.tree.forget(pos)
        } else {
            assert_eq!(pos, self.tree.num_leaves() - 1);
            // We can't forget the last leaf in a Merkle tree, because the tree always maintains the
            // full frontier (which includes the last leaf) as it is necessary to append more
            // elements. Instead, we just note that we want to forget this leaf, and we'll forget it
            // when we append a new last leaf.
            self.forget_last_leaf = true;
            self.tree.get_leaf(pos)
        }
    }

    /// "Re-insert" a leaf into the tree using its proof.
    ///
    /// Returns `Ok(())` if insertion is successful, or `Err((ix,val))` if the proof disagrees with
    /// the correct value `val` at position `ix` in the proof.
    pub fn remember(
        &mut self,
        pos: u64,
        proof: &MerkleLeafProof,
    ) -> Result<(), Option<(usize, NodeValue)>> {
        // If we were planning to forget this leaf once a new leaf is appended, stop planning that.
        if self.forget_last_leaf && pos == self.num_leaves() - 1 {
            self.forget_last_leaf = false;
        }
        self.tree.remember(pos, proof)
    }
}

impl Extend<BaseField> for LWMerkleTree {
    fn extend<T: IntoIterator<Item = BaseField>>(&mut self, leaves: T) {
        let mut leaves = leaves.into_iter().peekable();
        if leaves.peek().is_none() {
            // If there are no records to insert, just return. This is both an optimization and a
            // precondition of the following code -- in particular the logic involving
            // `forget_last_leaf` -- which assumes the iterator is non-empty.
            return;
        }
        // Save the index of the last leaf in case we want to forget it after appending.
        let leaf_to_forget = self.num_leaves() - 1;

        // FilledMTBuilder takes ownership of the MerkleTree, so we need to temporarily replace
        // `self.tree` with a dummy value (since we can't move out of a mutable reference). We
        // use a MerkleTree of height 0 as the dummy value, since its construction always succeeds
        // and the computation of 3^0 is cheap.
        let tree = std::mem::replace(&mut self.tree, MerkleTree::new(0).unwrap());
        let mut builder = FilledMTBuilder::from_existing(tree)
            .expect("failed to convert MerkleTree to FilledMTBuilder");
        for leaf in leaves {
            builder.push(leaf);
        }
        self.tree = builder.build();

        // Now that we have appended new leaves to the Merkle tree, we can forget the old last leaf,
        // if needed.
        if self.forget_last_leaf {
            self.tree.forget(leaf_to_forget);
            self.forget_last_leaf = false;
        }
    }
}

impl Extend<RecordCommitment> for LWMerkleTree {
    fn extend<T: IntoIterator<Item = RecordCommitment>>(&mut self, comms: T) {
        self.extend(comms.into_iter().map(|comm| comm.to_field_element()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::UniformRand;
    use quickcheck::Gen;
    #[cfg(feature = "slow-tests")]
    use quickcheck_macros::quickcheck;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    #[cfg(feature = "slow-tests")]
    use std::collections::HashSet;

    #[derive(Clone, Debug)]
    enum MerkleOp {
        Push(BaseField),
        Forget(u64),
        Remember(u64),
        Query(u64),
    }

    impl quickcheck::Arbitrary for MerkleOp {
        fn arbitrary(g: &mut Gen) -> Self {
            match g.choose(&[0, 1, 2, 3]).unwrap() {
                0 => {
                    let mut rng = ChaChaRng::from_seed([quickcheck::Arbitrary::arbitrary(g); 32]);
                    Self::Push(BaseField::rand(&mut rng))
                }
                1 => Self::Forget(quickcheck::Arbitrary::arbitrary(g)),
                2 => Self::Remember(quickcheck::Arbitrary::arbitrary(g)),
                3 => Self::Query(quickcheck::Arbitrary::arbitrary(g)),
                _ => unreachable!(),
            }
        }
    }

    #[cfg(feature = "slow-tests")]
    #[quickcheck]
    fn quickcheck_lw_merkle_tree(ops: Vec<MerkleOp>) -> bool {
        // We will do the same pushes to both `sparse_tree` and `full_tree`, but only forget/
        // remember using `sparse_tree`, so we can use `full_tree` to compare and to generate
        // proofs for remembering.
        let mut sparse_tree = LWMerkleTree::new(10).unwrap();
        let mut full_tree = LWMerkleTree::new(10).unwrap();
        let mut forgotten = HashSet::new();

        // The first operation must always be a push, as the other operations won't work without at
        // least one element in the tree. So start by pushing a random element.
        let f = BaseField::rand(&mut ChaChaRng::from_seed([0; 32]));
        full_tree.push(f);
        sparse_tree.push(f);

        for op in ops {
            match op {
                MerkleOp::Push(f) => {
                    sparse_tree.push(f);
                    full_tree.push(f);
                }
                MerkleOp::Forget(pos) => {
                    if !forgotten.contains(&(pos % sparse_tree.num_leaves())) {
                        let proof = sparse_tree
                            .forget(pos % sparse_tree.num_leaves())
                            .expect_ok()
                            .unwrap()
                            .1;
                        MerkleTree::check_proof(
                            sparse_tree.commitment().root_value,
                            pos % sparse_tree.num_leaves(),
                            &proof,
                        )
                        .unwrap();
                        forgotten.insert(pos % sparse_tree.num_leaves());
                    }
                }
                MerkleOp::Remember(pos) => {
                    let proof = full_tree
                        .get_leaf(pos % full_tree.num_leaves())
                        .expect_ok()
                        .unwrap()
                        .1;
                    sparse_tree
                        .remember(pos % sparse_tree.num_leaves(), &proof)
                        .unwrap();
                    sparse_tree
                        .get_leaf(pos % sparse_tree.num_leaves())
                        .expect_ok()
                        .unwrap();
                    forgotten.remove(&(pos % sparse_tree.num_leaves()));
                }
                MerkleOp::Query(pos) => {
                    let elem = full_tree
                        .get_leaf(pos % full_tree.num_leaves())
                        .expect_ok()
                        .unwrap()
                        .1;
                    if !forgotten.contains(&(pos % sparse_tree.num_leaves())) {
                        assert_eq!(
                            elem,
                            sparse_tree
                                .get_leaf(pos % sparse_tree.num_leaves())
                                .expect_ok()
                                .unwrap()
                                .1
                        );
                    }
                }
            }

            assert_eq!(sparse_tree.commitment(), full_tree.commitment());
        }

        true
    }
}
