//! The two Merkle trees that tie a byte of block data to a block id.
//!
//! An Alpenglow block id is a "double Merkle" root:
//!
//! ```text
//!                       block id
//!                      /        \
//!            ...                      ...
//!        /        \                /        \
//!   FEC root 0  FEC root 1  ...  FEC root n-1  parent leaf
//!       |
//!   64 leaves: 32 data shreds, then 32 coding shreds
//! ```
//!
//! Both trees use the same node rule, taken from Agave's
//! `ledger/src/shred/merkle_tree.rs`: a parent is
//! `sha256(NODE_PREFIX ‖ left[..20] ‖ right[..20])`. Children are truncated to
//! 20 bytes; a root is the full 32. A level with an odd number of nodes pairs
//! its last node with itself.
//!
//! That last rule is the dangerous one. In a tree of three leaves the third
//! leaf also verifies at index 3, as its own sibling. A verifier that takes a
//! leaf index on faith can be shown a leaf that is not there. Every caller in
//! this crate therefore fixes the path length from the tree size and bounds
//! the index by a count that the tree itself commits to.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

/// A full SHA-256 output.
pub type Hash = [u8; 32];
/// A tree node as it appears in a proof: the first 20 bytes of its hash.
pub type Node = [u8; 20];

const LEAF_PREFIX: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const NODE_PREFIX: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

/// Data shreds in one FEC set.
pub const DATA_SHREDS_PER_FEC_SET: usize = 32;
/// Depth of the data half of a FEC set's tree.
const DATA_TREE_DEPTH: usize = 5;

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The leaf hash of a shred: its bytes from just after the leader's signature
/// up to, but not including, its own Merkle proof.
pub fn shred_leaf(leaf_bytes: &[u8]) -> Hash {
    sha256(&[LEAF_PREFIX, leaf_bytes])
}

/// Joins two children. Only the first 20 bytes of each are used.
pub fn join(left: &[u8], right: &[u8]) -> Hash {
    sha256(&[NODE_PREFIX, &left[..20], &right[..20]])
}

/// Truncates a hash to the form it takes inside a proof.
pub fn truncate(hash: &Hash) -> Node {
    let mut node = [0u8; 20];
    node.copy_from_slice(&hash[..20]);
    node
}

/// Number of siblings on the path from any leaf to the root of a tree with
/// `leaves` leaves. All leaves sit at the same depth because odd levels are
/// padded by duplication.
pub fn path_len(leaves: usize) -> usize {
    if leaves <= 1 {
        0
    } else {
        (usize::BITS - (leaves - 1).leading_zeros()) as usize
    }
}

/// Walks a leaf up to the root of a tree that has exactly `leaves` leaves.
///
/// The path must be exactly as long as the tree is tall and `index` must name
/// a real leaf. Both checks are what stop the duplicated-last-node trick
/// described in the module docs.
pub fn root_from_path(index: usize, leaves: usize, leaf: Hash, path: &[Node]) -> Result<Hash> {
    if index >= leaves || path.len() != path_len(leaves) {
        return Err(Error::InvalidMerkleProof);
    }
    let mut node = leaf;
    let mut index = index;
    for sibling in path {
        node = if index % 2 == 0 {
            join(&node, sibling)
        } else {
            join(sibling, &node)
        };
        index >>= 1;
    }
    debug_assert_eq!(index, 0);
    Ok(node)
}

/// Root of the 32-leaf data half of a FEC set, from a contiguous run of leaves
/// starting at `first` plus the subtree hashes that cover everything else.
///
/// `siblings` are consumed left to right in the order a depth-first walk meets
/// subtrees that lie wholly outside the run. The walk is fixed by `first` and
/// the run's length alone, so there is exactly one valid sibling list for a
/// given run and no room for an attacker to re-interpret one.
pub fn data_range_root(first: usize, leaves: &[Hash], siblings: &[Node]) -> Result<Hash> {
    let end = first
        .checked_add(leaves.len())
        .ok_or(Error::InvalidMerkleProof)?;
    if leaves.is_empty() || end > DATA_SHREDS_PER_FEC_SET {
        return Err(Error::InvalidMerkleProof);
    }
    let mut siblings = siblings.iter();
    let root = range_node(0, DATA_TREE_DEPTH, first, end, leaves, &mut siblings)?;
    if siblings.next().is_some() {
        return Err(Error::InvalidMerkleProof);
    }
    Ok(root)
}

/// Hash of the node covering leaves `[lo, lo + 2^height)`.
fn range_node(
    lo: usize,
    height: usize,
    first: usize,
    end: usize,
    leaves: &[Hash],
    siblings: &mut core::slice::Iter<'_, Node>,
) -> Result<Hash> {
    let hi = lo + (1usize << height);
    if hi <= first || lo >= end {
        // Wholly outside the run: the proof supplies it.
        let node = siblings.next().ok_or(Error::InvalidMerkleProof)?;
        let mut padded = [0u8; 32];
        padded[..20].copy_from_slice(node);
        return Ok(padded);
    }
    if height == 0 {
        return Ok(leaves[lo - first]);
    }
    let mid = lo + (1usize << (height - 1));
    let left = range_node(lo, height - 1, first, end, leaves, siblings)?;
    let right = range_node(mid, height - 1, first, end, leaves, siblings)?;
    Ok(join(&left, &right))
}

/// A tree built the way Agave builds it, kept whole so paths can be read off.
/// Used by the prover and the test builders, never by the verifier.
#[derive(Debug, Clone)]
pub struct Tree {
    levels: Vec<Vec<Hash>>,
}

impl Tree {
    /// Builds a tree over `leaves`. Panics if there are none.
    pub fn new(leaves: Vec<Hash>) -> Self {
        assert!(!leaves.is_empty(), "a Merkle tree needs at least one leaf");
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next = prev
                .chunks(2)
                .map(|pair| join(&pair[0], pair.get(1).unwrap_or(&pair[0])))
                .collect();
            levels.push(next);
        }
        Self { levels }
    }

    /// The root.
    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    /// Whether the tree has no leaves. Always false; here for completeness.
    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    /// Siblings from leaf `index` up to, but not including, the root.
    pub fn path(&self, index: usize) -> Vec<Node> {
        assert!(index < self.len());
        let mut index = index;
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = (index ^ 1).min(level.len() - 1);
            path.push(truncate(&level[sibling]));
            index >>= 1;
        }
        path
    }
}

/// The sibling list [`data_range_root`] expects for the run
/// `[first, first + count)` of a full set of 32 data leaf hashes.
pub fn data_range_siblings(all: &[Hash], first: usize, count: usize) -> Vec<Node> {
    assert_eq!(all.len(), DATA_SHREDS_PER_FEC_SET);
    assert!(count > 0 && first + count <= DATA_SHREDS_PER_FEC_SET);
    let tree = Tree::new(all.to_vec());
    let mut out = Vec::new();
    collect_siblings(&tree, 0, DATA_TREE_DEPTH, first, first + count, &mut out);
    out
}

fn collect_siblings(
    tree: &Tree,
    lo: usize,
    height: usize,
    first: usize,
    end: usize,
    out: &mut Vec<Node>,
) {
    let hi = lo + (1usize << height);
    if hi <= first || lo >= end {
        out.push(truncate(&tree.levels[height][lo >> height]));
        return;
    }
    if height == 0 {
        return;
    }
    let mid = lo + (1usize << (height - 1));
    collect_siblings(tree, lo, height - 1, first, end, out);
    collect_siblings(tree, mid, height - 1, first, end, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| sha256(&[&(i as u64).to_le_bytes()]))
            .collect()
    }

    #[test]
    fn path_len_matches_agave() {
        // get_proof_size() in Agave for a few sizes.
        for (n, want) in [
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (8, 3),
            (9, 4),
            (64, 6),
            (65, 7),
        ] {
            assert_eq!(path_len(n), want, "n = {n}");
        }
    }

    #[test]
    fn every_leaf_of_every_small_tree_verifies() {
        for n in 1..=40 {
            let l = leaves(n);
            let tree = Tree::new(l.clone());
            for (i, leaf) in l.iter().enumerate() {
                let root = root_from_path(i, n, *leaf, &tree.path(i)).unwrap();
                assert_eq!(root, tree.root(), "n = {n}, i = {i}");
            }
        }
    }

    #[test]
    fn duplicated_last_leaf_is_not_a_second_leaf() {
        // Three leaves: the tree pairs leaf 2 with itself, so the hashes also
        // work out for "leaf 3". The index bound is what rejects it.
        let l = leaves(3);
        let tree = Tree::new(l.clone());
        let phantom_path = vec![truncate(&l[2]), truncate(&join(&l[0], &l[1]))];
        // The arithmetic alone would accept it in a four-leaf tree...
        assert_eq!(
            root_from_path(3, 4, l[2], &phantom_path).unwrap(),
            tree.root()
        );
        // ...which is why the leaf count has to come from the tree itself.
        assert_eq!(
            root_from_path(3, 3, l[2], &phantom_path),
            Err(Error::InvalidMerkleProof)
        );
    }

    #[test]
    fn wrong_length_paths_are_rejected() {
        let l = leaves(8);
        let tree = Tree::new(l.clone());
        let mut path = tree.path(5);
        path.pop();
        assert!(root_from_path(5, 8, l[5], &path).is_err());
        let mut path = tree.path(5);
        path.push([0; 20]);
        assert!(root_from_path(5, 8, l[5], &path).is_err());
    }

    #[test]
    fn an_inner_node_cannot_pose_as_a_leaf() {
        let l = leaves(8);
        let tree = Tree::new(l.clone());
        let inner = join(&l[0], &l[1]);
        // The inner node with the top two siblings does reach the root, but
        // only with a path one short of the tree's height.
        let short: Vec<Node> = tree.path(0)[1..].to_vec();
        assert!(root_from_path(0, 8, inner, &short).is_err());
    }

    #[test]
    fn range_proofs_agree_with_the_full_tree_for_every_run() {
        let l = leaves(DATA_SHREDS_PER_FEC_SET);
        let root = Tree::new(l.clone()).root();
        for first in 0..DATA_SHREDS_PER_FEC_SET {
            for count in 1..=DATA_SHREDS_PER_FEC_SET - first {
                let sib = data_range_siblings(&l, first, count);
                let got = data_range_root(first, &l[first..first + count], &sib).unwrap();
                assert_eq!(got, root, "first = {first}, count = {count}");
            }
        }
    }

    #[test]
    fn range_proofs_reject_shifted_or_resized_runs() {
        let l = leaves(DATA_SHREDS_PER_FEC_SET);
        let root = Tree::new(l.clone()).root();
        let sib = data_range_siblings(&l, 4, 3);
        // Same leaves, claimed one position to the right.
        match data_range_root(5, &l[4..7], &sib) {
            Ok(r) => assert_ne!(r, root),
            Err(e) => assert_eq!(e, Error::InvalidMerkleProof),
        }
        // Extra and missing siblings.
        let mut more = sib.clone();
        more.push([7; 20]);
        assert!(data_range_root(4, &l[4..7], &more).is_err());
        assert!(data_range_root(4, &l[4..7], &sib[1..]).is_err());
        // Runs that fall off the end.
        assert!(data_range_root(31, &l[0..2], &[]).is_err());
        assert!(data_range_root(0, &[], &[]).is_err());
    }
}
