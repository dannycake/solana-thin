//! Building proofs from a block's data shreds.
//!
//! The prover is the untrusted half. It runs wherever the shreds are: a
//! validator, an RPC node, a Geyser plugin, anything that keeps a slot's data
//! shreds. It needs no keys and no trust, because everything it produces is
//! checked by the client against a block id the validators signed.
//!
//! It needs only the *data* shreds, exactly as stored (1,203 bytes each). The
//! coding shreds are covered by one hash that every data shred already
//! carries in its own Merkle path.

use crate::block::{self, Footer, Marker, TxPosition};
use crate::certificate::{BlockRef, FinalityCert};
use crate::error::{Error, Result};
use crate::merkle::{self, Hash, Node, Tree, DATA_SHREDS_PER_FEC_SET};
use crate::proof::{BlockProof, FecSetProof, ParentLink, TxProof};
use crate::shred::RawDataShred;
use std::collections::BTreeSet;

/// One component of a block and the shreds it spans.
#[derive(Debug, Clone)]
struct Component {
    /// First shred.
    start: u32,
    /// Bytes of the component, padding included.
    data: Vec<u8>,
    /// Meaningful bytes contributed by each shred, in order.
    shred_lens: Vec<usize>,
}

impl Component {
    /// The shred holding byte `offset - 1`: the last shred a parse up to
    /// `offset` touches.
    fn last_shred_for(&self, offset: usize) -> u32 {
        let mut seen = 0;
        for (i, len) in self.shred_lens.iter().enumerate() {
            seen += len;
            if seen >= offset {
                return self.start + i as u32;
            }
        }
        self.start + self.shred_lens.len().saturating_sub(1) as u32
    }
}

/// A whole block, indexed for proving.
#[derive(Debug, Clone)]
pub struct BlockData {
    block: BlockRef,
    parent: BlockRef,
    shreds: Vec<RawDataShred>,
    fec_roots: Vec<Hash>,
    tree: Tree,
    components: Vec<Component>,
}

impl BlockData {
    /// Indexes a block from all of its data shreds, in any order.
    ///
    /// Fails if a shred is missing, if shreds disagree about slot or version,
    /// or if the leader switched parent mid-block (no inclusion proof can be
    /// built for such a block; see [`Error::UpdateParentBlock`]).
    pub fn from_shreds<T: AsRef<[u8]>>(payloads: &[T]) -> Result<Self> {
        Self::index(payloads, None)
    }

    /// Indexes a block whose leader switched parent mid-way, taking the final
    /// parent on faith. Only for tests that play a dishonest prover: an honest
    /// one refuses such blocks.
    #[cfg(any(test, feature = "testkit"))]
    pub fn from_shreds_with_final_parent<T: AsRef<[u8]>>(
        payloads: &[T],
        final_parent: BlockRef,
    ) -> Result<Self> {
        Self::index(payloads, Some(final_parent))
    }

    fn index<T: AsRef<[u8]>>(payloads: &[T], final_parent: Option<BlockRef>) -> Result<Self> {
        let mut shreds = payloads
            .iter()
            .map(|p| RawDataShred::parse(p.as_ref()))
            .collect::<Result<Vec<_>>>()?;
        shreds.sort_by_key(|s| s.index);
        let first = shreds.first().ok_or(Error::MissingShred(0))?;
        let (slot, version) = (first.slot, first.shred_version);
        if shreds.len() % DATA_SHREDS_PER_FEC_SET != 0 {
            return Err(Error::MissingShred(shreds.len() as u32));
        }
        for (i, shred) in shreds.iter().enumerate() {
            if shred.index != i as u32 {
                return Err(Error::MissingShred(i as u32));
            }
            if shred.slot != slot || shred.shred_version != version {
                return Err(Error::InvalidShred(
                    "slot or version differs within the block",
                ));
            }
            if shred.fec_set_index != (i - i % DATA_SHREDS_PER_FEC_SET) as u32 {
                return Err(Error::InvalidShred("FEC set index"));
            }
        }

        // One root per FEC set; every shred of a set must agree on it.
        let mut fec_roots = Vec::with_capacity(shreds.len() / DATA_SHREDS_PER_FEC_SET);
        for set in shreds.chunks(DATA_SHREDS_PER_FEC_SET) {
            let root = set[0].fec_set_root()?;
            for shred in set {
                if shred.fec_set_root()? != root {
                    return Err(Error::InvalidShred(
                        "shreds of one FEC set disagree on its root",
                    ));
                }
            }
            fec_roots.push(root);
        }

        // Components are the runs between DATA_COMPLETE flags.
        let mut components = Vec::new();
        let mut current: Option<Component> = None;
        for shred in &shreds {
            let component = current.get_or_insert_with(|| Component {
                start: shred.index,
                data: Vec::new(),
                shred_lens: Vec::new(),
            });
            component.shred_lens.push(shred.shred.data_len()?);
            shred.shred.append_data(&mut component.data)?;
            if shred.shred.data_complete() {
                components.push(current.take().unwrap());
            }
        }
        if current.is_some() {
            return Err(Error::InvalidComponent(
                "block does not end on a component boundary",
            ));
        }

        // The header counts only if it sits whole in shred 0, which is where
        // a validator's blockstore reads it. See `ThinClient::verify_transaction`.
        let mut first_shred = Vec::new();
        shreds[0].shred.append_data(&mut first_shred)?;
        let parent = match block::parse_marker(&first_shred) {
            Ok(Marker::Header { parent }) => Some(parent),
            _ => None,
        };
        for component in &components {
            if block::is_entry_batch(&component.data) {
                continue;
            }
            if let Ok(Marker::UpdateParent { .. }) = block::parse_marker(&component.data) {
                if final_parent.is_none() {
                    return Err(Error::UpdateParentBlock);
                }
            }
        }
        let parent = match final_parent {
            Some(parent) => parent,
            None => parent.ok_or(Error::InvalidComponent(
                "block does not start with a header",
            ))?,
        };

        let fec_set_count = fec_roots.len() as u32;
        let mut leaves = fec_roots.clone();
        leaves.push(merkle::sha256(&[
            &parent.slot.to_le_bytes(),
            &parent.id,
            &fec_set_count.to_le_bytes(),
        ]));
        let tree = Tree::new(leaves);
        Ok(Self {
            block: BlockRef {
                slot,
                id: tree.root(),
            },
            parent,
            shreds,
            fec_roots,
            tree,
            components,
        })
    }

    /// The block: its slot and the id computed from the shreds. Compare this
    /// with the id in a finality certificate before building a proof on it.
    pub fn block(&self) -> BlockRef {
        self.block
    }

    /// The block's parent.
    pub fn parent(&self) -> BlockRef {
        self.parent
    }

    /// The parent leaf and its path, for use in an ancestry chain.
    pub fn parent_link(&self) -> ParentLink {
        ParentLink {
            parent: self.parent,
            fec_set_count: self.fec_roots.len() as u32,
            path: self.tree.path(self.fec_roots.len()),
        }
    }

    /// The footer and the index of its first shred, if the block has one.
    pub fn footer(&self) -> Option<(u32, Footer)> {
        self.components.iter().find_map(|c| {
            if block::is_entry_batch(&c.data) {
                return None;
            }
            match block::parse_marker(&c.data) {
                Ok(Marker::Footer(footer)) => Some((c.start, *footer)),
                _ => None,
            }
        })
    }

    /// Signatures of every transaction in the block, in order.
    pub fn signatures(&self) -> Vec<[u8; 64]> {
        self.components
            .iter()
            .filter(|c| block::is_entry_batch(&c.data))
            .filter_map(|c| block::transactions(&c.data).ok())
            .flatten()
            .map(|(_, tx)| *tx.signature())
            .collect()
    }

    /// Finds a transaction by its first signature. Returns its component, its
    /// position, and the offset just past its last byte.
    fn locate(&self, signature: &[u8; 64]) -> Result<(&Component, TxPosition, usize)> {
        for component in &self.components {
            if component.start == 0 || !block::is_entry_batch(&component.data) {
                continue;
            }
            for (position, tx) in block::transactions(&component.data)? {
                if tx.signature() == signature {
                    return Ok((component, position, end_of(&component.data, position)?));
                }
            }
        }
        Err(Error::SignatureNotFound)
    }

    /// Opens the shreds that show `signature` is in this block: the header
    /// shred, the shred before the transaction's component, and the component
    /// up to the transaction's last byte. With `with_footer`, the footer too.
    pub fn prove_transaction(
        &self,
        signature: &[u8; 64],
        with_footer: bool,
    ) -> Result<(BlockProof, u32, TxPosition, Option<u32>)> {
        let (component, position, end) = self.locate(signature)?;
        let mut needed = BTreeSet::new();
        needed.insert(0u32);
        needed.insert(component.start - 1);
        needed.extend(component.start..=component.last_shred_for(end));
        let mut footer_start = None;
        if with_footer {
            if let Some(footer) = self.components.iter().find(|c| {
                !block::is_entry_batch(&c.data)
                    && matches!(block::parse_marker(&c.data), Ok(Marker::Footer(_)))
            }) {
                needed.insert(footer.start - 1);
                needed.extend(footer.start..=footer.last_shred_for(footer.data.len()));
                footer_start = Some(footer.start);
            }
        }
        Ok((self.open(&needed), component.start, position, footer_start))
    }

    /// Number of data shreds in the block.
    pub fn shred_count(&self) -> u32 {
        self.shreds.len() as u32
    }

    /// Start index and bytes of each component, in block order.
    pub fn components(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.components.iter().map(|c| (c.start, c.data.as_slice()))
    }

    /// Opens the given shreds, one contiguous run per FEC set touched.
    ///
    /// Panics if `needed` is empty or names a shred the block does not have.
    pub fn open(&self, needed: &BTreeSet<u32>) -> BlockProof {
        assert!(!needed.is_empty(), "nothing to open");
        let per_set = DATA_SHREDS_PER_FEC_SET as u32;
        let mut sets = Vec::new();
        let mut touched: Vec<u32> = needed.iter().map(|i| i / per_set).collect();
        touched.dedup();
        for set in touched {
            let base = set * per_set;
            let in_set = needed.range(base..base + per_set);
            let first = *in_set.clone().next().unwrap();
            let last = *in_set.clone().next_back().unwrap();
            let all = &self.shreds[base as usize..(base + per_set) as usize];
            let leaves: Vec<Hash> = all.iter().map(|s| s.leaf_hash().unwrap()).collect();
            let run = (first - base) as usize..=(last - base) as usize;
            let coding_root: Node = all[0].proof[5];
            sets.push(FecSetProof {
                set,
                first: (first - base) as u8,
                shreds: all[run.clone()].iter().map(|s| s.shred.clone()).collect(),
                chained_root: all[0].chained_root,
                siblings: merkle::data_range_siblings(
                    &leaves,
                    *run.start(),
                    run.end() - run.start() + 1,
                ),
                coding_root,
                path: self.tree.path(set as usize),
            });
        }
        BlockProof {
            parent: self.parent_link(),
            sets,
        }
    }
}

/// Offset just past the transaction at `position` in an entry batch, measured
/// with the same walk the verifier uses.
fn end_of(data: &[u8], position: TxPosition) -> Result<usize> {
    let mut r = crate::wire::Reader::new(data);
    r.u64()?;
    for entry in 0..=position.entry {
        r.bytes(40)?;
        let count = r.u64()?;
        let stop = if entry == position.entry {
            u64::from(position.transaction) + 1
        } else {
            count
        };
        for _ in 0..stop {
            crate::transaction::Transaction::read(&mut r)?;
        }
    }
    Ok(r.position())
}

/// Assembles a [`TxProof`].
///
/// `chain` lists blocks from the certified block back to the one holding the
/// transaction, newest first; each must be the parent of the one before it.
/// A single-element chain means the certificate is for the transaction's own
/// block.
pub fn prove(
    finality: FinalityCert,
    chain: &[&BlockData],
    signature: &[u8; 64],
    with_footer: bool,
) -> Result<TxProof> {
    let (target, ancestors) = chain.split_last().ok_or(Error::BrokenAncestry)?;
    if chain[0].block() != finality.block() {
        return Err(Error::BlockIdMismatch);
    }
    let mut ancestry = Vec::with_capacity(ancestors.len());
    for (child, parent) in chain.iter().zip(chain.iter().skip(1)) {
        if child.parent() != parent.block() {
            return Err(Error::BrokenAncestry);
        }
        ancestry.push(child.parent_link());
    }
    let (block, component_start, position, footer_start) =
        target.prove_transaction(signature, with_footer)?;
    Ok(TxProof {
        finality,
        ancestry,
        block,
        component_start,
        position,
        footer_start,
    })
}
