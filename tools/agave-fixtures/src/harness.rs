//! The differential harness: one case, judged by Agave and by the light
//! client, and the properties that tie the two answers together.
//!
//! A case is a [`Recipe`]: what the block's components hold and how they are
//! cut into shreds. [`World::run`] builds it (settling the footer's bank hash
//! in a second pass), asks the oracle for Agave's verdict in three arrival
//! orders, then plays a dishonest prover against the light client: every
//! claim a proof could make about those shreds is built with
//! `RawBlock::open` and offered to `ThinClient::verify_transaction_bytes`.
//!
//! * P0, order: the verdict does not depend on the order shreds arrive in.
//! * P1, soundness: if Agave would vote, every accepted claim names a
//!   transaction Agave executed, at the coordinates Agave executed it, and
//!   reports Agave's block, parent and footer.
//! * P2, identity: the light client's block id is Agave's.
//! * P3, coverage (reported): what the honest prover can prove of what Agave
//!   executed.
//! * opening: a claim accepted from the fewest shreds that show it is also
//!   accepted with every shred opened.
//!
//! No certificate is ever signed over an id Agave did not vote for.

use {
    crate::oracle::{FEC_SET, JudgeOptions, Oracle, OracleConfig, Replay, Verdict, reseal},
    solana_entry::entry::Entry,
    solana_hash::Hash,
    solana_thin::{
        BlockRef, ClusterParams, ThinClient, TxPosition, TxProof,
        block::{self, Marker},
        prover::{self, BlockData},
        shred::{
            DATA_HEADERS_SIZE, DataShred, FLAG_DATA_COMPLETE, VARIANT_DATA, VARIANT_DATA_RESIGNED,
            body_capacity,
        },
        testkit::{BlockBuilder, RawBlock, TestValidators},
        transaction::Transaction as ThinTransaction,
    },
    solana_transaction::versioned::VersionedTransaction,
    std::collections::{BTreeMap, BTreeSet},
};

/// A block with a real id that test blocks build on. Its parent is genesis.
pub const PARENT_SLOT: u64 = 32;
/// A child of [`PARENT_SLOT`]: the parent a leader starts on before it
/// switches back to [`PARENT_SLOT`] with an UpdateParent marker.
pub const SIDE_SLOT: u64 = 33;
/// The slot a block whose shreds point at [`SIDE_SLOT`] is judged at: epoch
/// 1, first slot of a leader window, so an UpdateParent marker is legal in
/// it. See [`window_slot`] for why there are three such slots.
pub const TEST_SLOT: u64 = 36;
/// The slot a block whose shreds point at [`PARENT_SLOT`] is judged at.
pub const MAIN_TEST_SLOT: u64 = 40;
/// The slot a block whose shreds point at genesis is judged at.
pub const GENESIS_TEST_SLOT: u64 = 44;
/// A slot that is not the first of its leader window.
pub const MID_WINDOW_SLOT: u64 = 37;

/// The first-of-window slot a block is judged at, by the parent slot its
/// shred headers point at.
///
/// One slot per shred parent, because Agave's blockstore remembers, per
/// `(slot, UpdateParent FEC set)`, the parent offset of the marker shred
/// (`update_parent_shred_parent_cache`, `ledger/src/blockstore.rs`), and
/// nothing clears that memory when the slot is purged. Judging two blocks
/// with different shred parents at one slot would have the second one's
/// shreds refused for the first one's parent.
pub fn window_slot(shred_parent_slot: u64) -> u64 {
    match shred_parent_slot {
        PARENT_SLOT => MAIN_TEST_SLOT,
        0 => GENESIS_TEST_SLOT,
        _ => TEST_SLOT,
    }
}

/// `LAST_SHRED_IN_SLOT`, which includes the `DATA_COMPLETE` bit.
pub const FLAG_LAST_IN_SLOT: u8 = 0b1100_0000;

/// Validators the test certificates are signed by.
pub const VALIDATORS: usize = 4;
/// Stake of each.
pub const VALIDATOR_STAKE: u64 = 1_000;

/// A small deterministic generator, so a seed names a case.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator for `seed`.
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    /// The next 64 bits (SplitMix64).
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value below `n`; zero if `n` is zero.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    /// A value in `low..=high`.
    pub fn range(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high.saturating_sub(low) + 1)
    }

    /// True with probability `percent` in a hundred.
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    /// `n` bytes, none of them zero.
    pub fn nonzero_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() % 255) as u8 + 1).collect()
    }
}

/// A parent a marker names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Par {
    /// The block the oracle holds at this slot, by its real id. Genesis has
    /// no id; it is named with all zeros.
    Bank(u64),
    /// This slot with an id of 32 copies of this byte. The slot must still
    /// be one the oracle holds, because entries are chained on its bank.
    Fake(u64, u8),
}

impl Par {
    /// The slot named.
    pub fn slot(&self) -> u64 {
        match self {
            Par::Bank(slot) | Par::Fake(slot, _) => *slot,
        }
    }
}

/// A transaction to put in an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tx {
    /// A transfer from the mint to a fresh account.
    Transfer,
    /// A transfer of more than the mint holds: committed, and fails.
    Failing,
    /// A transfer whose signature has one bit flipped.
    BadSignature,
    /// A transfer naming a blockhash no bank has seen.
    UnknownBlockhash,
    /// The previous transaction of the block again, byte for byte.
    Duplicate,
    /// A transfer whose instruction data ends in the bytes of another
    /// complete, signed transfer.
    Embedding,
}

/// Bytes appended to the component before them, inside the same component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trailer {
    /// This many zero bytes.
    Zeros(usize),
    /// These bytes.
    Bytes(Vec<u8>),
    /// A header marker.
    Header(Par),
    /// An UpdateParent marker. The entry chain is not moved.
    UpdateParent(Par),
    /// A footer with the block's real bank hash.
    Footer,
    /// One more entry, as bytes, beyond what the batch's count covers. It
    /// continues the hash chain but the chain is not advanced past it.
    Entry(Vec<Tx>),
    /// One transaction, as bytes.
    Transaction(Tx),
}

/// One step of a block's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A header marker. The first one sets the parent the shred headers
    /// point at and the bank entries are chained on.
    Header(Par),
    /// An UpdateParent marker. Entries after it are chained on the new
    /// parent's bank, as a leader that switched would chain them.
    Switch(Par),
    /// An entry batch: entries, each a list of transactions.
    Batch(Vec<Vec<Tx>>),
    /// A batch of one empty entry: a tick. Last in a block it is the
    /// alpentick.
    Tick,
    /// The footer, with the settled bank hash.
    Footer,
    /// A footer with a made-up bank hash.
    DecoyFooter,
    /// A component of exactly these bytes.
    Raw(Vec<u8>),
    /// Appends to the previous component.
    Trail(Trailer),
    /// Adds to the entry count of the previous component.
    EntryCount(i64),
    /// Adds to the transaction count of the last entry of the previous
    /// component.
    TxCount(i64),
    /// Cuts this many bytes off the end of the previous component.
    Truncate(usize),
}

/// Where a component's `DATA_COMPLETE` flag goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// Pad with empty shreds to the end of the FEC set and flag the last
    /// one: the only placement the fetch-stage filter lets through.
    Aligned,
    /// Flag the shred holding the component's last byte; the next component
    /// starts in the very next shred.
    MidSet,
    /// Pad to the end of the FEC set and flag nothing, so the component
    /// runs on into the next one.
    Missing,
}

/// A change to one shred after cutting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Sets these flag bits on a shred.
    OrFlags(u32, u8),
    /// Replaces a shred's flags.
    SetFlags(u32, u8),
    /// Replaces a shred's parent offset.
    ParentOffset(u32, u16),
    /// Replaces a shred's `size` field, valid or not.
    Size(u32, u16),
    /// Writes these bytes into a shred's padding, right after `size`.
    Padding(u32, Vec<u8>),
}

/// How component bytes are cut into shreds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layout {
    /// For a component (by index), the sizes of its leading shreds. Shreds
    /// after those are filled to capacity.
    pub chunks: BTreeMap<usize, Vec<usize>>,
    /// Where a component's `DATA_COMPLETE` goes, if not [`End::Aligned`].
    pub ends: BTreeMap<usize, End>,
    /// FEC sets cut as the resigned variant.
    pub resigned_sets: BTreeSet<u32>,
    /// Changes to single shreds.
    pub edits: Vec<Edit>,
}

/// A block: content and layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    /// Slot of the block.
    pub slot: u64,
    /// Makes the transfers of otherwise equal recipes distinct.
    pub seed: u64,
    /// The content, in order.
    pub items: Vec<Item>,
    /// The cut.
    pub layout: Layout,
}

impl Recipe {
    /// A recipe with the plain layout, at the first-of-window slot for its
    /// header's parent ([`window_slot`]).
    pub fn new(seed: u64, items: Vec<Item>) -> Self {
        let mut recipe = Self {
            slot: TEST_SLOT,
            seed,
            items,
            layout: Layout::default(),
        };
        recipe.slot = window_slot(recipe.header_parent().slot());
        recipe
    }

    /// The parent the first header names; [`PARENT_SLOT`]'s block if there
    /// is no header.
    pub fn header_parent(&self) -> Par {
        self.items
            .iter()
            .find_map(|item| match item {
                Item::Header(parent) => Some(*parent),
                _ => None,
            })
            .unwrap_or(Par::Bank(PARENT_SLOT))
    }
}

/// A recipe turned into shreds.
#[derive(Debug, Clone)]
pub struct Realised {
    /// The component bytes.
    pub components: Vec<Vec<u8>>,
    /// Signed payloads, in index order.
    pub payloads: Vec<Vec<u8>>,
    /// The shreds as handed to `BlockBuilder::push_shreds`, if the payloads
    /// are exactly what `BlockBuilder` builds from them. `None` if a header
    /// field had to be patched in afterwards.
    pub shreds: Option<Vec<DataShred>>,
    /// The parent the builder was started with (it seeds the first chained
    /// root).
    pub builder_parent: BlockRef,
}

/// What Agave must do with a case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Nothing is asserted.
    Report,
    /// Agave votes.
    Voted,
    /// Agave does not vote.
    NotVoted,
    /// Agave votes and executes exactly this many transactions, replaying
    /// from this shred.
    VotedExecuting {
        /// Number of executed transactions.
        executed: usize,
        /// Shred index replay starts at.
        replay_start: u64,
        /// Component start of the first executed transaction (ignored if
        /// none is executed).
        first_component: u32,
    },
    /// Agave votes and at least one executed transaction is committed as
    /// failed.
    VotedWithFailure,
    /// Agave does not vote, and the slot never fills because this shred
    /// never reached the blockstore: the filter discarded it, or the shred
    /// parser refused it.
    DroppedShred(u32),
}

/// A named case.
#[derive(Debug, Clone)]
pub struct Case {
    /// Name: `group/shape` for corpus cases, `random/family/seed-n` for
    /// generated ones.
    pub name: String,
    /// Mutator family, for the accounting.
    pub family: &'static str,
    /// The block.
    pub recipe: Recipe,
    /// What Agave must do when fast leader handover is active.
    pub expect: Expect,
    /// Whether the block can only vote with fast leader handover active.
    /// With the feature off such a case must not vote.
    pub needs_handover: bool,
    /// Whether `--emit` writes it.
    pub freeze: bool,
}

/// Not a violation by the verifier: Agave's own verdict on a block depends
/// on the order its shreds arrive in. Reported, and not counted against a
/// run, for the one shape where it is known and understood.
///
/// A block on a zero-id (genesis) parent that carries an UpdateParent naming
/// the same parent. Inserted in order, the header is recorded first, reads as
/// absent (`ParentInfo::from_slot_meta`, ledger/src/blockstore.rs:542-551),
/// and the marker is accepted. If the marker's shred arrives before shred 0,
/// the header is then compared with it, found equal, and the slot is marked
/// dead (`UpdateParentMatchesBlockHeader`). So validators can disagree about
/// whether such a block is valid. The verifier refuses every claim about it
/// (`Error::ZeroParentId`). Any other order dependence is a P0 violation.
pub const UPSTREAM_ORDER: &str = "agave-order";

/// A broken property.
#[derive(Debug, Clone)]
pub struct Violation {
    /// `P0`, `P1`, `P2`, `premise`, `oracle`, or [`UPSTREAM_ORDER`].
    pub property: &'static str,
    /// What happened.
    pub detail: String,
}

/// One claim offered to the verifier.
#[derive(Debug, Clone)]
pub struct ClaimRecord {
    /// `component_start` of the proof.
    pub component_start: u32,
    /// Entry claimed.
    pub entry: u32,
    /// Transaction claimed.
    pub transaction: u32,
    /// `footer_start` of the proof.
    pub footer_start: Option<u32>,
    /// `Ok` if the verifier accepted the proof opening the fewest shreds
    /// that show the claim, otherwise its error.
    pub observed: Result<(), String>,
    /// The same for the proof opening every shred of the block.
    pub observed_full: Result<(), String>,
    /// Whether Agave executed a transaction at these coordinates (and, for
    /// a footer claim, processed a footer there).
    pub executed: bool,
    /// The encoded proof that opens the fewest shreds.
    pub proof: Vec<u8>,
}

/// Everything one run of a case produced.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The case.
    pub case: Case,
    /// Whether the world had fast leader handover active.
    pub handover: bool,
    /// The block as built.
    pub realised: Realised,
    /// Whether the footer's bank hash was settled in a second pass.
    pub settled: bool,
    /// Agave's verdict, shreds in index order.
    pub verdict: Verdict,
    /// Whether any arrival order voted.
    pub voted: bool,
    /// Why `RawBlock::from_shreds` refused, if it did.
    pub raw_error: Option<String>,
    /// Claims that could be enumerated from the shreds.
    pub enumerated: usize,
    /// Claims offered to the verifier (only when Agave voted).
    pub claims: Vec<ClaimRecord>,
    /// Broken properties.
    pub violations: Vec<Violation>,
    /// The verdict's `SlotMeta` or deadness moved with arrival order while
    /// no order voted. Reported, not a P0 violation.
    pub meta_moved: bool,
    /// Whether the blockstore kept every shred given.
    pub stored_all: bool,
    /// P3: honest-prover result per executed transaction, by reason.
    pub coverage: BTreeMap<String, usize>,
}

impl Outcome {
    /// Claims the verifier accepted, from either opening.
    pub fn accepted(&self) -> usize {
        self.claims
            .iter()
            .filter(|c| c.observed.is_ok() || c.observed_full.is_ok())
            .count()
    }

    /// Violations of one property.
    pub fn count(&self, property: &str) -> usize {
        self.violations
            .iter()
            .filter(|v| v.property == property)
            .count()
    }
}

/// One oracle, the validators certificates are signed by, and a light client
/// that trusts them.
pub struct World {
    /// Agave.
    pub oracle: Oracle,
    /// The certificate signers.
    pub validators: TestValidators,
    /// The verifier.
    pub client: ThinClient,
    /// Whether fast leader handover is active.
    pub handover: bool,
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

fn wire(tx: &VersionedTransaction) -> Vec<u8> {
    wincode::serialize(tx).expect("transaction serializes")
}

/// An entry batch as bytes: `count`, then each entry.
fn batch_bytes(entries: &[Entry]) -> (Vec<u8>, usize) {
    let mut out = (entries.len() as u64).to_le_bytes().to_vec();
    let mut last_count_at = 0;
    for entry in entries {
        entry_bytes(&mut out, entry, &mut last_count_at);
    }
    (out, last_count_at)
}

fn entry_bytes(out: &mut Vec<u8>, entry: &Entry, count_at: &mut usize) {
    out.extend_from_slice(&entry.num_hashes.to_le_bytes());
    out.extend_from_slice(entry.hash.as_ref());
    *count_at = out.len();
    out.extend_from_slice(&(entry.transactions.len() as u64).to_le_bytes());
    for tx in &entry.transactions {
        out.extend_from_slice(&wire(tx));
    }
}

fn add_u64_at(bytes: &mut [u8], at: usize, delta: i64) {
    let value = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    bytes[at..at + 8].copy_from_slice(&value.wrapping_add_signed(delta).to_le_bytes());
}

/// Cuts components into shreds as `layout` says, before edits.
fn cut(components: &[Vec<u8>], layout: &Layout, parent_offset: u16) -> Vec<DataShred> {
    let per_set = FEC_SET as usize;
    let variant_at = |n: usize| match layout.resigned_sets.contains(&((n / per_set) as u32)) {
        true => VARIANT_DATA_RESIGNED,
        false => VARIANT_DATA,
    };
    let shred = |n: usize, data: &[u8]| DataShred {
        variant: variant_at(n),
        parent_offset,
        flags: 0,
        size: (DATA_HEADERS_SIZE + data.len()) as u16,
        body: data.to_vec(),
    };
    let mut shreds: Vec<DataShred> = Vec::new();
    for (index, bytes) in components.iter().enumerate() {
        let mut rest = &bytes[..];
        let mut lead = layout
            .chunks
            .get(&index)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter();
        loop {
            let n = shreds.len();
            let capacity = body_capacity(variant_at(n)).expect("data variant");
            let want = lead
                .next()
                .copied()
                .unwrap_or(capacity)
                .min(capacity)
                .min(rest.len());
            shreds.push(shred(n, &rest[..want]));
            rest = &rest[want..];
            if rest.is_empty() {
                break;
            }
        }
        let end = layout.ends.get(&index).copied().unwrap_or(End::Aligned);
        if end != End::MidSet {
            while !shreds.len().is_multiple_of(per_set) {
                shreds.push(shred(shreds.len(), &[]));
            }
        }
        if end != End::Missing {
            shreds.last_mut().unwrap().flags |= FLAG_DATA_COMPLETE;
        }
    }
    while !shreds.len().is_multiple_of(per_set) {
        shreds.push(shred(shreds.len(), &[]));
    }
    shreds
}

fn trim(shred: &mut DataShred) {
    let zeros = shred.body.iter().rev().take_while(|b| **b == 0).count();
    shred.body.truncate(shred.body.len() - zeros);
}

impl World {
    /// Builds an oracle with or without fast leader handover, the two
    /// parent blocks every case builds on, and a client trusting the test
    /// validators.
    pub fn new(handover: bool) -> Self {
        let oracle = Oracle::new(OracleConfig {
            fast_leader_handover: handover,
            ..OracleConfig::default()
        });
        assert_eq!(oracle.fast_leader_handover(), handover);
        let validators = TestValidators::new(VALIDATORS, |_| VALIDATOR_STAKE);
        let mut client = ThinClient::new(ClusterParams {
            shred_version: oracle.config().shred_version,
            slots_per_epoch: oracle.config().slots_per_epoch,
            first_normal_slot: 0,
            first_normal_epoch: 0,
        });
        for epoch in 0..4 {
            let set = validators.set();
            let hash = set.hash();
            client
                .trust_validator_set(epoch, set, &hash)
                .expect("the set hashes to its own hash");
        }
        let world = Self {
            oracle,
            validators,
            client,
            handover,
        };
        for (slot, parent) in [(PARENT_SLOT, 0), (SIDE_SLOT, PARENT_SLOT)] {
            let recipe = Recipe {
                slot,
                seed: 0xba5e + slot,
                items: vec![
                    Item::Header(Par::Bank(parent)),
                    Item::Batch(vec![vec![Tx::Transfer]]),
                    Item::Footer,
                    Item::Tick,
                ],
                layout: Layout::default(),
            };
            let (realised, _) = world.settle(&recipe);
            let verdict = world.oracle.judge(slot, &realised.payloads);
            assert!(
                verdict.voted,
                "parent block {slot} did not vote:\n{verdict}"
            );
        }
        world
    }

    /// The block a [`Par`] names.
    pub fn par(&self, parent: Par) -> BlockRef {
        match parent {
            Par::Bank(slot) => self.oracle.block_ref(slot),
            Par::Fake(slot, byte) => BlockRef {
                slot,
                id: [byte; 32],
            },
        }
    }

    /// The component bytes of a recipe, with `bank_hash` in its footers.
    pub fn components(&self, recipe: &Recipe, bank_hash: Hash) -> Vec<Vec<u8>> {
        let oracle = &self.oracle;
        let start = recipe.header_parent().slot();
        let mut parent_slot = start;
        let mut blockhash = oracle.last_blockhash(start);
        let mut chain = blockhash;
        let mut counter = 0u64;
        let mut previous: Option<VersionedTransaction> = None;
        let mut components: Vec<Vec<u8>> = Vec::new();
        // Offset of the last entry's transaction count in the last batch.
        let mut last_count_at = 0usize;

        let mut make = |kind: Tx,
                        blockhash: Hash,
                        previous: &mut Option<VersionedTransaction>|
         -> VersionedTransaction {
            counter += 1;
            let seed = [
                recipe.slot.to_le_bytes(),
                recipe.seed.to_le_bytes(),
                counter.to_le_bytes(),
            ]
            .concat();
            let lamports = 1_000_000 + counter;
            let tx = match kind {
                Tx::Transfer => oracle.transfer(&seed, lamports, blockhash),
                Tx::Failing => oracle.transfer(&seed, u64::MAX, blockhash),
                Tx::BadSignature => {
                    let mut tx = oracle.transfer(&seed, lamports, blockhash);
                    let mut signature: [u8; 64] = tx.signatures[0].into();
                    signature[5] ^= 1;
                    tx.signatures[0] = signature.into();
                    tx
                }
                Tx::UnknownBlockhash => {
                    oracle.transfer(&seed, lamports, Hash::new_from_array([9; 32]))
                }
                Tx::Duplicate => match previous.clone() {
                    Some(tx) => tx,
                    None => oracle.transfer(&seed, lamports, blockhash),
                },
                Tx::Embedding => {
                    let inner_seed = [&seed[..], b"inner"].concat();
                    let inner = oracle.transfer(&inner_seed, lamports, blockhash);
                    oracle.transfer_with_data(&seed, lamports, &wire(&inner), blockhash)
                }
            };
            *previous = Some(tx.clone());
            tx
        };

        for item in &recipe.items {
            match item {
                Item::Header(parent) => {
                    components.push(Oracle::header_bytes(&self.par(*parent)));
                }
                Item::Switch(parent) => {
                    components.push(Oracle::update_parent_bytes(&self.par(*parent)));
                    parent_slot = parent.slot();
                    blockhash = oracle.last_blockhash(parent_slot);
                    chain = blockhash;
                }
                Item::Batch(entries) => {
                    let entries: Vec<Entry> = entries
                        .iter()
                        .map(|txs| {
                            let txs = txs
                                .iter()
                                .map(|kind| make(*kind, blockhash, &mut previous))
                                .collect();
                            Oracle::entry(&mut chain, txs)
                        })
                        .collect();
                    let (bytes, count_at) = batch_bytes(&entries);
                    last_count_at = count_at;
                    components.push(bytes);
                }
                Item::Tick => {
                    let entry = Oracle::entry(&mut chain, vec![]);
                    let (bytes, count_at) = batch_bytes(&[entry]);
                    last_count_at = count_at;
                    components.push(bytes);
                }
                Item::Footer => components.push(Oracle::footer_bytes(
                    bank_hash,
                    oracle.footer_time(parent_slot, recipe.slot),
                )),
                Item::DecoyFooter => components.push(Oracle::footer_bytes(
                    Hash::new_from_array([0xdf; 32]),
                    oracle.footer_time(parent_slot, recipe.slot),
                )),
                Item::Raw(bytes) => components.push(bytes.clone()),
                Item::Trail(trailer) => {
                    let extra = match trailer {
                        Trailer::Zeros(n) => vec![0; *n],
                        Trailer::Bytes(bytes) => bytes.clone(),
                        Trailer::Header(parent) => Oracle::header_bytes(&self.par(*parent)),
                        Trailer::UpdateParent(parent) => {
                            Oracle::update_parent_bytes(&self.par(*parent))
                        }
                        Trailer::Footer => Oracle::footer_bytes(
                            bank_hash,
                            oracle.footer_time(parent_slot, recipe.slot),
                        ),
                        Trailer::Entry(txs) => {
                            let txs = txs
                                .iter()
                                .map(|kind| make(*kind, blockhash, &mut previous))
                                .collect();
                            let entry = Oracle::entry(&mut chain.clone(), txs);
                            let mut bytes = Vec::new();
                            entry_bytes(&mut bytes, &entry, &mut 0);
                            bytes
                        }
                        Trailer::Transaction(kind) => wire(&make(*kind, blockhash, &mut previous)),
                    };
                    components
                        .last_mut()
                        .expect("a trailer follows a component")
                        .extend_from_slice(&extra);
                }
                Item::EntryCount(delta) => {
                    add_u64_at(components.last_mut().expect("a component"), 0, *delta);
                }
                Item::TxCount(delta) => {
                    add_u64_at(
                        components.last_mut().expect("a component"),
                        last_count_at,
                        *delta,
                    );
                }
                Item::Truncate(n) => {
                    let last = components.last_mut().expect("a component");
                    last.truncate(last.len().saturating_sub(*n));
                }
            }
        }
        components
    }

    /// The shreds a recipe is cut into, before edits and signing. Their
    /// number and sizes do not depend on the bank hash, so a generator can
    /// look at them to choose which shred to edit.
    pub fn shape(&self, recipe: &Recipe) -> Vec<DataShred> {
        let components = self.components(recipe, Hash::default());
        let offset = recipe.slot - recipe.header_parent().slot();
        cut(&components, &recipe.layout, offset as u16)
    }

    /// Builds a recipe's shreds with `bank_hash` in its footers, and signs
    /// them.
    pub fn realise(&self, recipe: &Recipe, bank_hash: Hash) -> Realised {
        let components = self.components(recipe, bank_hash);
        let builder_parent = self.par(recipe.header_parent());
        let offset = (recipe.slot - builder_parent.slot) as u16;
        let mut wanted = cut(&components, &recipe.layout, offset);
        // The last shred of a block is flagged last in slot unless an edit
        // says otherwise.
        wanted.last_mut().expect("at least one shred").flags |= FLAG_LAST_IN_SLOT;
        let count = wanted.len();
        for edit in &recipe.layout.edits {
            let at = |index: &u32| (*index as usize).min(count - 1);
            match edit {
                Edit::OrFlags(index, flags) => wanted[at(index)].flags |= flags,
                Edit::SetFlags(index, flags) => wanted[at(index)].flags = *flags,
                Edit::ParentOffset(index, offset) => wanted[at(index)].parent_offset = *offset,
                Edit::Size(index, size) => wanted[at(index)].size = *size,
                Edit::Padding(index, padding) => {
                    let shred = &mut wanted[at(index)];
                    let capacity = body_capacity(shred.variant).expect("data variant");
                    let data = usize::from(shred.size).saturating_sub(DATA_HEADERS_SIZE);
                    shred.body.resize(data.min(capacity), 0);
                    let room = capacity - shred.body.len();
                    shred
                        .body
                        .extend_from_slice(&padding[..padding.len().min(room)]);
                }
            }
        }
        // What `BlockBuilder` can write: a size in bounds, a body within
        // capacity. Anything else is patched into the payload afterwards.
        let mut buildable = wanted.clone();
        for shred in &mut buildable {
            let capacity = body_capacity(shred.variant).expect("data variant");
            shred.size = shred.size.clamp(
                DATA_HEADERS_SIZE as u16,
                (DATA_HEADERS_SIZE + capacity) as u16,
            );
            shred.body.truncate(capacity);
            trim(shred);
        }
        let mut payloads = BlockBuilder::new(
            recipe.slot,
            builder_parent,
            self.oracle.config().shred_version,
        )
        .push_shreds(buildable.clone())
        .build();
        let mut patched = false;
        for (payload, want) in payloads.iter_mut().zip(&wanted) {
            if payload[85] != want.flags {
                payload[85] = want.flags;
                patched = true;
            }
            if payload[86..88] != want.size.to_le_bytes() {
                payload[86..88].copy_from_slice(&want.size.to_le_bytes());
                patched = true;
            }
        }
        if patched {
            reseal(&mut payloads);
        }
        self.oracle.sign(&mut payloads);
        Realised {
            components,
            payloads,
            shreds: (!patched).then_some(buildable),
            builder_parent,
        }
    }

    /// Builds a recipe with its footer's bank hash settled: a first pass
    /// with a placeholder, and if replay gets as far as comparing bank
    /// hashes, a second with the hash Agave computed. Returns the block and
    /// whether a hash was settled.
    pub fn settle(&self, recipe: &Recipe) -> (Realised, bool) {
        let first = self.realise(recipe, Hash::default());
        match self.oracle.judge(recipe.slot, &first.payloads).replay {
            Replay::Failed {
                bank_hash_mismatch: Some((_, computed)),
                ..
            } => (self.realise(recipe, computed), true),
            _ => (first, false),
        }
    }

    /// Runs one case: builds it, takes Agave's verdict in three arrival
    /// orders, offers every claim to the verifier, and checks the
    /// properties.
    pub fn run(&self, case: &Case) -> Outcome {
        let recipe = &case.recipe;
        let slot = recipe.slot;
        let (realised, settled) = self.settle(recipe);
        let payloads = &realised.payloads;
        let mut violations = Vec::new();

        // Agave, three arrival orders.
        let forward = self.oracle.judge(slot, payloads);
        let mut reversed = payloads.clone();
        reversed.reverse();
        let mut shuffled = payloads.clone();
        let mut rng = Rng::new(recipe.seed ^ 0x5bd1_e995);
        for i in (1..shuffled.len()).rev() {
            shuffled.swap(i, rng.below(i + 1));
        }
        let others = [
            ("reversed", self.oracle.judge(slot, &reversed)),
            (
                "shuffled, one shred per insert",
                self.oracle.judge_with(
                    slot,
                    &shuffled,
                    &JudgeOptions {
                        replay: true,
                        batch: Some(1),
                    },
                ),
            ),
        ];
        let voted = forward.voted || others.iter().any(|(_, v)| v.voted);
        let mut meta_moved = false;
        for (order, other) in &others {
            if other.order_independent() == forward.order_independent() {
                continue;
            }
            if voted {
                let zero_parent_marker = |v: &Verdict| {
                    v.meta.as_ref().is_some_and(|m| {
                        m.has_update_parent
                            && m.parent_slot == Some(0)
                            && m.parent_block_id == Hash::default()
                    })
                };
                let known = zero_parent_marker(&forward) || zero_parent_marker(other);
                violations.push(Violation {
                    property: if known { UPSTREAM_ORDER } else { "P0" },
                    detail: format!(
                        "verdict depends on arrival order: forward voted={} dead={} replay={:?} \
                         meta={:?}; {order} voted={} dead={} replay={:?} meta={:?}",
                        forward.voted,
                        forward.dead,
                        forward.replay,
                        forward.meta,
                        other.voted,
                        other.dead,
                        other.replay,
                        other.meta,
                    ),
                });
            } else {
                meta_moved = true;
            }
        }
        if forward.voted && forward.executed.is_none() {
            violations.push(Violation {
                property: "oracle",
                detail: format!(
                    "voted, but replay's component view ({} transactions) and the status drain \
                     ({}) disagree",
                    forward.view.len(),
                    forward.statuses.len()
                ),
            });
        }

        // The light client's reading of the same shreds. Counted over the
        // shreds as given; checked over the shreds Agave's blockstore kept,
        // which is the block a certificate would be for.
        let raw_error = RawBlock::from_shreds(payloads).err();
        let raw_error = raw_error.map(|e| format!("{e:?}"));
        let enumerated = RawBlock::from_shreds(payloads)
            .map(|raw| enumerate(&raw).len())
            .unwrap_or(0);
        let mut claims = Vec::new();
        let mut coverage = BTreeMap::new();
        // Every verdict with a block id is a truth the light client is held
        // to. They are one verdict unless P0 failed above.
        let mut truths: Vec<&Verdict> = Vec::new();
        for verdict in std::iter::once(&forward).chain(others.iter().map(|(_, v)| v)) {
            let known = truths
                .iter()
                .any(|t| t.order_independent() == verdict.order_independent());
            if !known && verdict.block_id.is_some() {
                truths.push(verdict);
            }
        }
        for truth in truths {
            match RawBlock::from_shreds(&truth.stored) {
                Ok(raw) => {
                    self.check_identity(&raw, truth, &mut violations);
                    if truth.voted {
                        let record = claims.is_empty();
                        let candidates = enumerate(&raw);
                        self.check_claims(
                            &raw,
                            truth,
                            &candidates,
                            &mut claims,
                            &mut violations,
                            record,
                        );
                    }
                }
                // Agave has a block the light client's shred parser refuses.
                // No claim can be made about it, so this is a refusal, not a
                // soundness failure; it is recorded under coverage.
                Err(error) => {
                    *coverage
                        .entry(format!("shreds refused by the light client: {error:?}"))
                        .or_insert(0) += truth.view.len().max(1);
                }
            }
        }
        if forward.voted {
            for (reason, n) in self.coverage(&forward.stored, &forward) {
                *coverage.entry(reason).or_insert(0) += n;
            }
        }
        let stored_all = forward.stored.len() == payloads.len();

        // What the case says Agave must do.
        let expect = match (case.needs_handover && !self.handover, &case.expect) {
            (true, Expect::Report) => Expect::Report,
            (true, _) => Expect::NotVoted,
            (false, expect) => expect.clone(),
        };
        if case.needs_handover && !self.handover && voted {
            violations.push(Violation {
                property: "premise",
                detail: "an UpdateParent block voted with fast leader handover off".into(),
            });
        }
        if let Err(detail) = check_expectation(&expect, &forward) {
            violations.push(Violation {
                property: "premise",
                detail,
            });
        }

        Outcome {
            case: case.clone(),
            handover: self.handover,
            realised,
            settled,
            verdict: forward,
            voted,
            raw_error,
            enumerated,
            claims,
            violations,
            meta_moved,
            stored_all,
            coverage,
        }
    }

    /// P2: under the parent in Agave's `SlotMeta`, the light client's block
    /// id is Agave's; under any other parent a marker in the block names,
    /// and under an all-zero parent, it is not.
    fn check_identity(&self, raw: &RawBlock, truth: &Verdict, violations: &mut Vec<Violation>) {
        let (Some(block_id), Some(parent)) = (truth.block_id, truth.parent()) else {
            return;
        };
        let ours = raw.block(&parent);
        if ours.id != block_id.to_bytes() {
            violations.push(Violation {
                property: "P2",
                detail: format!(
                    "block id under SlotMeta's parent ({}, {}): light client {}, Agave {}",
                    parent.slot,
                    hex(parent.id),
                    hex(ours.id),
                    hex(block_id),
                ),
            });
        }
        let mut alternatives = vec![BlockRef {
            slot: parent.slot,
            id: [0; 32],
        }];
        let mut markers = vec![raw.shred_data(0)];
        markers.extend(
            raw.component_starts()
                .into_iter()
                .map(|s| raw.component(s).0),
        );
        for bytes in markers {
            if let Ok(Marker::Header { parent } | Marker::UpdateParent { parent }) =
                block::parse_marker(&bytes)
            {
                alternatives.push(parent);
            }
        }
        for alternative in alternatives {
            if alternative != parent && raw.block(&alternative).id == block_id.to_bytes() {
                violations.push(Violation {
                    property: "P2",
                    detail: format!(
                        "block id under another parent ({}, {}) equals Agave's",
                        alternative.slot,
                        hex(alternative.id)
                    ),
                });
            }
        }
    }

    /// P1: offers every candidate claim, committed to Agave's parent and
    /// certified at Agave's block id, and holds each accepted one to what
    /// Agave executed.
    ///
    /// Each claim is offered twice: with the fewest shreds that show it, and
    /// with every shred of the block opened. A prover chooses what to open,
    /// and the verifier reads more of the block the more it is given (the
    /// header's second shred, say), so the fullest opening is the one most
    /// likely to be accepted; the smallest is what an honest prover sends.
    fn check_claims(
        &self,
        raw: &RawBlock,
        truth: &Verdict,
        candidates: &[Candidate],
        claims: &mut Vec<ClaimRecord>,
        violations: &mut Vec<Violation>,
        record: bool,
    ) {
        let (Some(block_id), Some(parent)) = (truth.block_id, truth.parent()) else {
            return;
        };
        let block = raw.block(&parent);
        if block.id != block_id.to_bytes() {
            // P2 already failed. No certificate exists for the id the light
            // client computes, so there is nothing to claim.
            return;
        }
        let executed = truth.executed.clone().unwrap_or_default();
        let version = self.oracle.config().shred_version;
        let certificate =
            self.validators
                .fast_cert(block, &self.validators.ranks_reaching(8_000), version);
        let everything: BTreeSet<u32> = (0..raw.shred_count()).collect();
        let offer = |needed: &BTreeSet<u32>, candidate: &Candidate, footer: Option<u32>| {
            let proof = TxProof {
                finality: certificate.clone(),
                ancestry: vec![],
                block: raw.open(&parent, needed),
                component_start: candidate.component_start,
                position: candidate.position,
                footer_start: footer,
            };
            let bytes = proof.to_bytes();
            (self.client.verify_transaction_bytes(&bytes), bytes)
        };

        let mut first_accepted: Option<&Candidate> = None;
        for candidate in candidates {
            let coordinate = executed.iter().find(|tx| {
                tx.component_start == candidate.component_start
                    && tx.entry == candidate.position.entry as usize
                    && tx.tx == candidate.position.transaction as usize
            });
            let claim = format!(
                "claim (component_start {}, entry {}, transaction {}) signature {}",
                candidate.component_start,
                candidate.position.entry,
                candidate.position.transaction,
                hex(&candidate.transaction.signature()[..8]),
            );
            let (minimal, bytes) = offer(&candidate.needed, candidate, None);
            let (full, _) = offer(&everything, candidate, None);
            let accepted: Vec<(&str, &solana_thin::VerifiedTransaction)> =
                [("fewest shreds", &minimal), ("every shred", &full)]
                    .into_iter()
                    .filter_map(|(opening, result)| Some((opening, result.as_ref().ok()?)))
                    .collect();
            let openings: Vec<&str> = accepted.iter().map(|(opening, _)| *opening).collect();
            let openings = openings.join(" and ");
            if !accepted.is_empty() {
                first_accepted.get_or_insert(candidate);
            }
            match coordinate {
                None if !accepted.is_empty() => violations.push(Violation {
                    property: "P1",
                    detail: format!(
                        "SOUNDNESS: verifier accepted {claim} (opening: {openings}); Agave voted \
                         for block {} and executed no transaction at those coordinates (replay \
                         started at shred {}, executed {})",
                        hex(block_id),
                        truth.replay_start,
                        executed.len(),
                    ),
                }),
                Some(tx) => {
                    let agave = ThinTransaction::parse(&tx.wire).ok();
                    if accepted
                        .iter()
                        .any(|(_, verified)| agave.as_ref() != Some(&verified.transaction))
                    {
                        violations.push(Violation {
                            property: "P1",
                            detail: format!(
                                "SOUNDNESS: verifier accepted {claim} (opening: {openings}); \
                                 Agave executed other bytes there (signature {})",
                                hex(&tx.signature[..8])
                            ),
                        });
                    }
                }
                None => {}
            }
            if accepted
                .iter()
                .any(|(_, verified)| verified.block != block || verified.parent != parent)
            {
                violations.push(Violation {
                    property: "P1",
                    detail: format!(
                        "verifier accepted {claim} (opening: {openings}) but reports another \
                         block or parent than Agave's"
                    ),
                });
            }
            drop(accepted);
            if minimal.is_ok() && full.is_err() {
                violations.push(Violation {
                    property: "opening",
                    detail: format!(
                        "verifier accepted {claim} from the fewest shreds and refused it with \
                         every shred opened: {:?}",
                        full.as_ref().err()
                    ),
                });
            }
            if record {
                let text = |r: Result<solana_thin::VerifiedTransaction, solana_thin::Error>| {
                    r.map(|_| ()).map_err(|e| format!("{e:?}"))
                };
                claims.push(ClaimRecord {
                    component_start: candidate.component_start,
                    entry: candidate.position.entry,
                    transaction: candidate.position.transaction,
                    footer_start: None,
                    observed: text(minimal),
                    observed_full: text(full),
                    executed: coordinate.is_some(),
                    proof: bytes,
                });
            }
        }

        // Footer claims ride on one accepted transaction claim: every
        // component that parses as a footer is offered as the footer.
        let Some(base) = first_accepted else {
            return;
        };
        for start in raw.component_starts() {
            let (bytes, last) = raw.component(start);
            let Ok(Marker::Footer(_)) = block::parse_marker(&bytes) else {
                continue;
            };
            let mut needed = base.needed.clone();
            if start > 0 {
                needed.insert(start - 1);
            }
            needed.extend(start..=last);
            let agave = truth.footers.iter().find(|f| f.component_start == start);
            let (minimal, bytes) = offer(&needed, base, Some(start));
            let (full, _) = offer(&everything, base, Some(start));
            for result in [&minimal, &full] {
                let Ok(verified) = result else {
                    continue;
                };
                let ours = verified.footer.as_ref();
                let same = match (ours, agave) {
                    (Some(ours), Some(agave)) => {
                        ours.bank_hash == agave.bank_hash.to_bytes()
                            && ours.producer_time_nanos == agave.producer_time_nanos
                            && Some(agave.bank_hash) == truth.bank_hash
                    }
                    _ => false,
                };
                if !same {
                    violations.push(Violation {
                        property: "P1",
                        detail: format!(
                            "SOUNDNESS: verifier accepted a footer at component_start {start} \
                             (bank hash {:?}); Agave's footers in the replayed part: {:?}",
                            ours.map(|f| hex(f.bank_hash)),
                            truth.footers,
                        ),
                    });
                    break;
                }
            }
            if record {
                let text = |r: Result<solana_thin::VerifiedTransaction, solana_thin::Error>| {
                    r.map(|_| ()).map_err(|e| format!("{e:?}"))
                };
                claims.push(ClaimRecord {
                    component_start: base.component_start,
                    entry: base.position.entry,
                    transaction: base.position.transaction,
                    footer_start: Some(start),
                    observed: text(minimal),
                    observed_full: text(full),
                    executed: agave.is_some(),
                    proof: bytes,
                });
            }
        }
    }

    /// P3: for each transaction Agave executed, whether the honest prover
    /// proves it and the verifier accepts, or why not.
    fn coverage(&self, payloads: &[Vec<u8>], truth: &Verdict) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        let executed = truth.executed.clone().unwrap_or_default();
        let mut add = |reason: String, n: usize| {
            if n > 0 {
                *out.entry(reason).or_insert(0) += n;
            }
        };
        let data = match BlockData::from_shreds(payloads) {
            Ok(data) => data,
            Err(error) => {
                add(
                    format!("prover refuses the block: {error:?}"),
                    executed.len(),
                );
                return out;
            }
        };
        if Some(data.block().id) != truth.block_id.map(|id| id.to_bytes()) {
            add(
                "prover computes another block id (no certificate exists for it)".into(),
                executed.len(),
            );
            return out;
        }
        let version = self.oracle.config().shred_version;
        let certificate = self.validators.fast_cert(
            data.block(),
            &self.validators.ranks_reaching(8_000),
            version,
        );
        for tx in &executed {
            let reason = match prover::prove(certificate.clone(), &[&data], &tx.signature, true) {
                Err(error) => format!("prover cannot prove the transaction: {error:?}"),
                Ok(proof) => match self.client.verify_transaction_bytes(&proof.to_bytes()) {
                    Err(error) => format!("verifier rejects the honest proof: {error:?}"),
                    Ok(verified) => {
                        let same = verified.component_start == tx.component_start
                            && verified.position.entry as usize == tx.entry
                            && verified.position.transaction as usize == tx.tx;
                        match same {
                            true => "proved and accepted".to_string(),
                            false => "proved at another coordinate with the same signature".into(),
                        }
                    }
                },
            };
            add(reason, 1);
        }
        out
    }
}

/// A claim a proof could make: a transaction the verifier's own walk reaches
/// from some shred, and the fewest shreds that show it.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Shred the walk starts at.
    pub component_start: u32,
    /// Where the walk found the transaction.
    pub position: TxPosition,
    /// The transaction as the light client parsed it.
    pub transaction: ThinTransaction,
    /// Shred 0, the shred before the start, and the start through the shred
    /// holding the transaction's last byte.
    pub needed: BTreeSet<u32>,
}

/// Every claim a proof could make about a block. Starts are not limited to
/// real component boundaries: the verifier is the one that has to refuse a
/// start that follows no `DATA_COMPLETE`.
pub fn enumerate(raw: &RawBlock) -> Vec<Candidate> {
    let mut out = Vec::new();
    for start in 0..raw.shred_count() {
        let (bytes, last) = raw.component(start);
        let reached = block::reachable(&bytes);
        if reached.is_empty() {
            continue;
        }
        let lens: Vec<usize> = (start..=last).map(|i| raw.shred_data(i).len()).collect();
        for (position, transaction, end) in reached {
            let mut seen = 0;
            let mut holder = last;
            for (i, len) in lens.iter().enumerate() {
                seen += len;
                if seen >= end {
                    holder = start + i as u32;
                    break;
                }
            }
            let mut needed = BTreeSet::from([0]);
            if start > 0 {
                needed.insert(start - 1);
            }
            needed.extend(start..=holder);
            out.push(Candidate {
                component_start: start,
                position,
                transaction,
                needed,
            });
        }
    }
    out
}

fn check_expectation(expect: &Expect, verdict: &Verdict) -> Result<(), String> {
    let executed = verdict.executed.clone().unwrap_or_default();
    let fail = |what: &str| {
        Err(format!(
            "expected {what}; Agave: voted={} replay={:?} from shred {} executed {}",
            verdict.voted,
            verdict.replay,
            verdict.replay_start,
            executed.len(),
        ))
    };
    match expect {
        Expect::Report => Ok(()),
        Expect::Voted if verdict.voted => Ok(()),
        Expect::Voted => fail("a vote"),
        Expect::NotVoted if !verdict.voted => Ok(()),
        Expect::NotVoted => fail("no vote"),
        Expect::VotedExecuting {
            executed: count,
            replay_start,
            first_component,
        } => {
            let first = executed.first().map(|tx| tx.component_start);
            if verdict.voted
                && executed.len() == *count
                && verdict.replay_start == *replay_start
                && first.is_none_or(|start| start == *first_component)
            {
                Ok(())
            } else {
                fail(&format!(
                    "a vote executing {count} transactions from shred {replay_start}, the first \
                     in the component at {first_component} (it is at {first:?})"
                ))
            }
        }
        Expect::VotedWithFailure => {
            if verdict.voted && executed.iter().any(|tx| matches!(tx.commit, Ok(Err(_)))) {
                Ok(())
            } else {
                fail("a vote with a transaction committed as failed")
            }
        }
        Expect::DroppedShred(index) => {
            let dropped = verdict
                .shreds
                .get(*index as usize)
                .is_some_and(|s| !s.accepted());
            let full = verdict.meta.as_ref().is_some_and(|m| m.full);
            if dropped && !full && !verdict.voted {
                Ok(())
            } else {
                Err(format!(
                    "expected shred {index} dropped and the slot never full; dropped={dropped} \
                     ({:?}) full={full} voted={}",
                    verdict.shreds.get(*index as usize),
                    verdict.voted
                ))
            }
        }
    }
}

/// The frozen form of an outcome, for the main workspace's tests: the
/// shreds, Agave's verdict, and the claims with what the verifier did and
/// what it must do. `max_proofs` bounds how many encoded proofs are kept;
/// the shreds are enough to rebuild every claim.
pub fn freeze(outcome: &Outcome, world: &World, max_proofs: usize) -> serde_json::Value {
    use serde_json::json;
    let verdict = &outcome.verdict;
    let block = |b: &BlockRef| json!({ "slot": b.slot, "id": hex(b.id) });
    // The frozen shreds are for rebuilding the block Agave judged. If the
    // blockstore kept only some of them, that is not this block.
    let kept = outcome
        .realised
        .shreds
        .as_ref()
        .filter(|_| outcome.stored_all);
    // Most shreds of a block are identical empty padding, so runs of equal
    // shreds are written once with a count: `[hex, count]`.
    let shreds = kept.map(|shreds| {
        let mut runs: Vec<(String, usize)> = Vec::new();
        for s in shreds {
            let mut bytes = vec![s.variant];
            bytes.extend_from_slice(&s.parent_offset.to_le_bytes());
            bytes.push(s.flags);
            bytes.extend_from_slice(&s.size.to_le_bytes());
            bytes.extend_from_slice(&s.body);
            let text = hex(bytes);
            match runs.last_mut() {
                Some((last, count)) if *last == text => *count += 1,
                _ => runs.push((text, 1)),
            }
        }
        runs.into_iter()
            .map(|(text, count)| match count {
                1 => json!(text),
                _ => json!([text, count]),
            })
            .collect::<Vec<_>>()
    });
    let executed: Vec<_> = verdict
        .executed
        .iter()
        .flatten()
        .filter(|_| verdict.voted)
        .map(|tx| {
            json!({
                "component_start": tx.component_start,
                "entry": tx.entry,
                "transaction": tx.tx,
                "wire": hex(&tx.wire),
                "committed_ok": tx.commit == Ok(Ok(())),
            })
        })
        .collect();
    // Keep the proofs worth keeping first: accepted against the rule, then
    // accepted, then one rejected.
    let mut order: Vec<usize> = (0..outcome.claims.len()).collect();
    order.sort_by_key(|i| {
        let claim = &outcome.claims[*i];
        match (
            claim.observed.is_ok() || claim.observed_full.is_ok(),
            claim.executed,
        ) {
            (true, false) => 0,
            (true, true) => 1,
            (false, _) => 2,
        }
    });
    let keep: BTreeSet<usize> = order.into_iter().take(max_proofs).collect();
    let claims: Vec<_> = outcome
        .claims
        .iter()
        .enumerate()
        .map(|(i, claim)| {
            json!({
                "component_start": claim.component_start,
                "entry": claim.entry,
                "transaction": claim.transaction,
                "footer_start": claim.footer_start,
                "observed": match &claim.observed {
                    Ok(()) => "accept".to_string(),
                    Err(error) => format!("reject: {error}"),
                },
                "observed_full_opening": match &claim.observed_full {
                    Ok(()) => "accept".to_string(),
                    Err(error) => format!("reject: {error}"),
                },
                "required": if claim.executed { "may-accept" } else { "must-reject" },
                "proof": keep.contains(&i).then(|| hex(&claim.proof)),
            })
        })
        .collect();
    json!({
        "name": outcome.case.name,
        "agave": "v4.4.1",
        "fast_leader_handover": outcome.handover,
        "recipe": format!("{:?}", outcome.case.recipe.items),
        "shred_version": world.oracle.config().shred_version,
        "slots_per_epoch": world.oracle.config().slots_per_epoch,
        "slot": verdict.slot,
        "builder_parent": block(&outcome.realised.builder_parent),
        "shreds": shreds,
        "parent": verdict.parent().as_ref().map(block),
        "block_id": verdict.block_id.map(hex),
        "voted": verdict.voted,
        "replay": format!("{:?}", verdict.replay),
        "replay_start": verdict.replay_start,
        "executed": executed,
        "footer": verdict.footers.first().filter(|_| verdict.voted).map(|f| json!({
            "component_start": f.component_start,
            "bank_hash": hex(f.bank_hash),
            "producer_time_nanos": f.producer_time_nanos,
        })),
        "validators": { "count": VALIDATORS, "stake": VALIDATOR_STAKE },
        "validator_set": hex(world.validators.set().to_bytes()),
        "claims": claims,
    })
}
