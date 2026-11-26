//! A differential oracle: what would a validator do with these shreds?
//!
//! The oracle owns one Alpenglow chain (genesis, bank forks, blockstore) and
//! answers for any set of shred payloads of one slot, data and coding, using
//! Agave's own code for every step that has an opinion:
//!
//! * the fetch-stage filter (`ShredFilterContext::should_discard_shred`),
//! * leader signature verification (`sigverify_shreds::verify_shred_cpu`),
//! * parsing (`Shred::new_from_serialized_shred`),
//! * insertion with duplicate handling and erasure recovery
//!   (`Blockstore::insert_shreds_handle_duplicate`, `is_trusted = false`),
//! * replay (`blockstore_processor::process_single_slot`) behind the
//!   replay-stage rules for choosing a parent and a starting shred.
//!
//! Nothing here decides validity itself. Two pieces of Agave are copied
//! rather than called, because they are private to `solana-core`:
//! [`replay_start`] is `core/src/replay_stage/update_parent.rs`
//! `child_bank_replay_start`, and the duplicate handler in [`Oracle::judge`]
//! is the closure in `core/src/window_service.rs` `run_check_duplicate`.
//!
//! Blocks are cut into shreds by `solana_thin::testkit::BlockBuilder`, not by
//! Agave's `Shredder`, so that layouts a real leader would never produce can
//! be judged. The oracle signs them as the slot leader.
//!
//! The testkit's Merkle trees have filler hashes where the coding shreds'
//! leaves go, so no coding shred can belong to them. [`erasure_code`] makes
//! the real coding shreds for such a block and rebuilds its trees over them,
//! which is what lets a slot be judged from part of its data shreds plus
//! parity: the blockstore reconstructs the rest
//! (`ShredRecoveryContext::recover`) on its own.

use {
    agave_votor_messages::migration::MigrationStatus,
    crossbeam_channel::Receiver,
    reed_solomon_erasure::galois_8::ReedSolomon,
    solana_entry::{
        block_component::{
            BlockComponent, BlockFooterV1, ParsedBlockComponent, UpdateParentV1,
            VersionedBlockFooter, VersionedBlockMarker,
        },
        entry::{Entry, next_versioned_entry},
    },
    solana_epoch_schedule::EpochSchedule,
    solana_hash::Hash,
    solana_keypair::{Keypair, keypair_from_seed},
    solana_ledger::{
        blockstore::{
            Blockstore, BlockstoreInsertionMetrics, PossibleDuplicateShred, PurgeType,
            handle_duplicate_shred,
        },
        blockstore_meta::{BlockLocation, SlotMeta},
        blockstore_processor::{
            self, BlockstoreProcessorError, ConfirmationProgress, ProcessOptions,
            ReplayVerificationWorkerPool,
        },
        leader_schedule_cache::LeaderScheduleCache,
        shred::{
            ProcessShredsStats, ReedSolomonCache, Shred, Shredder,
            filter::{
                ShredFilterContext, ShredRecoveryContext, check_feature_activation_from_bank,
            },
            wire,
        },
        sigverify_shreds::{LruCache, SlotPubkeys, verify_shred_cpu},
    },
    solana_message::Message,
    solana_perf::packet::Packet,
    solana_pubkey::Pubkey,
    solana_runtime::{
        bank::Bank,
        bank_forks::BankForks,
        block_component_processor::BlockComponentProcessor,
        genesis_utils::{
            GenesisConfigInfo, ValidatorVoteKeypairs,
            create_genesis_config_with_alpenglow_vote_accounts,
        },
        transaction_execution::{TransactionStatusMessage, TransactionStatusSender},
    },
    solana_sha256_hasher::hashv,
    solana_signer::Signer,
    solana_streamer::evicting_sender::EvictingSender,
    solana_svm_timings::ExecuteTimings,
    solana_system_interface::instruction as system_instruction,
    solana_thin::{
        BlockRef, merkle,
        shred::{DATA_HEADERS_SIZE, DATA_SHRED_SIZE, VARIANT_DATA, body_capacity},
        testkit::BlockBuilder,
    },
    solana_transaction::{Transaction, versioned::VersionedTransaction},
    solana_unified_scheduler_pool::DefaultSchedulerPool,
    std::{
        borrow::Cow,
        cell::RefCell,
        collections::HashMap,
        fmt,
        sync::{Arc, RwLock},
        time::{Duration, Instant},
    },
    tempfile::TempDir,
};

/// Data shreds per FEC set.
pub const FEC_SET: u32 = 32;
/// Coding shreds per FEC set: Agave's erasure batch is fixed at 32 and 32.
pub const CODING_PER_SET: u32 = 32;
/// Bytes in a coding shred on the wire.
pub const CODING_SHRED_SIZE: usize = 1228;
/// Signature, common header and coding header.
const CODING_HEADERS_SIZE: usize = 89;
/// Variant bytes of a coding shred and of one that carries a retransmitter
/// signature, both with the six proof entries of a 64-leaf tree.
const VARIANT_CODING: u8 = 0x66;
const VARIANT_CODING_RESIGNED: u8 = 0x76;

/// How the oracle's chain is set up.
#[derive(Debug, Clone)]
pub struct OracleConfig {
    /// Shred version every shred must carry.
    pub shred_version: u16,
    /// Genesis creation time, Unix seconds. Fixed so runs are comparable.
    pub creation_time: i64,
    /// Slots per epoch. Shred rules that depend on a feature only apply one
    /// epoch after activation, so test slots belong in epoch 1 or later.
    pub slots_per_epoch: u64,
    /// Lamports in the mint, which pays for every transfer.
    pub mint_lamports: u64,
    /// Stake of the one validator.
    pub stake_lamports: u64,
    /// Threads for PoH and signature verification during replay.
    pub verification_threads: usize,
    /// Whether `alpenglow_fast_leader_handover` is active, which is what
    /// makes UpdateParent markers legal. Every other feature is always on.
    pub fast_leader_handover: bool,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            shred_version: 50093,
            creation_time: 1_792_590_840,
            slots_per_epoch: 32,
            mint_lamports: 1_000_000_000_000_000,
            stake_lamports: 100_000_000_000,
            verification_threads: 2,
            fast_leader_handover: true,
        }
    }
}

/// One Alpenglow chain and the machinery to judge shreds against it.
pub struct Oracle {
    config: OracleConfig,
    mint: Keypair,
    leader: Keypair,
    genesis_hash: Hash,
    blockstore: Arc<Blockstore>,
    bank_forks: Arc<RwLock<BankForks>>,
    migration_status: Arc<MigrationStatus>,
    leader_schedule_cache: LeaderScheduleCache,
    verification_pool: ReplayVerificationWorkerPool,
    process_options: ProcessOptions,
    status_sender: TransactionStatusSender,
    status_receiver: Receiver<TransactionStatusMessage>,
    sigverify_cache: RwLock<LruCache>,
    // Dropped last: the blockstore lives in it.
    _ledger: TempDir,
}

/// What an honest block should contain.
#[derive(Debug, Clone)]
pub struct HonestSpec {
    /// Slot of the block.
    pub slot: u64,
    /// Slot of its parent, which must be a frozen bank the oracle holds.
    pub parent_slot: u64,
    /// Entry batches; each lists its entries; each entry is a number of
    /// transfers from the mint.
    pub batches: Vec<Vec<usize>>,
    /// Bank hash to put in the footer. See [`Oracle::settle_bank_hash`].
    pub bank_hash: Hash,
    /// Makes the transfers of otherwise equal specs distinct.
    pub seed: u64,
    /// If set, the block starts on another parent and switches to
    /// `parent_slot` with an UpdateParent marker.
    pub abandoned: Option<AbandonedPrefix>,
}

/// The part of a block a leader built on a parent it then gave up on.
#[derive(Debug, Clone)]
pub struct AbandonedPrefix {
    /// The parent the header names. It must be a frozen bank the oracle
    /// holds, at a slot no lower than the final parent's, and a different
    /// block.
    pub header_parent_slot: u64,
    /// Entry batches between the header and the UpdateParent marker, in the
    /// shape of [`HonestSpec::batches`]. A validator never executes these.
    pub batches: Vec<Vec<usize>>,
}

/// A transaction as built, with the place it was put.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltTx {
    /// Index of its component in [`HonestBlock::components`].
    pub component: usize,
    /// Entry within the batch.
    pub entry: usize,
    /// Transaction within the entry.
    pub tx: usize,
    /// First signature.
    pub signature: [u8; 64],
    /// The transaction as serialized into the entry.
    pub wire: Vec<u8>,
    /// The account the transfer pays.
    pub recipient: Pubkey,
    /// What it pays. Recipients are fresh, so this is the balance a bank
    /// shows after executing the transfer.
    pub lamports: u64,
    /// Whether it sits before an UpdateParent marker, where a validator
    /// does not execute it.
    pub abandoned: bool,
}

/// An honest block as component bytes, before shredding.
#[derive(Debug, Clone)]
pub struct HonestBlock {
    /// Slot of the block.
    pub slot: u64,
    /// The parent the header names, which is what the shred headers'
    /// parent offset is cut for.
    pub parent: BlockRef,
    /// The parent the block ends up on: `parent` unless the block has an
    /// UpdateParent marker.
    pub final_parent: BlockRef,
    /// Header, entry batches, footer, alpentick, each as wincode bytes;
    /// with a prefix before a parent switch, its batches and the UpdateParent
    /// marker follow the header.
    pub components: Vec<Vec<u8>>,
    /// Every transaction, in block order, abandoned ones included.
    pub transactions: Vec<BuiltTx>,
    /// Index of the UpdateParent marker in `components`, if there is one.
    pub update_parent: Option<usize>,
    /// Index of the footer in `components`.
    pub footer: usize,
    /// The footer's timestamp.
    pub producer_time_nanos: u64,
}

/// What the filter, signature check and parser said about one payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShredOutcome {
    /// `Some(counters)` if `should_discard_shred` returned true: the non-zero
    /// fields of `ShredFetchStats` after this one shred.
    pub discarded: Option<String>,
    /// Counters the filter raised without discarding.
    pub filter_notes: Option<String>,
    /// `verify_shred_cpu` against the slot leader.
    pub signature_ok: bool,
    /// Error from `Shred::new_from_serialized_shred`, if any.
    pub parse_error: Option<String>,
}

impl ShredOutcome {
    /// Whether the shred reached the blockstore.
    pub fn accepted(&self) -> bool {
        self.discarded.is_none() && self.signature_ok && self.parse_error.is_none()
    }
}

/// The fields of `SlotMeta` that consensus reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaView {
    /// Parent slot, from the shred headers or an UpdateParent marker.
    pub parent_slot: Option<u64>,
    /// Parent block id, from the block header or an UpdateParent marker.
    pub parent_block_id: Hash,
    /// Where replay starts; non-zero after an UpdateParent.
    pub replay_fec_set_index: u32,
    /// `SlotMeta::has_update_parent`.
    pub has_update_parent: bool,
    /// `SlotMeta::is_full`.
    pub full: bool,
    /// Consecutive shreds received from index 0.
    pub consumed: u64,
    /// Highest index received plus one.
    pub received: u64,
    /// Index of the shred flagged last in slot.
    pub last_index: Option<u64>,
    /// Indexes flagged data complete.
    pub completed_data_indexes: Vec<u32>,
}

impl MetaView {
    fn new(meta: &SlotMeta) -> Self {
        Self {
            parent_slot: meta.parent_slot,
            parent_block_id: meta.parent_block_id,
            replay_fec_set_index: meta.replay_fec_set_index,
            has_update_parent: meta.has_update_parent(),
            full: meta.is_full(),
            consumed: meta.consumed,
            received: meta.received,
            last_index: meta.last_index,
            completed_data_indexes: meta.completed_data_indexes.iter().collect(),
        }
    }
}

/// How replay went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replay {
    /// Replay was not asked for.
    Skipped,
    /// The replay stage would not have a bank to replay into yet.
    NotReplayable(String),
    /// The replay stage would decline to create a bank (`Defer`).
    Deferred(String),
    /// `process_single_slot` returned an error.
    Failed {
        /// The error, as Agave prints it.
        error: String,
        /// `(expected, computed)` if the error was a bank hash mismatch.
        bank_hash_mismatch: Option<(Hash, Hash)>,
    },
    /// `process_single_slot` returned Ok; the bank is frozen.
    Ok,
}

/// A transaction replay read from the blockstore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewTx {
    /// Index of the first shred of its component.
    pub component_start: u32,
    /// Entry within the component.
    pub entry: usize,
    /// Transaction within the entry.
    pub tx: usize,
    /// First signature.
    pub signature: [u8; 64],
    /// The transaction's bytes, as replay's parser delimited them.
    pub wire: Vec<u8>,
}

/// A footer marker replay read from the blockstore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewFooter {
    /// Index of the first shred of its component.
    pub component_start: u32,
    /// The bank hash it states.
    pub bank_hash: Hash,
    /// The leader's clock it states.
    pub producer_time_nanos: u64,
}

/// A transaction the scheduler reported a status for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusTx {
    /// Index of the transaction within the slot, as replay counted it.
    pub index: usize,
    /// First signature.
    pub signature: [u8; 64],
    /// `Ok(Ok(()))` committed and succeeded, `Ok(Err(_))` committed and
    /// failed (fees charged, no effect), `Err(_)` not committed.
    pub commit: Result<Result<(), String>, String>,
}

/// A transaction Agave executed, joined from both sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedTx {
    /// Index of the first shred of its component.
    pub component_start: u32,
    /// Entry within the component.
    pub entry: usize,
    /// Transaction within the entry.
    pub tx: usize,
    /// First signature.
    pub signature: [u8; 64],
    /// The transaction's bytes, as replay's parser delimited them.
    pub wire: Vec<u8>,
    /// See [`StatusTx::commit`].
    pub commit: Result<Result<(), String>, String>,
}

/// The blockstore's own counters (`BlockstoreInsertionMetrics`) for coding
/// shreds and erasure recovery, summed over the insert calls of one judgment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryCounts {
    /// Coding shreds stored.
    pub coding_inserted: usize,
    /// Coding shreds refused: invalid, or an erasure config that conflicts.
    pub coding_refused: usize,
    /// Data shreds reconstructed that passed the filter applied after
    /// recovery.
    pub recovered: usize,
    /// Of those, stored.
    pub recovered_inserted: usize,
    /// Of those, refused by the blockstore as invalid.
    pub recovered_invalid: usize,
    /// Of those, already present.
    pub recovered_exists: usize,
}

impl RecoveryCounts {
    /// Adds another judgment's counters to these.
    pub fn add(&mut self, other: &Self) {
        self.coding_inserted += other.coding_inserted;
        self.coding_refused += other.coding_refused;
        self.recovered += other.recovered;
        self.recovered_inserted += other.recovered_inserted;
        self.recovered_invalid += other.recovered_invalid;
        self.recovered_exists += other.recovered_exists;
    }
}

/// Agave's answer for one slot.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// The slot judged.
    pub slot: u64,
    /// One outcome per payload, in the order given.
    pub shreds: Vec<ShredOutcome>,
    /// Error from the insert call itself.
    pub insert_error: Option<String>,
    /// Duplicate reports raised during insertion, by variant name.
    pub duplicates: Vec<String>,
    /// What the blockstore said it did with coding shreds and with the data
    /// shreds it reconstructed from them.
    pub recovery: RecoveryCounts,
    /// `SlotMeta` after insertion; `None` if no shred was stored.
    pub meta: Option<MetaView>,
    /// The data shreds the blockstore holds for the slot after insertion,
    /// in index order: what a node could serve, and what its block id is
    /// computed over. Not every payload given gets here.
    pub stored: Vec<Vec<u8>>,
    /// Whether the slot was dead after insertion, before replay.
    pub dead_after_insert: bool,
    /// Whether the slot is dead now.
    pub dead: bool,
    /// The double Merkle root, if the blockstore computed one.
    pub block_id: Option<Hash>,
    /// Outcome of replay.
    pub replay: Replay,
    /// Hash of the frozen bank, if replay succeeded.
    pub bank_hash: Option<Hash>,
    /// Full, not dead, not deferred, replayed, and a block id exists.
    pub voted: bool,
    /// Shred index replay started from.
    pub replay_start: u64,
    /// Transactions in the components replay loads, in order. Empty unless
    /// replay ran.
    pub view: Vec<ViewTx>,
    /// Footer markers in the components replay loads, in order.
    pub footers: Vec<ViewFooter>,
    /// Error from loading those components.
    pub view_error: Option<String>,
    /// Statuses from the scheduler, sorted by index.
    pub statuses: Vec<StatusTx>,
    /// The join of `view` and `statuses`. `None` if replay did not run, or
    /// if the two disagree in count or order, which is what a replay that
    /// stopped part way looks like.
    pub executed: Option<Vec<ExecutedTx>>,
    /// Wall time of filter, signature check, parse and insert.
    pub ingest_time: Duration,
    /// Wall time of replay.
    pub replay_time: Duration,
}

impl Verdict {
    /// How many payloads the filter discarded.
    pub fn discarded(&self) -> usize {
        self.shreds.iter().filter(|s| s.discarded.is_some()).count()
    }

    /// How many payloads failed the leader signature check.
    pub fn bad_signatures(&self) -> usize {
        self.shreds.iter().filter(|s| !s.signature_ok).count()
    }

    /// How many payloads did not parse.
    pub fn unparsed(&self) -> usize {
        self.shreds
            .iter()
            .filter(|s| s.parse_error.is_some())
            .count()
    }

    /// Whether `process_single_slot` was called.
    pub fn ran(&self) -> bool {
        matches!(self.replay, Replay::Ok | Replay::Failed { .. })
    }

    /// The parent Agave settled on, if `SlotMeta` has one.
    pub fn parent(&self) -> Option<BlockRef> {
        let meta = self.meta.as_ref()?;
        Some(BlockRef {
            slot: meta.parent_slot?,
            id: meta.parent_block_id.to_bytes(),
        })
    }

    /// Everything about the verdict that must not depend on the order shreds
    /// arrive in.
    pub fn order_independent(&self) -> String {
        format!(
            "meta={:?} dead_after_insert={} dead={} block_id={:?} replay={:?} voted={} \
             bank_hash={:?} executed={:?}",
            self.meta,
            self.dead_after_insert,
            self.dead,
            self.block_id,
            self.replay,
            self.voted,
            self.bank_hash,
            self.executed,
        )
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "  shreds: {} given, {} discarded by filter, {} bad signature, {} unparsed",
            self.shreds.len(),
            self.discarded(),
            self.bad_signatures(),
            self.unparsed(),
        )?;
        let mut reasons: Vec<&str> = self
            .shreds
            .iter()
            .filter_map(|s| s.discarded.as_deref())
            .collect();
        reasons.sort_unstable();
        reasons.dedup();
        if !reasons.is_empty() {
            writeln!(f, "  filter reasons: {reasons:?}")?;
        }
        writeln!(
            f,
            "  insert: {} duplicates {:?}",
            self.insert_error.as_deref().unwrap_or("ok"),
            self.duplicates,
        )?;
        if self.recovery != RecoveryCounts::default() {
            writeln!(f, "  recovery: {:?}", self.recovery)?;
        }
        match &self.meta {
            None => writeln!(f, "  meta: none")?,
            Some(meta) => writeln!(
                f,
                "  meta: parent_slot={:?} parent_block_id={} replay_fec_set_index={} \
                 has_update_parent={} full={} consumed={} last_index={:?}",
                meta.parent_slot,
                meta.parent_block_id,
                meta.replay_fec_set_index,
                meta.has_update_parent,
                meta.full,
                meta.consumed,
                meta.last_index,
            )?,
        }
        writeln!(
            f,
            "  dead: after insert {}, now {}",
            self.dead_after_insert, self.dead
        )?;
        match self.block_id {
            Some(id) => writeln!(f, "  block id: {id}")?,
            None => writeln!(f, "  block id: none")?,
        }
        writeln!(
            f,
            "  replay: {:?} (from shred {})",
            self.replay, self.replay_start
        )?;
        if let Some(hash) = self.bank_hash {
            writeln!(f, "  bank hash: {hash}")?;
        }
        if let Some(error) = &self.view_error {
            writeln!(f, "  component load error: {error}")?;
        }
        if self.ran() {
            writeln!(
                f,
                "  transactions: {} in replay's view, {} statuses, joined {}",
                self.view.len(),
                self.statuses.len(),
                match &self.executed {
                    Some(list) => format!("{}", list.len()),
                    None => "INCONSISTENT".to_string(),
                },
            )?;
        }
        writeln!(f, "  voted: {}", self.voted)?;
        write!(
            f,
            "  time: ingest {:.1} ms, replay {:.1} ms",
            self.ingest_time.as_secs_f64() * 1e3,
            self.replay_time.as_secs_f64() * 1e3,
        )
    }
}

/// How to run one judgment.
#[derive(Debug, Clone)]
pub struct JudgeOptions {
    /// Whether to replay after inserting.
    pub replay: bool,
    /// Shreds per insert call; `None` inserts everything in one call.
    pub batch: Option<usize>,
    /// The size of each insert call in turn, which overrides `batch`.
    /// Counted, like `batch`, in shreds that got past the filter, the
    /// signature check and the parser; what is left over goes in one more
    /// call.
    pub cuts: Option<Vec<usize>>,
}

impl Default for JudgeOptions {
    fn default() -> Self {
        Self {
            replay: true,
            batch: None,
            cuts: None,
        }
    }
}

/// The replay stage's decision for a newly discovered child slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayStart {
    /// Create the bank and replay from shred zero.
    FromStart,
    /// Create the bank and start at the UpdateParent FEC set.
    FromUpdateParent(u64),
    /// Do not create the bank.
    Defer(String),
}

/// `child_bank_replay_start` from `core/src/replay_stage/update_parent.rs`,
/// with the reason for a deferral spelled out.
pub fn replay_start(
    slot_meta: Option<&SlotMeta>,
    parent_bank: &Bank,
    parent_slot: u64,
    child_slot: u64,
    migration_status: &MigrationStatus,
) -> ReplayStart {
    if !migration_status.should_allow_block_markers(child_slot) {
        return ReplayStart::FromStart;
    }
    let Some(slot_meta) = slot_meta else {
        return ReplayStart::Defer("no slot meta".into());
    };
    if slot_meta.parent_slot != Some(parent_slot) {
        return ReplayStart::Defer("slot meta parent changed".into());
    }
    // Genesis doesn't have a block id.
    if parent_slot != 0 && Some(slot_meta.parent_block_id) != parent_bank.block_id() {
        return ReplayStart::Defer(format!(
            "slot meta parent block id {} is not the parent bank's {:?}",
            slot_meta.parent_block_id,
            parent_bank.block_id(),
        ));
    }
    if !slot_meta.has_update_parent() {
        return ReplayStart::FromStart;
    }
    ReplayStart::FromUpdateParent(u64::from(slot_meta.replay_fec_set_index))
}

fn signature_bytes(signature: impl AsRef<[u8]>) -> [u8; 64] {
    signature.as_ref().try_into().expect("64-byte signature")
}

/// The non-zero counters in a `ShredFetchStats`, apart from the two that
/// only count accepted shreds.
fn nonzero_counters(debug: &str) -> Option<String> {
    let body = debug
        .trim_start_matches("ShredFetchStats")
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}');
    let hits: Vec<&str> = body
        .split(',')
        .filter_map(|field| {
            let (name, value) = field.split_once(':')?;
            let name = name.trim();
            let value: usize = value.trim().parse().ok()?;
            (value != 0 && !name.starts_with("num_shreds_merkle_")).then_some(name)
        })
        .collect();
    (!hits.is_empty()).then(|| hits.join("+"))
}

fn duplicate_name(duplicate: &PossibleDuplicateShred) -> &'static str {
    match duplicate {
        PossibleDuplicateShred::Exists(_) => "Exists",
        PossibleDuplicateShred::LastIndexConflict(..) => "LastIndexConflict",
        PossibleDuplicateShred::ErasureConflict(..) => "ErasureConflict",
        PossibleDuplicateShred::MerkleRootConflict(..) => "MerkleRootConflict",
        PossibleDuplicateShred::FixedFECChainedMerkleRootConflict(_) => {
            "FixedFECChainedMerkleRootConflict"
        }
    }
}

/// Rewrites the data of one FEC set's shreds in place: shred `start + i`
/// carries `chunks[i]`, later shreds of the set carry nothing. Flags are left
/// alone, so the component still ends where it did. The concatenation of
/// `chunks` is what a validator deshreds.
pub fn set_layout(builder: &mut BlockBuilder, start: u32, chunks: &[&[u8]]) {
    assert!(start.is_multiple_of(FEC_SET) && chunks.len() <= FEC_SET as usize);
    let capacity = body_capacity(VARIANT_DATA).expect("data variant");
    for i in 0..FEC_SET as usize {
        let chunk = chunks.get(i).copied().unwrap_or(&[]);
        assert!(chunk.len() <= capacity);
        let zeros = chunk.iter().rev().take_while(|b| **b == 0).count();
        let shred = builder.shred_mut(start + i as u32);
        shred.size = (DATA_HEADERS_SIZE + chunk.len()) as u16;
        shred.body = chunk[..chunk.len() - zeros].to_vec();
    }
}

/// Cuts `bytes` into a first chunk of `first` bytes and full shreds after it.
pub fn split_first(bytes: &[u8], first: usize) -> Vec<&[u8]> {
    let capacity = body_capacity(VARIANT_DATA).expect("data variant");
    let (head, tail) = bytes.split_at(first.min(bytes.len()));
    std::iter::once(head).chain(tail.chunks(capacity)).collect()
}

/// Recomputes the Merkle proofs of every FEC set after payloads were edited
/// in place, and re-chains the sets the way the testkit does (each set's
/// chained root is the root of the set before it; the first set keeps what it
/// has). Signatures are left stale: call [`Oracle::sign`] afterward.
///
/// This is what lets a case carry header fields `BlockBuilder` refuses to
/// write, such as a `size` out of bounds. `payloads` must be whole FEC sets
/// in index order, as `BlockBuilder::build` returns them.
pub fn reseal(payloads: &mut [Vec<u8>]) {
    assert!(payloads.len().is_multiple_of(FEC_SET as usize));
    let mut previous_root: Option<[u8; 32]> = None;
    for (set, shreds) in payloads.chunks_mut(FEC_SET as usize).enumerate() {
        let slot = u64::from_le_bytes(shreds[0][65..73].try_into().unwrap());
        let mut leaves = Vec::with_capacity(2 * FEC_SET as usize);
        let mut leaf_ends = Vec::with_capacity(FEC_SET as usize);
        for payload in shreds.iter_mut() {
            assert_eq!(payload.len(), DATA_SHRED_SIZE);
            let capacity = body_capacity(payload[64]).expect("a Merkle data shred variant");
            let body_end = DATA_HEADERS_SIZE + capacity;
            if let Some(root) = previous_root {
                payload[body_end..body_end + 32].copy_from_slice(&root);
            }
            leaves.push(merkle::shred_leaf(&payload[64..body_end + 32]));
            leaf_ends.push(body_end + 32);
        }
        for i in 0..u64::from(FEC_SET) {
            leaves.push(merkle::sha256(&[
                b"testkit-coding",
                &slot.to_le_bytes(),
                &(set as u64).to_le_bytes(),
                &i.to_le_bytes(),
            ]));
        }
        let tree = merkle::Tree::new(leaves);
        for (i, payload) in shreds.iter_mut().enumerate() {
            let mut at = leaf_ends[i];
            for node in tree.path(i) {
                payload[at..at + node.len()].copy_from_slice(&node);
                at += node.len();
            }
        }
        previous_root = Some(tree.root());
    }
}

/// Gives a block real coding shreds: for every FEC set, the 32 Reed-Solomon
/// parity shards of its data shreds, each in a coding shred a validator
/// accepts, and the Merkle tree over all 64. Returns the coding shreds in
/// index order, 32 per set; the data payloads are rewritten in place.
///
/// `BlockBuilder` cannot do this: its trees hold filler hashes for the
/// coding leaves, and no shred hashes to those. With real coding leaves
/// every set's root moves, so the root chained into the next set moves, and
/// the block id with them; the bytes a validator deshreds do not. Each set's
/// chained root is the root of the set before it and the first set keeps
/// what it has, as in [`reseal`]. Signatures are left stale: call
/// [`Oracle::sign`] on both lists afterward.
///
/// The parity covers each data shred from its variant byte to the end of
/// its data buffer, headers and padding included, which is what
/// `finish_erasure_batch` (`ledger/src/shred/merkle.rs`) encodes; that
/// function is private, so the layout is written out here and
/// [`Oracle::coding_matches_agave`] holds it to Agave's shredder. `payloads`
/// must be whole FEC sets in index order, each of one variant.
pub fn erasure_code(payloads: &mut [Vec<u8>]) -> Vec<Vec<u8>> {
    let per_set = FEC_SET as usize;
    assert!(payloads.len().is_multiple_of(per_set));
    let codec = ReedSolomon::new(per_set, CODING_PER_SET as usize).expect("a 32:32 code exists");
    let mut coding = Vec::with_capacity(payloads.len());
    let mut previous_root: Option<[u8; 32]> = None;
    for shreds in payloads.chunks_mut(per_set) {
        let variant = shreds[0][64];
        assert!(shreds.iter().all(|payload| payload[64] == variant));
        let capacity = body_capacity(variant).expect("a Merkle data shred variant");
        let resigned = variant != VARIANT_DATA;
        // Data shred: headers, data buffer, chained root, proof.
        let data_end = DATA_HEADERS_SIZE + capacity;
        // Coding shred: headers, a shard as long as the coded part of a
        // data shred, chained root, proof.
        let shard_len = data_end - 64;
        let code_end = CODING_HEADERS_SIZE + shard_len;
        let chained: [u8; 32] = match previous_root {
            Some(root) => root,
            None => shreds[0][data_end..data_end + 32].try_into().unwrap(),
        };

        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(2 * per_set);
        for payload in shreds.iter_mut() {
            assert_eq!(payload.len(), DATA_SHRED_SIZE);
            payload[data_end..data_end + 32].copy_from_slice(&chained);
            shards.push(payload[64..data_end].to_vec());
        }
        shards.resize(2 * per_set, vec![0; shard_len]);
        codec
            .encode(&mut shards)
            .expect("32 data shards of one length");

        // The set's index and the fields every shred of it shares.
        let common = shreds[0][65..83].to_vec();
        let fec_set_index = u32::from_le_bytes(common[14..18].try_into().unwrap());
        let mut set_coding: Vec<Vec<u8>> = (0..CODING_PER_SET)
            .map(|position| {
                let mut payload = vec![0u8; CODING_SHRED_SIZE];
                payload[64] = match resigned {
                    true => VARIANT_CODING_RESIGNED,
                    false => VARIANT_CODING,
                };
                payload[65..83].copy_from_slice(&common);
                // A coding shred's index runs beside the data indexes.
                payload[73..77].copy_from_slice(&(fec_set_index + position).to_le_bytes());
                payload[83..85].copy_from_slice(&(FEC_SET as u16).to_le_bytes());
                payload[85..87].copy_from_slice(&(CODING_PER_SET as u16).to_le_bytes());
                payload[87..89].copy_from_slice(&(position as u16).to_le_bytes());
                payload[CODING_HEADERS_SIZE..code_end]
                    .copy_from_slice(&shards[per_set + position as usize]);
                payload[code_end..code_end + 32].copy_from_slice(&chained);
                payload
            })
            .collect();

        let leaves = shreds
            .iter()
            .map(|payload| merkle::shred_leaf(&payload[64..data_end + 32]))
            .chain(
                set_coding
                    .iter()
                    .map(|payload| merkle::shred_leaf(&payload[64..code_end + 32])),
            )
            .collect();
        let tree = merkle::Tree::new(leaves);
        let proofs = shreds
            .iter_mut()
            .map(|payload| (payload, data_end + 32))
            .chain(
                set_coding
                    .iter_mut()
                    .map(|payload| (payload, code_end + 32)),
            );
        for (i, (payload, proof_at)) in proofs.enumerate() {
            let mut at = proof_at;
            for node in tree.path(i) {
                payload[at..at + node.len()].copy_from_slice(&node);
                at += node.len();
            }
        }
        previous_root = Some(tree.root());
        coding.append(&mut set_coding);
    }
    coding
}

impl Oracle {
    /// Builds the chain: genesis with one validator and every feature
    /// active, Alpenglow enabled from slot 0, an empty blockstore.
    pub fn new(config: OracleConfig) -> Self {
        let seeded = |n: u8| keypair_from_seed(&[n; 32]).expect("32-byte seed");
        let validator = ValidatorVoteKeypairs::new(seeded(1), seeded(2), seeded(3));
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_alpenglow_vote_accounts(
            config.mint_lamports,
            &[&validator],
            vec![config.stake_lamports],
        );
        genesis_config.creation_time = config.creation_time;
        if !config.fast_leader_handover {
            genesis_config
                .accounts
                .remove(&agave_feature_set::alpenglow_fast_leader_handover::id())
                .expect("the all-features genesis activates fast leader handover");
        }
        genesis_config.epoch_schedule =
            EpochSchedule::custom(config.slots_per_epoch, config.slots_per_epoch, false);

        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
        let root_bank = bank_forks.read().unwrap().root_bank();
        root_bank.freeze();
        let migration_status = bank_forks.read().unwrap().migration_status();
        assert!(
            migration_status.is_alpenglow_enabled(),
            "genesis must start in Alpenglow"
        );
        assert!(
            root_bank
                .feature_set
                .is_active(&agave_feature_set::alpenglow::id())
        );

        let (sender, status_receiver) = crossbeam_channel::unbounded();
        let status_sender = TransactionStatusSender {
            sender,
            dependency_tracker: None,
        };
        let pool = DefaultSchedulerPool::new_for_verification(
            None,
            None,
            Some(status_sender.clone()),
            None,
            None,
        );
        bank_forks.write().unwrap().install_scheduler_pool(pool);

        let ledger = tempfile::tempdir().expect("temporary ledger directory");
        let blockstore = Arc::new(Blockstore::open(ledger.path()).expect("blockstore opens"));
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);

        Self {
            mint: mint_keypair,
            leader: validator.node_keypair.insecure_clone(),
            genesis_hash: genesis_config.hash(),
            blockstore,
            bank_forks,
            migration_status,
            leader_schedule_cache,
            verification_pool: ReplayVerificationWorkerPool::new(config.verification_threads),
            process_options: ProcessOptions {
                run_verification: true,
                ..ProcessOptions::default()
            },
            status_sender,
            status_receiver,
            sigverify_cache: RwLock::new(LruCache::new(4096)),
            _ledger: ledger,
            config,
        }
    }

    /// The configuration the oracle was built with.
    pub fn config(&self) -> &OracleConfig {
        &self.config
    }

    /// Hash of the genesis config.
    pub fn genesis_hash(&self) -> Hash {
        self.genesis_hash
    }

    /// The blockstore, for reading.
    pub fn blockstore(&self) -> &Blockstore {
        &self.blockstore
    }

    /// The migration status every call is made with.
    pub fn migration_status(&self) -> &MigrationStatus {
        &self.migration_status
    }

    /// Identity of the validator, leader of every slot.
    pub fn leader(&self) -> Pubkey {
        self.leader.pubkey()
    }

    /// The bank at `slot`, if the oracle holds one.
    pub fn bank(&self, slot: u64) -> Option<Arc<Bank>> {
        self.bank_forks.read().unwrap().get(slot)
    }

    /// Whether `alpenglow_fast_leader_handover` is active, which is what
    /// makes UpdateParent markers legal.
    pub fn fast_leader_handover(&self) -> bool {
        self.root_bank()
            .feature_set
            .snapshot()
            .alpenglow_fast_leader_handover
    }

    /// Whether the shred-level Alpenglow rules apply to `slot`. Shred rules
    /// lag a feature's activation by one epoch, so with features active
    /// from genesis this is false throughout epoch 0. It is what the
    /// duplicate handler reads to decide whether a broken chained Merkle
    /// root kills the slot.
    pub fn alpenglow_shred_rules(&self, slot: u64) -> bool {
        check_feature_activation_from_bank(
            &agave_feature_set::alpenglow::id(),
            slot,
            &self.root_bank(),
        )
    }

    fn root_bank(&self) -> Arc<Bank> {
        self.bank_forks.read().unwrap().root_bank()
    }

    fn frozen_bank(&self, slot: u64) -> Arc<Bank> {
        let bank = self
            .bank(slot)
            .unwrap_or_else(|| panic!("the oracle holds no bank for slot {slot}"));
        assert!(bank.is_frozen(), "bank {slot} is not frozen");
        bank
    }

    /// Slot and block id of a frozen bank, as a child's header names it.
    /// Genesis has no block id; its id is all zeros.
    pub fn block_ref(&self, slot: u64) -> BlockRef {
        BlockRef {
            slot,
            id: self
                .frozen_bank(slot)
                .block_id()
                .unwrap_or_default()
                .to_bytes(),
        }
    }

    /// The blockhash transactions in a child of `parent_slot` should name,
    /// and the hash its entry chain starts from.
    pub fn last_blockhash(&self, parent_slot: u64) -> Hash {
        self.frozen_bank(parent_slot).last_blockhash()
    }

    /// The inclusive range of footer timestamps the clock bounds accept for
    /// `slot` built on `parent_slot`, from Agave's own
    /// `nanosecond_time_bounds`. The inputs are read from the parent bank;
    /// replay reads the slot durations from the child bank, which is the
    /// same thing unless a feature changes them between the two.
    pub fn footer_time_bounds(&self, parent_slot: u64, slot: u64) -> (u64, u64) {
        let parent = self.frozen_bank(parent_slot);
        let parent_nanos = parent
            .get_nanosecond_clock()
            .unwrap_or_else(|| parent.clock().unix_timestamp.saturating_mul(1_000_000_000));
        let elapsed = parent.slot_range_duration_nanos(parent_slot + 1, slot);
        let (low, high) = BlockComponentProcessor::nanosecond_time_bounds(parent_nanos, elapsed);
        (
            u64::try_from(low).expect("time after 1970"),
            u64::try_from(high).expect("time after 1970"),
        )
    }

    /// A footer timestamp in the middle of [`Oracle::footer_time_bounds`]:
    /// one nominal slot time per slot elapsed since the parent.
    pub fn footer_time(&self, parent_slot: u64, slot: u64) -> u64 {
        let (low, high) = self.footer_time_bounds(parent_slot, slot);
        low + (high - low) / 2
    }

    /// The account [`Oracle::transfer`] pays for `seed`.
    pub fn recipient(seed: &[u8]) -> Pubkey {
        Pubkey::new_from_array(hashv(&[b"oracle-recipient", seed]).to_bytes())
    }

    /// A signed transfer of `lamports` from the mint to a fresh account
    /// derived from `seed`.
    pub fn transfer(&self, seed: &[u8], lamports: u64, blockhash: Hash) -> VersionedTransaction {
        let to = Self::recipient(seed);
        let instruction = system_instruction::transfer(&self.mint.pubkey(), &to, lamports);
        let message = Message::new(&[instruction], Some(&self.mint.pubkey()));
        VersionedTransaction::from(Transaction::new(&[&self.mint], message, blockhash))
    }

    /// Like [`Oracle::transfer`], with `extra` appended to the instruction
    /// data: arbitrary bytes inside a transaction.
    pub fn transfer_with_data(
        &self,
        seed: &[u8],
        lamports: u64,
        extra: &[u8],
        blockhash: Hash,
    ) -> VersionedTransaction {
        let to = Self::recipient(seed);
        let mut instruction = system_instruction::transfer(&self.mint.pubkey(), &to, lamports);
        instruction.data.extend_from_slice(extra);
        let message = Message::new(&[instruction], Some(&self.mint.pubkey()));
        VersionedTransaction::from(Transaction::new(&[&self.mint], message, blockhash))
    }

    /// One entry on the hash chain in `chain`, one hash after the previous.
    pub fn entry(chain: &mut Hash, transactions: Vec<VersionedTransaction>) -> Entry {
        let entry = next_versioned_entry(chain, 1, transactions);
        *chain = entry.hash;
        entry
    }

    /// The header marker, as bytes.
    pub fn header_bytes(parent: &BlockRef) -> Vec<u8> {
        let component =
            BlockComponent::new_block_header(parent.slot, Hash::new_from_array(parent.id));
        wincode::serialize(&component).expect("header serializes")
    }

    /// An UpdateParent marker, as bytes.
    pub fn update_parent_bytes(parent: &BlockRef) -> Vec<u8> {
        let marker = VersionedBlockMarker::from_update_parent(UpdateParentV1 {
            new_parent_slot: parent.slot,
            new_parent_block_id: Hash::new_from_array(parent.id),
        });
        wincode::serialize(&BlockComponent::new_block_marker(marker))
            .expect("update parent serializes")
    }

    /// A footer marker with no certificates, as bytes.
    pub fn footer_bytes(bank_hash: Hash, producer_time_nanos: u64) -> Vec<u8> {
        let marker = VersionedBlockMarker::from_block_footer(BlockFooterV1 {
            bank_hash,
            block_producer_time_nanos: producer_time_nanos,
            block_user_agent: b"agave-fixtures/oracle".to_vec(),
            block_final_cert: None,
            skip_reward_cert: None,
            notar_reward_cert: None,
        });
        wincode::serialize(&BlockComponent::new_block_marker(marker)).expect("footer serializes")
    }

    /// An entry batch as bytes: one entry per element of `entries`, each
    /// one hash after the previous, continuing the chain in `chain`.
    pub fn entry_batch_bytes(chain: &mut Hash, entries: Vec<Vec<VersionedTransaction>>) -> Vec<u8> {
        let entries: Vec<Entry> = entries
            .into_iter()
            .map(|transactions| {
                let entry = next_versioned_entry(chain, 1, transactions);
                *chain = entry.hash;
                entry
            })
            .collect();
        let component = BlockComponent::new_entry_batch(entries).expect("non-empty batch");
        wincode::serialize(&component).expect("entry batch serializes")
    }

    /// Appends entry batches of transfers to `components`, on the hash
    /// chain in `chain`, naming `blockhash`.
    #[allow(clippy::too_many_arguments)]
    fn push_batches(
        &self,
        spec: &HonestSpec,
        batches: &[Vec<usize>],
        abandoned: bool,
        blockhash: Hash,
        chain: &mut Hash,
        components: &mut Vec<Vec<u8>>,
        transactions: &mut Vec<BuiltTx>,
    ) {
        for (batch_index, batch) in batches.iter().enumerate() {
            let component = components.len();
            let entries: Vec<Vec<VersionedTransaction>> = batch
                .iter()
                .enumerate()
                .map(|(entry_index, count)| {
                    (0..*count)
                        .map(|tx_index| {
                            let seed = [
                                spec.slot.to_le_bytes(),
                                spec.seed.to_le_bytes(),
                                u64::from(abandoned).to_le_bytes(),
                                (batch_index as u64).to_le_bytes(),
                                (entry_index as u64).to_le_bytes(),
                                (tx_index as u64).to_le_bytes(),
                            ]
                            .concat();
                            let lamports = 1_000_000 + transactions.len() as u64;
                            let tx = self.transfer(&seed, lamports, blockhash);
                            transactions.push(BuiltTx {
                                component,
                                entry: entry_index,
                                tx: tx_index,
                                signature: signature_bytes(tx.signatures[0]),
                                wire: wincode::serialize(&tx).expect("transaction serializes"),
                                recipient: Self::recipient(&seed),
                                lamports,
                                abandoned,
                            });
                            tx
                        })
                        .collect()
                })
                .collect();
            components.push(Self::entry_batch_bytes(chain, entries));
        }
    }

    /// Builds an honest block from Agave's own types: header, entry batches
    /// of transfers on a real hash chain, footer, alpentick. With
    /// [`HonestSpec::abandoned`], the block a leader produces when it starts
    /// on one parent and switches to another.
    pub fn build_honest(&self, spec: &HonestSpec) -> HonestBlock {
        let parent = self.block_ref(spec.parent_slot);
        let blockhash = self.last_blockhash(spec.parent_slot);
        let producer_time_nanos = self.footer_time(spec.parent_slot, spec.slot);

        let mut components = Vec::new();
        let mut transactions = Vec::new();
        let mut update_parent = None;
        match &spec.abandoned {
            None => components.push(Self::header_bytes(&parent)),
            Some(prefix) => {
                let optimistic = self.block_ref(prefix.header_parent_slot);
                let optimistic_blockhash = self.last_blockhash(prefix.header_parent_slot);
                components.push(Self::header_bytes(&optimistic));
                self.push_batches(
                    spec,
                    &prefix.batches,
                    true,
                    optimistic_blockhash,
                    &mut optimistic_blockhash.clone(),
                    &mut components,
                    &mut transactions,
                );
                update_parent = Some(components.len());
                components.push(Self::update_parent_bytes(&parent));
            }
        }
        let mut chain = blockhash;
        self.push_batches(
            spec,
            &spec.batches,
            false,
            blockhash,
            &mut chain,
            &mut components,
            &mut transactions,
        );
        let footer = components.len();
        components.push(Self::footer_bytes(spec.bank_hash, producer_time_nanos));
        components.push(Self::entry_batch_bytes(&mut chain, vec![vec![]]));

        HonestBlock {
            slot: spec.slot,
            // What the shred headers point at: the parent the leader
            // started on.
            parent: match &spec.abandoned {
                None => parent,
                Some(prefix) => self.block_ref(prefix.header_parent_slot),
            },
            final_parent: parent,
            components,
            transactions,
            update_parent,
            footer,
            producer_time_nanos,
        }
    }

    /// Starts a testkit builder holding `components`, one FEC-set-aligned
    /// run of shreds per component. Mutate it, `build()` it, then
    /// [`Oracle::sign`] the result.
    pub fn shred(&self, slot: u64, parent: BlockRef, components: &[Vec<u8>]) -> BlockBuilder {
        components.iter().fold(
            BlockBuilder::new(slot, parent, self.config.shred_version),
            |builder, bytes| builder.component(bytes),
        )
    }

    /// Signs every payload as the leader: the signature covers the Merkle
    /// root of the payload's FEC set and goes into its first 64 bytes.
    pub fn sign(&self, payloads: &mut [Vec<u8>]) {
        let mut signatures: HashMap<Hash, [u8; 64]> = HashMap::new();
        for payload in payloads {
            let root = wire::get_merkle_root(payload).expect("payload has a Merkle root");
            let signature = signatures
                .entry(root)
                .or_insert_with(|| signature_bytes(self.leader.sign_message(root.as_ref())));
            payload[..64].copy_from_slice(signature);
        }
    }

    /// Shreds `components` in the plain layout and signs them.
    pub fn shred_and_sign(
        &self,
        slot: u64,
        parent: BlockRef,
        components: &[Vec<u8>],
    ) -> Vec<Vec<u8>> {
        let mut payloads = self.shred(slot, parent, components).build();
        self.sign(&mut payloads);
        payloads
    }

    /// Holds [`erasure_code`] to Agave's shredder: cuts some bytes into
    /// shreds with `Shredder::make_shreds_from_data_slice`, blanks everything
    /// in its data shreds that `erasure_code` and [`Oracle::sign`] are
    /// supposed to produce, and requires both to give back Agave's data and
    /// coding shreds byte for byte. The block is three full sets and a last
    /// one of the resigned variant, so both variants are covered.
    pub fn coding_matches_agave(&self) -> Result<String, String> {
        let slot = 2 * self.config.slots_per_epoch + 5;
        let capacity = body_capacity(VARIANT_DATA).expect("data variant");
        let data: Vec<u8> = (0..3 * FEC_SET as usize * capacity + 7_000)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let first_chained_root = hashv(&[b"oracle-coding-check"]);
        let shreds = Shredder::new(slot, slot - 1, 0, self.config.shred_version)
            .map_err(|error| format!("shredder: {error:?}"))?
            .make_shreds_from_data_slice(
                &self.leader,
                &data,
                true, // is_last_in_slot
                first_chained_root,
                0,
                0,
                &ReedSolomonCache::default(),
                &mut ProcessShredsStats::default(),
            )
            .map_err(|error| format!("shredder: {error:?}"))?;
        let (agave_data, agave_coding): (Vec<&Shred>, Vec<&Shred>) =
            shreds.iter().partition(|shred| shred.is_data());
        let agave_data: Vec<Vec<u8>> = agave_data.iter().map(|s| s.payload().to_vec()).collect();
        let agave_coding: Vec<Vec<u8>> =
            agave_coding.iter().map(|s| s.payload().to_vec()).collect();

        let mut ours = agave_data.clone();
        for (i, payload) in ours.iter_mut().enumerate() {
            let data_end =
                DATA_HEADERS_SIZE + body_capacity(payload[64]).ok_or("unknown data variant")?;
            payload[..64].fill(0);
            // The first set's chained root is an input, not a product.
            let keep = if i < FEC_SET as usize { 32 } else { 0 };
            payload[data_end + keep..data_end + 32 + 6 * 20].fill(0);
        }
        let mut coding = erasure_code(&mut ours);
        self.sign(&mut ours);
        self.sign(&mut coding);

        let differing = |ours: &[Vec<u8>], agave: &[Vec<u8>]| {
            ours.len().abs_diff(agave.len())
                + ours.iter().zip(agave).filter(|(a, b)| a != b).count()
        };
        let resigned = agave_data
            .iter()
            .filter(|payload| payload[64] != VARIANT_DATA)
            .count();
        match (
            differing(&ours, &agave_data),
            differing(&coding, &agave_coding),
        ) {
            (0, 0) => Ok(format!(
                "{} data shreds ({resigned} resigned) and {} coding shreds",
                ours.len(),
                coding.len()
            )),
            (data, code) => Err(format!(
                "{data} of {} data shreds and {code} of {} coding shreds differ from Agave's",
                agave_data.len(),
                agave_coding.len()
            )),
        }
    }

    /// Finds the bank hash an honest block needs in its footer: judges the
    /// block with whatever hash the spec has, and if replay stops at a bank
    /// hash mismatch, returns the hash Agave computed. `None` means the
    /// block fails for another reason (or already votes); the verdict says
    /// which.
    pub fn settle_bank_hash(&self, spec: &HonestSpec) -> (Option<Hash>, Verdict) {
        let block = self.build_honest(spec);
        let payloads = self.shred_and_sign(block.slot, block.parent, &block.components);
        let verdict = self.judge(spec.slot, &payloads);
        let computed = match &verdict.replay {
            Replay::Failed {
                bank_hash_mismatch: Some((_, computed)),
                ..
            } => Some(*computed),
            _ => None,
        };
        (computed, verdict)
    }

    /// Forgets everything about `slot`: its bank, its accounts, its status
    /// cache entries, and every blockstore column.
    pub fn reset_slot(&self, slot: u64) {
        assert_ne!(slot, 0, "genesis cannot be reset");
        let existing = self.bank_forks.read().unwrap().get_with_scheduler(slot);
        if let Some(bank) = existing {
            let _ = bank.wait_for_completed_scheduler();
            drop(bank);
            let root_bank = self.root_bank();
            let (slots, banks) = self
                .bank_forks
                .write()
                .unwrap()
                .dump_slots(std::iter::once(&slot), false);
            root_bank.remove_unrooted_slots(&slots);
            drop(banks);
            for (slot, _) in slots {
                root_bank.clear_slot_signatures(slot);
                root_bank.prune_program_cache_by_deployment_slot(slot);
            }
        }
        // A freeze message holds the bank alive; statuses of a judgment
        // nobody read must not leak into the next one.
        self.status_receiver.try_iter().for_each(drop);
        self.blockstore
            .purge_slots_cleanup_chaining(slot, slot, PurgeType::Exact)
            .expect("purge succeeds");
        assert!(self.blockstore.meta(slot).unwrap().is_none());
        assert!(!self.blockstore.is_dead(slot));
    }

    /// Judges `payloads` as the shreds of `slot`, with replay.
    pub fn judge(&self, slot: u64, payloads: &[Vec<u8>]) -> Verdict {
        self.judge_with(slot, payloads, &JudgeOptions::default())
    }

    /// Judges `payloads` as the shreds of `slot`.
    ///
    /// The slot is reset first, so the same slot can be judged many times.
    /// Afterward its state is left in place: a voted block stays as a
    /// frozen bank and can be the parent of later blocks.
    pub fn judge_with(&self, slot: u64, payloads: &[Vec<u8>], options: &JudgeOptions) -> Verdict {
        self.reset_slot(slot);
        let root_bank = self.root_bank();
        let shred_version = self.config.shred_version;
        let started = Instant::now();

        // Fetch stage, sigverify, parse: the skeleton of Agave's
        // conformance/src/shred.rs `execute_shred_parse`, plus sigverify.
        let mut filter = ShredFilterContext::new(root_bank.clone(), shred_version);
        let mut slot_leaders = SlotPubkeys::default();
        let mut outcomes = Vec::with_capacity(payloads.len());
        let mut accepted: Vec<Shred> = Vec::new();
        for payload in payloads {
            let discard = filter.should_discard_shred(payload);
            let counters = nonzero_counters(&format!("{:?}", std::mem::take(&mut filter.stats)));
            let (discarded, filter_notes) = match discard {
                true => (Some(counters.unwrap_or_else(|| "unknown".into())), None),
                false => (None, counters),
            };

            if let Some(shred_slot) = wire::get_slot(payload)
                && !slot_leaders.contains_key(&shred_slot)
                && let Some(leader) = self
                    .leader_schedule_cache
                    .slot_leader_at(shred_slot, Some(&root_bank))
            {
                slot_leaders.insert(shred_slot, leader.id);
            }
            let signature_ok = payload.len() <= solana_perf::packet::PACKET_DATA_SIZE && {
                let mut packet = Packet::default();
                packet.buffer_mut()[..payload.len()].copy_from_slice(payload);
                packet.meta_mut().size = payload.len();
                verify_shred_cpu((&packet).into(), &slot_leaders, &self.sigverify_cache)
            };

            let parsed = Shred::new_from_serialized_shred(payload.clone());
            let outcome = ShredOutcome {
                discarded,
                filter_notes,
                signature_ok,
                parse_error: parsed.as_ref().err().map(|e| format!("{e:?}")),
            };
            if outcome.accepted() {
                accepted.push(parsed.unwrap());
            }
            outcomes.push(outcome);
        }

        // Window service: insert, untrusted, with duplicate handling.
        let (retransmit_sender, _retransmit_receiver) = EvictingSender::new_bounded(0);
        let mut recovery = ShredRecoveryContext::new(
            ReedSolomonCache::default(),
            retransmit_sender,
            root_bank.clone(),
            shred_version,
        );
        let duplicates = RefCell::new(Vec::new());
        let handle_duplicate = |duplicate: PossibleDuplicateShred| {
            duplicates
                .borrow_mut()
                .push(duplicate_name(&duplicate).to_string());
            let shred_slot = duplicate.slot();
            let no_verify_chained_merkle_root = check_feature_activation_from_bank(
                &agave_feature_set::alpenglow::id(),
                shred_slot,
                &root_bank,
            );
            handle_duplicate_shred(&self.blockstore, duplicate, no_verify_chained_merkle_root)
                .expect("handle duplicate shred");
            let should_mark_dead = self
                .migration_status
                .genesis_block()
                .is_some_and(|genesis| shred_slot > genesis.slot);
            if should_mark_dead {
                self.blockstore
                    .set_dead_slot_if_duplicate_and_not_full(shred_slot)
                    .expect("mark dead");
            }
        };
        let mut metrics = BlockstoreInsertionMetrics::default();
        let mut insert_error = None;
        let calls: Vec<&[Shred]> = match &options.cuts {
            Some(cuts) => {
                let mut rest = &accepted[..];
                let mut calls: Vec<&[Shred]> = cuts
                    .iter()
                    .map(|size| {
                        let (call, after) = rest.split_at((*size).min(rest.len()));
                        rest = after;
                        call
                    })
                    .collect();
                calls.push(rest);
                calls
            }
            None => accepted
                .chunks(options.batch.unwrap_or(usize::MAX).max(1))
                .collect(),
        };
        for batch in calls.into_iter().filter(|call| !call.is_empty()) {
            let shreds = batch.iter().map(|shred| (Cow::Borrowed(shred), false));
            if let Err(error) = self.blockstore.insert_shreds_handle_duplicate(
                shreds,
                false, // is_trusted
                &mut recovery,
                &handle_duplicate,
                &mut metrics,
            ) {
                insert_error.get_or_insert_with(|| format!("{error:?}"));
            }
        }
        let ingest_time = started.elapsed();

        let slot_meta = self.blockstore.meta(slot).expect("meta reads");
        let dead_after_insert = self.blockstore.is_dead(slot);
        let block_id = self
            .blockstore
            .get_double_merkle_root(slot, BlockLocation::Original)
            .expect("double merkle root reads");

        let mut verdict = Verdict {
            slot,
            shreds: outcomes,
            insert_error,
            duplicates: duplicates.into_inner(),
            recovery: RecoveryCounts {
                coding_inserted: metrics.num_coding_shreds_inserted,
                coding_refused: metrics.num_coding_shreds_invalid
                    + metrics.num_coding_shreds_invalid_erasure_config,
                recovered: metrics.num_recovered,
                recovered_inserted: metrics.num_recovered_inserted,
                recovered_invalid: metrics.num_recovered_failed_invalid,
                recovered_exists: metrics.num_recovered_exists,
            },
            meta: slot_meta.as_ref().map(MetaView::new),
            stored: self
                .blockstore
                .get_data_shreds_for_slot(slot, 0)
                .map(|shreds| shreds.iter().map(|s| s.payload().to_vec()).collect())
                .unwrap_or_default(),
            dead_after_insert,
            dead: dead_after_insert,
            block_id,
            replay: Replay::Skipped,
            bank_hash: None,
            voted: false,
            replay_start: 0,
            view: Vec::new(),
            footers: Vec::new(),
            view_error: None,
            statuses: Vec::new(),
            executed: None,
            ingest_time,
            replay_time: Duration::ZERO,
        };
        if options.replay {
            let started = Instant::now();
            self.replay(slot, slot_meta.as_ref(), &mut verdict);
            verdict.replay_time = started.elapsed();
        }
        verdict.dead = self.blockstore.is_dead(slot);
        verdict.voted = verdict.meta.as_ref().is_some_and(|meta| meta.full)
            && !verdict.dead
            && verdict.replay == Replay::Ok
            && verdict.block_id.is_some();
        verdict
    }

    /// The replay stage, reduced to one slot: decide whether and where to
    /// start (`generate_new_bank_forks`), then replay the full slot.
    fn replay(&self, slot: u64, slot_meta: Option<&SlotMeta>, verdict: &mut Verdict) {
        let not_replayable = |reason: &str| Replay::NotReplayable(reason.to_string());
        let Some(meta) = slot_meta else {
            verdict.replay = not_replayable("no slot meta");
            return;
        };
        // The replay stage replays partial slots as shreds arrive; a slot
        // that never fills never freezes, so there is nothing to vote on.
        if !meta.is_full() {
            verdict.replay = not_replayable("slot is not full");
            return;
        }
        if verdict.dead_after_insert {
            verdict.replay = not_replayable("slot is dead");
            return;
        }
        // `get_slots_since` only finds children of frozen banks.
        let Some(parent_slot) = meta.parent_slot else {
            verdict.replay = not_replayable("slot meta has no parent");
            return;
        };
        let Some(parent) = self.bank(parent_slot).filter(|bank| bank.is_frozen()) else {
            verdict.replay = not_replayable("no frozen bank for the parent slot");
            return;
        };
        if parent_slot >= slot {
            verdict.replay = not_replayable("parent slot is not before the slot");
            return;
        }

        let start = match replay_start(
            Some(meta),
            &parent,
            parent_slot,
            slot,
            &self.migration_status,
        ) {
            ReplayStart::Defer(reason) => {
                verdict.replay = Replay::Deferred(reason);
                return;
            }
            ReplayStart::FromStart => 0,
            ReplayStart::FromUpdateParent(num_shreds) => num_shreds,
        };
        verdict.replay_start = start;

        // `process_single_slot` expects a block id after a successful
        // replay and panics without one.
        if self
            .blockstore
            .get_block_id(slot, &self.migration_status)
            .expect("block id reads")
            .is_none()
        {
            verdict.replay = not_replayable("slot is full but has no block id");
            return;
        }

        let leader = self
            .leader_schedule_cache
            .slot_leader_at(slot, Some(&parent))
            .expect("leader schedule covers the slot");
        assert_eq!(leader.id, self.leader.pubkey());
        let child = Bank::new_from_parent(parent.clone(), leader, slot);
        blockstore_processor::set_alpenglow_ticks(&child, &self.migration_status);
        let bank = self.bank_forks.write().unwrap().insert(child);

        let mut progress = ConfirmationProgress::new(parent.last_blockhash());
        progress.num_shreds = start;
        let result = blockstore_processor::process_single_slot(
            &self.blockstore,
            &bank,
            self.config.shred_version,
            &self.verification_pool,
            &self.process_options,
            &mut progress,
            Some(&self.status_sender),
            None,
            None,
            &mut ExecuteTimings::default(),
            &self.migration_status,
        );
        // On an error path the scheduler may still be attached.
        let _ = bank.wait_for_completed_scheduler();

        verdict.replay = match result {
            Ok(()) => {
                verdict.bank_hash = Some(bank.hash());
                Replay::Ok
            }
            Err(error) => Replay::Failed {
                bank_hash_mismatch: match &error {
                    BlockstoreProcessorError::BankHashMismatch(_, expected, computed) => {
                        Some((*expected, *computed))
                    }
                    _ => None,
                },
                error: error.to_string(),
            },
        };

        // What replay read: the same call `confirm_slot` makes.
        match self
            .blockstore
            .get_slot_component_views_with_shred_info(slot, start, true)
        {
            Ok((components, ranges, _full)) => {
                for (range, component) in ranges.iter().zip(components) {
                    let entries = match component {
                        ParsedBlockComponent::EntryBatch(entries) => entries,
                        ParsedBlockComponent::BlockMarker(VersionedBlockMarker::V1(marker)) => {
                            if let Some(VersionedBlockFooter::V1(footer)) = marker.as_block_footer()
                            {
                                verdict.footers.push(ViewFooter {
                                    component_start: range.start,
                                    bank_hash: footer.bank_hash,
                                    producer_time_nanos: footer.block_producer_time_nanos,
                                });
                            }
                            continue;
                        }
                    };
                    for (entry_index, entry) in entries.iter().enumerate() {
                        for (tx_index, tx) in entry.transactions.iter().enumerate() {
                            verdict.view.push(ViewTx {
                                component_start: range.start,
                                entry: entry_index,
                                tx: tx_index,
                                signature: signature_bytes(tx.signatures()[0]),
                                wire: tx.data().to_vec(),
                            });
                        }
                    }
                }
            }
            Err(error) => verdict.view_error = Some(format!("{error:?}")),
        }

        // What the scheduler executed.
        for message in self.status_receiver.try_iter() {
            let TransactionStatusMessage::Batch((batch, _)) = message else {
                continue;
            };
            if batch.slot != slot {
                continue;
            }
            for ((transaction, commit), index) in batch
                .transactions
                .iter()
                .zip(&batch.commit_results)
                .zip(&batch.transaction_indexes)
            {
                verdict.statuses.push(StatusTx {
                    index: *index,
                    signature: signature_bytes(transaction.signature()),
                    commit: match commit {
                        Ok(committed) => Ok(committed
                            .status
                            .as_ref()
                            .map(|_| ())
                            .map_err(|e| format!("{e:?}"))),
                        Err(error) => Err(format!("{error:?}")),
                    },
                });
            }
        }
        verdict.statuses.sort_by_key(|status| status.index);

        let consistent =
            verdict.view.len() == verdict.statuses.len()
                && verdict.view.iter().zip(&verdict.statuses).enumerate().all(
                    |(i, (view, status))| status.index == i && status.signature == view.signature,
                );
        verdict.executed = consistent.then(|| {
            verdict
                .view
                .iter()
                .zip(&verdict.statuses)
                .map(|(view, status)| ExecutedTx {
                    component_start: view.component_start,
                    entry: view.entry,
                    tx: view.tx,
                    signature: view.signature,
                    wire: view.wire.clone(),
                    commit: status.commit.clone(),
                })
                .collect()
        });
    }
}
