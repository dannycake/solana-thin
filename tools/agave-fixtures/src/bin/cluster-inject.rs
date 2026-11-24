//! Injects hand-built Alpenglow blocks into a running four-validator
//! `LocalCluster` and reports what the live validators do with them.
//!
//! The single-process oracle (`src/oracle.rs`) shows what Agave's blockstore
//! and `process_single_slot` do with a hand-built block in one process. It
//! does not run the live replay stage, turbine, or votor. This binary turns
//! "seen in a single-process replay" into "seen on running validators" for
//! four blocks:
//!
//!   (A) an honest block (control: injection works and the block finalizes);
//!   (B) a legitimate UpdateParent block with an abandoned prefix holding a
//!       transfer X (expected: finalized, X not executed);
//!   (C) the split-header block: a 54-byte header cut 20/34 across shreds 0
//!       and 1, an abandoned prefix with a transfer X, an UpdateParent naming
//!       the SAME parent as the header, then a valid suffix;
//!   (D) the zero-parent ("C2") block, only constructible for a block whose
//!       parent is slot 0 with an all-zero id. Skipped unless the cluster's
//!       first slots make it reachable.
//!
//! How a block is injected:
//!
//! * A fixed leader schedule assigns a recurring window of slots to the 10%
//!   validator, which is then stopped (`exit_node`). Its node keypair is
//!   held, so blocks for those slots can be signed and injected while no
//!   validator produces them.
//! * The parent is a recent frozen bank taken from a running validator's
//!   `BankForks` in this process. The footer's bank hash is settled by
//!   replaying the block against a child of that bank on a scratch
//!   blockstore, exactly as the oracle does but against live state.
//! * The signed shreds are parsed into Agave `Shred`s and sent to every
//!   running validator's TVU with `Cluster::send_shreds_to_validator`, which
//!   is the full pipeline: fetch filter, sigverify, blockstore, replay,
//!   votor.
//!
//! The verdicts are data. Exit status is 0 if the run completed, whatever the
//! validators decided; non-zero only on a harness failure.
//!
//! ```text
//! cluster-inject <out dir>
//! ```

use {
    agave_votor_messages::migration::MigrationStatus,
    serde_json::json,
    solana_core::validator::ValidatorConfig,
    solana_entry::{block_component::BlockComponent, entry::next_versioned_entry},
    solana_hash::Hash,
    solana_keypair::{Keypair, keypair_from_seed},
    solana_leader_schedule::{FixedSchedule, LeaderSchedule, SlotLeader},
    solana_ledger::{
        blockstore::Blockstore,
        blockstore_meta::BlockLocation,
        blockstore_processor::{
            self, BlockstoreProcessorError, ConfirmationProgress, ProcessOptions,
            ReplayVerificationWorkerPool,
        },
        shred::{Shred, wire},
    },
    solana_local_cluster::{
        cluster::Cluster,
        cluster_tests,
        integration_tests::{DEFAULT_NODE_STAKE, ValidatorKeys},
        local_cluster::{ClusterConfig, LocalCluster},
        validator_configs::make_identical_validator_configs,
    },
    solana_message::Message,
    solana_net_utils::SocketAddrSpace,
    solana_pubkey::Pubkey,
    solana_rpc_client::rpc_client::RpcClient,
    solana_runtime::{
        bank::Bank,
        bank_forks::BankForks,
        block_component_processor::BlockComponentProcessor,
        installed_scheduler_pool::{BankWithScheduler, InstalledSchedulerPool, SchedulingContext},
    },
    solana_sha256_hasher::hashv,
    solana_signer::Signer,
    solana_svm_timings::ExecuteTimings,
    solana_system_interface::instruction as system_instruction,
    solana_thin::{
        BlockRef, ClusterParams, Finality, FinalityCert, Limits, ThinClient, TxProof, ValidatorSet,
        VoteAccount,
        prover::{self, BlockData},
        shred::FLAG_DATA_COMPLETE,
        testkit::BlockBuilder,
    },
    solana_transaction::{Transaction, versioned::VersionedTransaction},
    solana_unified_scheduler_pool::DefaultSchedulerPool,
    std::{
        collections::{BTreeMap, HashMap, HashSet},
        env, fmt, fs,
        path::{Path, PathBuf},
        process::exit,
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    },
    tempfile::TempDir,
};

const SLOTS_PER_EPOCH: u64 = 64;
/// Stakes, in `DEFAULT_NODE_STAKE` units: 40%, 30%, 20%, 10%.
const STAKE_SHARES: [u64; 4] = [4, 3, 2, 1];
/// The validator whose leader slots are injected: the 10% one, stopped so no
/// one produces its slots and its stake does not block the other 90% from
/// finalizing what is injected.
const INJECTED_LEADER: usize = 3;
/// A validator that keeps running; its in-process `BankForks` and
/// `Blockstore` are read to settle bank hashes and to see what happened.
const TARGET: usize = 0;
/// Data shreds per FEC set.
const FEC_SET: u32 = 32;

/// The fixed leader schedule: four-slot chunks round-robin, so the injected
/// leader owns one window (slots `12..16`, `28..32`, ...) every sixteen
/// slots. Every window start is a multiple of four, which an UpdateParent
/// marker needs.
fn injected_windows(leaders: &[SlotLeader]) -> (FixedSchedule, Vec<u64>) {
    let chunk = 4usize;
    let rounds = (SLOTS_PER_EPOCH as usize).div_ceil(chunk * leaders.len()) + 1;
    let mut schedule = Vec::new();
    for _ in 0..rounds {
        for leader in leaders {
            for _ in 0..chunk {
                schedule.push(*leader);
            }
        }
    }
    let rotation = chunk * leaders.len();
    let mut windows = Vec::new();
    for round in 0..rounds {
        let start = (round * rotation + INJECTED_LEADER * chunk) as u64;
        windows.push(start);
    }
    (
        FixedSchedule {
            leader_schedule: LeaderSchedule::new_from_schedule(
                schedule,
                std::num::NonZeroUsize::new(1).unwrap(),
            )
            .into(),
        },
        windows,
    )
}

/// Saves `getVoteAccounts` once per epoch, in the form the verifier reads.
/// Lifted from `cluster-run`.
fn record_vote_accounts(rpc: Arc<RpcClient>, out: PathBuf, stop: Arc<AtomicBool>) {
    let mut saved = None;
    while !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(150));
        let Ok(info) = rpc.get_epoch_info() else {
            continue;
        };
        if saved == Some(info.epoch) {
            continue;
        }
        let Ok(votes) = rpc.get_vote_accounts() else {
            continue;
        };
        let accounts: Option<Vec<_>> = votes
            .current
            .iter()
            .chain(votes.delinquent.iter())
            .map(|vote| {
                let vote_pubkey: Pubkey = vote.vote_pubkey.parse().ok()?;
                let node_pubkey: Pubkey = vote.node_pubkey.parse().ok()?;
                let data = rpc.get_account_data(&vote_pubkey).ok()?;
                let bls = (data.len() >= 193
                    && u32::from_le_bytes(data[..4].try_into().unwrap()) == 3
                    && data[144] == 1)
                    .then(|| hex::encode(&data[145..193]));
                Some(json!({
                    "vote_pubkey": hex::encode(vote_pubkey.to_bytes()),
                    "node_pubkey": hex::encode(node_pubkey.to_bytes()),
                    "bls_pubkey": bls,
                    "stake": vote.activated_stake,
                }))
            })
            .collect();
        let (Some(accounts), Ok(after)) = (accounts, rpc.get_epoch_info()) else {
            continue;
        };
        if after.epoch != info.epoch {
            continue;
        }
        let doc = json!({
            "fetched_in_epoch": info.epoch,
            "fetched_at_slot": info.absolute_slot,
            "accounts": accounts,
        });
        let path = out.join(format!("vote-accounts-epoch-{}.json", info.epoch));
        fs::write(path, doc.to_string()).expect("write vote accounts");
        saved = Some(info.epoch);
    }
}

/// One transfer placed in a block, with where its effect would show.
#[derive(Clone)]
#[allow(dead_code)]
struct Payment {
    recipient: Pubkey,
    lamports: u64,
    /// Before an UpdateParent marker: a validator never executes it.
    abandoned: bool,
    signature: [u8; 64],
}

/// The parent a block is built on: a frozen bank held by a running validator.
struct LiveParent {
    slot: u64,
    block_ref: BlockRef,
    bank: Arc<Bank>,
    blockhash: Hash,
}

/// A block built against live state, ready to inject.
struct Built {
    /// Signed shred payloads.
    payloads: Vec<Vec<u8>>,
    /// Every transfer, in order.
    payments: Vec<Payment>,
    /// Shred index replay should start at (after the UpdateParent marker's
    /// FEC set), for the scratch replay.
    replay_start: u64,
    /// The settled bank hash, if a scratch replay produced one.
    bank_hash: Option<Hash>,
    /// What the scratch replay said.
    scratch: String,
}

/// Builds transfers and components against live cluster state.
struct Builder<'a> {
    mint: &'a Keypair,
    shred_version: u16,
    seed: u64,
}

impl Builder<'_> {
    fn recipient(&self, tag: &[u8]) -> Pubkey {
        Pubkey::new_from_array(
            hashv(&[b"cluster-inject", &self.seed.to_le_bytes(), tag]).to_bytes(),
        )
    }

    /// A signed transfer from the mint to a fresh account.
    fn transfer(
        &self,
        tag: &[u8],
        lamports: u64,
        blockhash: Hash,
    ) -> (VersionedTransaction, Pubkey) {
        let to = self.recipient(tag);
        let instruction = system_instruction::transfer(&self.mint.pubkey(), &to, lamports);
        let message = Message::new(&[instruction], Some(&self.mint.pubkey()));
        let tx = VersionedTransaction::from(Transaction::new(&[self.mint], message, blockhash));
        (tx, to)
    }

    fn header(parent: &BlockRef) -> Vec<u8> {
        let component =
            BlockComponent::new_block_header(parent.slot, Hash::new_from_array(parent.id));
        wincode::serialize(&component).expect("header serializes")
    }

    fn update_parent(parent: &BlockRef) -> Vec<u8> {
        use solana_entry::block_component::{UpdateParentV1, VersionedBlockMarker};
        let marker = VersionedBlockMarker::from_update_parent(UpdateParentV1 {
            new_parent_slot: parent.slot,
            new_parent_block_id: Hash::new_from_array(parent.id),
        });
        wincode::serialize(&BlockComponent::new_block_marker(marker))
            .expect("update parent serializes")
    }

    fn footer(bank_hash: Hash, time_nanos: u64) -> Vec<u8> {
        use solana_entry::block_component::{BlockFooterV1, VersionedBlockMarker};
        let marker = VersionedBlockMarker::from_block_footer(BlockFooterV1 {
            bank_hash,
            block_producer_time_nanos: time_nanos,
            block_user_agent: b"agave-fixtures/cluster-inject".to_vec(),
            block_final_cert: None,
            skip_reward_cert: None,
            notar_reward_cert: None,
        });
        wincode::serialize(&BlockComponent::new_block_marker(marker)).expect("footer serializes")
    }

    /// An entry batch of `entries`, each a list of transactions, on `chain`.
    fn batch(chain: &mut Hash, entries: Vec<Vec<VersionedTransaction>>) -> Vec<u8> {
        let entries: Vec<_> = entries
            .into_iter()
            .map(|txs| {
                let entry = next_versioned_entry(chain, 1, txs);
                *chain = entry.hash;
                entry
            })
            .collect();
        let component = BlockComponent::new_entry_batch(entries).expect("non-empty batch");
        wincode::serialize(&component).expect("entry batch serializes")
    }

    fn tick(chain: &mut Hash) -> Vec<u8> {
        let entry = next_versioned_entry(chain, 1, vec![]);
        *chain = entry.hash;
        let component = BlockComponent::new_entry_batch(vec![entry]).expect("tick");
        wincode::serialize(&component).expect("tick serializes")
    }

    /// Shreds `components` for `slot` on `header_parent` and signs every
    /// payload as `leader`. When `split_header_at` is set (case C), the first
    /// component (the header) is cut across shreds 0 and 1 of FEC set 0 by
    /// hand, instead of landing whole in shred 0: that is the split-header
    /// shape, in which the blockstore records no header parent.
    fn shred_and_sign(
        &self,
        slot: u64,
        header_parent: &BlockRef,
        components: &[Vec<u8>],
        split_header_at: Option<usize>,
        leader: &Keypair,
    ) -> Vec<Vec<u8>> {
        let mut builder = BlockBuilder::new(slot, *header_parent, self.shred_version);
        for (index, bytes) in components.iter().enumerate() {
            if index == 0
                && let Some(first) = split_header_at
            {
                // Header bytes cut `first`/rest across shreds 0 and 1, then
                // padded to a full FEC set with DATA_COMPLETE on the last.
                let mut shreds = vec![
                    builder.shred(&bytes[..first]),
                    builder.shred(&bytes[first..]),
                ];
                while !shreds.len().is_multiple_of(FEC_SET as usize) {
                    shreds.push(builder.shred(&[]));
                }
                shreds.last_mut().unwrap().flags |= FLAG_DATA_COMPLETE;
                builder = builder.push_shreds(shreds);
            } else {
                builder = builder.component(bytes);
            }
        }
        let mut payloads = builder.build();
        self.sign(&mut payloads, leader);
        payloads
    }

    fn sign(&self, payloads: &mut [Vec<u8>], leader: &Keypair) {
        let mut signatures: HashMap<Hash, [u8; 64]> = HashMap::new();
        for payload in payloads.iter_mut() {
            let root = wire::get_merkle_root(payload).expect("payload has a Merkle root");
            let signature = signatures.entry(root).or_insert_with(|| {
                let sig = leader.sign_message(root.as_ref());
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(sig.as_ref());
                bytes
            });
            payload[..64].copy_from_slice(signature);
        }
    }
}

/// Replays `payloads` for `slot` against a child of `parent` on a fresh
/// blockstore, so the footer's real bank hash can be read. This is the
/// oracle's `replay`, run against live state instead of the oracle's own
/// banks.
fn scratch_bank_hash(
    parent: &Arc<Bank>,
    leader: SlotLeader,
    slot: u64,
    payloads: &[Vec<u8>],
    migration_status: &MigrationStatus,
    shred_version: u16,
    start: u64,
) -> (Option<Hash>, String) {
    let dir = match TempDir::new() {
        Ok(dir) => dir,
        Err(error) => return (None, format!("scratch tempdir: {error}")),
    };
    let blockstore = match Blockstore::open(dir.path()) {
        Ok(blockstore) => blockstore,
        Err(error) => return (None, format!("scratch blockstore: {error}")),
    };
    let mut shreds = Vec::with_capacity(payloads.len());
    for payload in payloads {
        match Shred::new_from_serialized_shred(payload.clone()) {
            Ok(shred) => shreds.push(shred),
            Err(error) => return (None, format!("shred parse: {error:?}")),
        }
    }
    // Trusted insert: the point is only the bank hash, not the filter.
    if let Err(error) = blockstore.insert_shreds(shreds, true) {
        return (None, format!("scratch insert: {error:?}"));
    }
    if blockstore
        .get_double_merkle_root(slot, BlockLocation::Original)
        .ok()
        .flatten()
        .is_none()
    {
        return (None, "scratch: slot has no double merkle root".into());
    }
    let child = Arc::new(Bank::new_from_parent(parent.clone(), leader, slot));
    blockstore_processor::set_alpenglow_ticks(&child, migration_status);
    // A bank that replays transactions must have a scheduler installed. Take
    // one from a fresh verification pool, as the replay stage does via
    // `BankForks::insert`.
    let pool = DefaultSchedulerPool::new_for_verification(None, None, None, None, None);
    let context = SchedulingContext::new(child.clone());
    let bank = match pool.take_scheduler(context) {
        Some(scheduler) => BankWithScheduler::new(child, Some(scheduler)),
        None => BankWithScheduler::new_without_scheduler(child),
    };
    let mut progress = ConfirmationProgress::new(parent.last_blockhash());
    progress.num_shreds = start;
    let pool = ReplayVerificationWorkerPool::new(2);
    let options = ProcessOptions {
        run_verification: true,
        ..ProcessOptions::default()
    };
    let result = blockstore_processor::process_single_slot(
        &blockstore,
        &bank,
        shred_version,
        &pool,
        &options,
        &mut progress,
        None,
        None,
        None,
        &mut ExecuteTimings::default(),
        migration_status,
    );
    let _ = bank.wait_for_completed_scheduler();
    match result {
        Ok(()) => (Some(bank.hash()), "replayed cleanly".into()),
        Err(BlockstoreProcessorError::BankHashMismatch(_, _expected, computed)) => {
            (Some(computed), "settled from a bank-hash mismatch".into())
        }
        Err(error) => (None, format!("scratch replay failed: {error}")),
    }
}

/// What a running validator did with an injected slot, read from its
/// in-process blockstore and bank forks.
struct Seen {
    inserted: bool,
    full: bool,
    dead: bool,
    deferred: Option<String>,
    block_id: Option<[u8; 32]>,
    frozen_bank: bool,
    bank_hash: Option<Hash>,
    rooted: bool,
    finalized_via: Option<String>,
    x_recipient_balance: Option<u64>,
    suffix_recipient_balance: Option<u64>,
}

impl fmt::Display for Seen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inserted={} full={} dead={} deferred={:?} block_id={:?} frozen_bank={} bank_hash={:?} rooted={} finalized_via={:?}",
            self.inserted,
            self.full,
            self.dead,
            self.deferred,
            self.block_id.map(hex::encode),
            self.frozen_bank,
            self.bank_hash,
            self.rooted,
            self.finalized_via,
        )
    }
}

/// The highest frozen bank a validator holds below `below`, with a block id.
fn recent_parent(forks: &Arc<RwLock<BankForks>>, below: u64) -> Option<LiveParent> {
    let forks = forks.read().unwrap();
    let mut best: Option<Arc<Bank>> = None;
    for (slot, bank) in forks.banks().iter() {
        if *slot < below && bank.is_frozen() && bank.block_id().is_some() {
            if best.as_ref().map(|b| b.slot()).unwrap_or(0) <= *slot {
                best = Some(bank.clone_without_scheduler());
            }
        }
    }
    let bank = best?;
    let id = bank.block_id().unwrap().to_bytes();
    Some(LiveParent {
        slot: bank.slot(),
        block_ref: BlockRef {
            slot: bank.slot(),
            id,
        },
        blockhash: bank.last_blockhash(),
        bank,
    })
}

/// Reads what the target validator did with `slot`.
fn observe(
    target: &solana_core::validator::Validator,
    slot: u64,
    x: Option<Pubkey>,
    suffix: Option<Pubkey>,
    block_id: Option<[u8; 32]>,
) -> Seen {
    let blockstore = &target.blockstore;
    let forks = target.bank_forks.read().unwrap();
    let meta = blockstore.meta(slot).ok().flatten();
    let full = meta.as_ref().map(|m| m.is_full()).unwrap_or(false);
    let inserted = meta.is_some();
    let dead = blockstore.is_dead(slot);
    let observed_id = blockstore
        .get_double_merkle_root(slot, BlockLocation::Original)
        .ok()
        .flatten()
        .map(|h| h.to_bytes());
    let bank = forks.get(slot).filter(|b| b.is_frozen());
    let frozen_bank = bank.is_some();
    let bank_hash = bank.as_ref().map(|b| b.hash());
    let root = forks.root();
    let rooted = root >= slot && blockstore.is_root(slot);
    // Finalized: the validator rooted our slot with our id, or a bank at a
    // descendant is frozen and our slot is its ancestor and rooted.
    let finalized_via = if rooted {
        match (observed_id, block_id) {
            (Some(seen), Some(ours)) if seen == ours => {
                Some(format!("rooted at slot {slot} with our block id"))
            }
            (Some(_), Some(_)) => Some("rooted, but a DIFFERENT block id".into()),
            _ => Some(format!("rooted at slot {slot}")),
        }
    } else {
        None
    };
    // Balances in the best frozen bank that descends from our slot (or the
    // slot's own bank), to see transfer effects.
    let effect_bank = bank.clone().or_else(|| {
        let mut best: Option<Arc<Bank>> = None;
        let mut best_slot = slot;
        for (s, b) in forks.banks().iter() {
            if *s > slot && *s >= best_slot && b.is_frozen() {
                best = Some(b.clone_without_scheduler());
                best_slot = *s;
            }
        }
        best
    });
    let bal =
        |who: Option<Pubkey>| who.and_then(|p| effect_bank.as_ref().map(|b| b.get_balance(&p)));
    Seen {
        inserted,
        full,
        dead,
        deferred: None,
        block_id: observed_id,
        frozen_bank,
        bank_hash,
        rooted,
        finalized_via,
        x_recipient_balance: bal(x),
        suffix_recipient_balance: bal(suffix),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: cluster-inject <out dir>");
        exit(2);
    }
    let out = Path::new(&args[1]);
    fs::create_dir_all(out).expect("create the output directory");

    let keys: Vec<(ValidatorKeys, bool)> = (0..STAKE_SHARES.len())
        .map(|i| {
            (
                ValidatorKeys {
                    node_keypair: Arc::new(keypair_from_seed(&[i as u8 + 1; 32]).unwrap()),
                    vote_keypair: Arc::new(keypair_from_seed(&[i as u8 + 101; 32]).unwrap()),
                },
                true,
            )
        })
        .collect();

    let leaders: Vec<SlotLeader> = keys.iter().map(|(k, _)| SlotLeader::from(k)).collect();
    let (fixed_schedule, windows) = injected_windows(&leaders);

    let mut validator_config = ValidatorConfig::default_for_test();
    validator_config.wait_for_supermajority = Some(0);
    validator_config.fixed_leader_schedule = Some(fixed_schedule);
    let mut config = ClusterConfig {
        validator_configs: make_identical_validator_configs(&validator_config, keys.len()),
        validator_keys: Some(keys.clone()),
        node_stakes: STAKE_SHARES
            .iter()
            .map(|s| s * DEFAULT_NODE_STAKE)
            .collect(),
        slots_per_epoch: SLOTS_PER_EPOCH,
        stakers_slot_offset: SLOTS_PER_EPOCH,
        skip_warmup_slots: true,
        ..ClusterConfig::default()
    };

    let mut cluster = LocalCluster::new_alpenglow(&mut config, SocketAddrSpace::Unspecified);
    let shred_version = cluster.entry_point_info.shred_version();
    let bootstrap = keys[0].0.node_keypair.pubkey();
    let ledger = cluster.ledger_path(&bootstrap);
    let others: Vec<PathBuf> = keys[1..]
        .iter()
        .map(|(k, _)| cluster.ledger_path(&k.node_keypair.pubkey()))
        .collect();
    let funding = cluster.funding_keypair.insecure_clone();
    let injected_leader_key = keys[INJECTED_LEADER].0.node_keypair.insecure_clone();
    let injected_slot_leader = SlotLeader::from(&keys[INJECTED_LEADER].0);
    let injected_leader_pubkey = injected_leader_key.pubkey();
    eprintln!(
        "cluster up, shred version {shred_version}, injected leader {injected_leader_pubkey} (10% stake), injected windows start at {windows:?}"
    );

    let rpc = cluster.build_rpc_client(&bootstrap).expect("rpc client");
    let stop = Arc::new(AtomicBool::new(false));
    let recorder = {
        let (rpc, out, stop) = (rpc.clone(), out.to_path_buf(), stop.clone());
        thread::spawn(move || record_vote_accounts(rpc, out, stop))
    };

    // Let the cluster get going and finalize some slots.
    cluster_tests::spend_and_verify_all_nodes(
        &cluster.entry_point_info,
        &cluster.funding_keypair,
        keys.len(),
        HashSet::new(),
        SocketAddrSpace::Unspecified,
        &cluster_tests::TpuSender::new(),
    );
    cluster.check_for_new_roots(16, "warmup before injection", SocketAddrSpace::Unspecified);

    // Stop the injected leader. Its slots are now nobody's to produce.
    eprintln!("stopping the injected leader {injected_leader_pubkey}");
    let _stopped_info = cluster.exit_node(&injected_leader_pubkey);

    // Running validators, by pubkey, for injection and observation.
    let running: Vec<Pubkey> = keys
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != INJECTED_LEADER)
        .map(|(_, (k, _))| k.node_keypair.pubkey())
        .collect();
    let target_pubkey = keys[TARGET].0.node_keypair.pubkey();

    let report_path = out.join("inject-report.txt");
    let mut report = String::new();
    macro_rules! say {
        ($($arg:tt)*) => {{
            let line = format!($($arg)*);
            eprintln!("{line}");
            report.push_str(&line);
            report.push('\n');
        }};
    }

    say!("== cluster-inject ==");
    say!(
        "shred version {shred_version}, slots/epoch {SLOTS_PER_EPOCH}, injected leader (10%) stopped"
    );
    say!("running validators: {}", running.len());

    // Record the injected slots and their outcomes for the verifier pass.
    let mut injected_cases: Vec<(
        String,
        u64,
        Option<Pubkey>,
        Option<Pubkey>,
        Option<[u8; 32]>,
    )> = Vec::new();

    // Run the cases. Each targets the next available injected window.
    for case in ["A-honest", "B-abandoned-prefix", "C-split-header"] {
        let result = run_case(
            case,
            &cluster,
            &rpc,
            &target_pubkey,
            &running,
            &funding,
            &injected_leader_key,
            injected_slot_leader,
            shred_version,
            &mut |s: String| {
                eprintln!("{s}");
                report.push_str(&s);
                report.push('\n');
            },
        );
        if let Some((slot, x, suffix, block_id)) = result {
            injected_cases.push((case.to_string(), slot, x, suffix, block_id));
        }
    }

    // (D) The zero-parent block needs a parent that is slot 0 with an all-zero
    // id: it must be one of the very first slots and a multiple of four. By
    // the time injection starts the cluster is well past slot 0, so it is not
    // constructible here.
    say!("== case D (zero-parent / C2) ==");
    say!(
        "SKIPPED: a C2 block's parent must be slot 0 with an all-zero id, so the block must be one of the cluster's very first slots (<= a few, and == 0 mod 4). Injection only starts after warmup (slot > 16), so slot 0 is never a reachable parent on a live cluster. Not constructible; see ORACLE-NOTES."
    );

    // Give the cluster a little longer to possibly finalize and to write
    // footers that might certify the injected blocks.
    thread::sleep(Duration::from_secs(4));

    // Final observation + verifier pass, reading the target validator in
    // process.
    let target = cluster.validators[&target_pubkey]
        .validator
        .as_ref()
        .expect("target validator is running");

    say!("== final observations ==");
    for (name, slot, x, suffix, block_id) in &injected_cases {
        let seen = observe(target, *slot, *x, *suffix, *block_id);
        say!("case {name}: slot {slot}: {seen}");
        say!(
            "  X recipient balance {:?} (X is the abandoned-prefix transfer; absent effect means balance 0/None)",
            seen.x_recipient_balance
        );
        say!(
            "  suffix recipient balance {:?} (effect present means non-zero)",
            seen.suffix_recipient_balance
        );
    }

    // Verifier pass: build BlockData for the injected slots and nearby slots
    // from the target validator's blockstore, find a footer certificate, and
    // verify a claim on X and on a suffix transaction. Uses the REAL
    // certificate and REAL validator set (recorded vote accounts).
    say!("== verifier ==");
    verifier_pass(
        target,
        &injected_cases,
        out,
        shred_version,
        &mut |s: String| {
            eprintln!("{s}");
            report.push_str(&s);
            report.push('\n');
        },
    );

    let last = rpc.get_slot().unwrap_or(0);
    say!("cluster at slot {last} at the end");

    stop.store(true, Ordering::Relaxed);
    let _ = recorder.join();

    cluster.close_preserve_ledgers();

    // Move the bootstrap ledger next to the outputs and drop the rest, as
    // cluster-run does.
    let kept = out.join("ledger");
    let _ = fs::remove_dir_all(&kept);
    if let Err(error) = fs::rename(&ledger, &kept) {
        eprintln!("could not move the ledger ({error}); leaving it in place");
    }
    for other in others {
        let _ = fs::remove_dir_all(other);
    }

    fs::write(
        out.join("cluster.json"),
        json!({
            "ledger": kept,
            "shred_version": shred_version,
            "slots_per_epoch": SLOTS_PER_EPOCH,
            "last_slot": last,
            "stake_shares": STAKE_SHARES,
            "injected_leader_index": INJECTED_LEADER,
        })
        .to_string(),
    )
    .expect("write cluster.json");

    fs::write(&report_path, &report).expect("write the report");
    println!("{}", report_path.display());
}

/// Builds and injects one case, waits for the validators to act, and reports.
/// Returns the injected slot and the X and suffix recipients for the final
/// pass.
#[allow(clippy::too_many_arguments)]
fn run_case(
    case: &str,
    cluster: &LocalCluster,
    _rpc: &Arc<RpcClient>,
    target_pubkey: &Pubkey,
    running: &[Pubkey],
    funding: &Keypair,
    leader: &Keypair,
    leader_slot: SlotLeader,
    shred_version: u16,
    say: &mut dyn FnMut(String),
) -> Option<(u64, Option<Pubkey>, Option<Pubkey>, Option<[u8; 32]>)> {
    say(format!("== case {case} =="));
    let seed = 0xC0FFEE ^ (case.len() as u64) ^ case.bytes().map(|b| b as u64).sum::<u64>();
    let builder = Builder {
        mint: funding,
        shred_version,
        seed,
    };

    let target = cluster.validators[target_pubkey]
        .validator
        .as_ref()
        .expect("target is running");
    let forks = target.bank_forks.clone();
    let migration_status = forks.read().unwrap().migration_status();

    // To land on the canonical chain the block's parent must be the current
    // head, and its slot the head's immediate successor. The injected leader
    // owns the window [12..16) of every sixteen-slot rotation, so the moment
    // to inject the window start (`% 16 == 12`) is when the head is the slot
    // just before it (`% 16 == 11`): then nothing is produced for the window
    // and the block, injected at once, races only the skip timeout. A miss
    // (votor skips the slot before the shreds land) is retried at the next
    // window, up to a few times.
    let rotation = 16u64;
    let window_start_offset = 12u64; // INJECTED_LEADER (3) * chunk (4)
    let max_attempts = 4;
    let mut tried_above = 0u64;
    let mut outcome: Option<(u64, Option<Pubkey>, Option<Pubkey>, Option<[u8; 32]>)> = None;

    for attempt in 0..max_attempts {
        // Wait for alignment: head at a slot just before an injected window,
        // and past any slot we already tried.
        let align_deadline = Instant::now() + Duration::from_secs(30);
        let (parent, slot) = loop {
            if Instant::now() > align_deadline {
                say(format!(
                    "  attempt {attempt}: never reached an injected window; stopping"
                ));
                return outcome;
            }
            let Some(head) = recent_parent(&forks, u64::MAX) else {
                thread::sleep(Duration::from_millis(20));
                continue;
            };
            let candidate = head.slot + 1;
            if candidate % rotation == window_start_offset && candidate > tried_above {
                break (head, candidate);
            }
            thread::sleep(Duration::from_millis(15));
        };
        tried_above = slot;

        say(format!(
            "  attempt {attempt}: target slot {slot} (head+1), header parent slot {} (block id {})",
            parent.slot,
            hex::encode(parent.block_ref.id)
        ));

        let built = match build_case(
            case,
            &builder,
            &parent,
            slot,
            leader,
            leader_slot,
            &migration_status,
            shred_version,
        ) {
            Some(built) => built,
            None => {
                say(format!(
                    "  case {case} could not be built against live state; skipping"
                ));
                return outcome;
            }
        };
        say(format!(
            "    built {} shreds, scratch replay: {}, bank hash {:?}, replay_start {}",
            built.payloads.len(),
            built.scratch,
            built.bank_hash,
            built.replay_start,
        ));

        // What the verifier makes of the injected block on its own (the
        // honest-prover view): indexed, or refused and with which error? The
        // UpdateParent and split-header blocks are expected to be refused
        // whole (`UpdateParentBlock` / split header), the soundness property:
        // a claim on X is never provable because the block is never accepted.
        let expected_id = match BlockData::from_shreds(&built.payloads) {
            Ok(block) => {
                say(format!(
                    "    verifier (BlockData::from_shreds on the injected shreds): ACCEPTED, block id {}, {} signature(s)",
                    hex::encode(block.block().id),
                    block.signatures().len()
                ));
                Some(block.block().id)
            }
            Err(error) => {
                say(format!(
                    "    verifier (BlockData::from_shreds on the injected shreds): REFUSED: {error} (a claim on X is therefore unprovable)"
                ));
                None
            }
        };

        let shreds: Vec<Shred> = built
            .payloads
            .iter()
            .filter_map(|p| Shred::new_from_serialized_shred(p.clone()).ok())
            .collect();
        let shred_refs: Vec<&Shred> = shreds.iter().collect();
        // Resend a few times: UDP to the TVU port is lossy, and votor needs
        // the shreds before the skip timeout.
        for round in 0..4 {
            for who in running {
                cluster.send_shreds_to_validator(shred_refs.clone(), who);
            }
            if round < 3 {
                thread::sleep(Duration::from_millis(40));
            }
        }
        say(format!(
            "    injected {} shreds to {} validators (4 rounds)",
            shreds.len(),
            running.len()
        ));

        let x = built
            .payments
            .iter()
            .find(|p| p.abandoned)
            .map(|p| p.recipient);
        let suffix = built
            .payments
            .iter()
            .find(|p| !p.abandoned)
            .map(|p| p.recipient);

        // Watch the target validator react.
        let watch_deadline = Instant::now() + Duration::from_secs(8);
        let mut last_seen = observe(target, slot, x, suffix, expected_id);
        while Instant::now() < watch_deadline {
            let seen = observe(target, slot, x, suffix, expected_id);
            let rooted = seen.rooted;
            last_seen = seen;
            if rooted {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        say(format!("    after injection: {last_seen}"));

        outcome = Some((slot, x, suffix, expected_id));
        if last_seen.rooted {
            say(format!("    rooted on attempt {attempt}"));
            break;
        }
        say(format!(
            "    not rooted on attempt {attempt}; {}",
            if attempt + 1 < max_attempts {
                "retrying at the next window"
            } else {
                "out of attempts"
            }
        ));
    }

    outcome
}

/// Builds the components for a case against the live parent.
fn build_case(
    case: &str,
    builder: &Builder,
    parent: &LiveParent,
    slot: u64,
    leader: &Keypair,
    leader_slot: SlotLeader,
    migration_status: &MigrationStatus,
    shred_version: u16,
) -> Option<Built> {
    let mut chain = parent.blockhash;
    let mut components: Vec<Vec<u8>> = Vec::new();
    let mut payments: Vec<Payment> = Vec::new();
    let mut split_header_at = None;
    let mut replay_start = 0u64;

    // The parent the block ends up on, and whose bank the scratch replay (and
    // the live validator) builds the child on. For a block with an
    // UpdateParent marker it is the marker's parent, not the header's parent.
    let mut replay_parent = parent.bank.clone();
    let mut replay_parent_slot = parent.slot;
    let mut replay_blockhash = parent.blockhash;

    match case {
        "A-honest" => {
            // header, one batch with one transfer (the "suffix"), footer, tick.
            components.push(Builder::header(&parent.block_ref));
            let (tx, to) = builder.transfer(b"A-suffix", 2_000_000, parent.blockhash);
            payments.push(Payment {
                recipient: to,
                lamports: 2_000_000,
                abandoned: false,
                signature: sig_of(&tx),
            });
            components.push(Builder::batch(&mut chain, vec![vec![tx]]));
            components.push(Builder::footer(Hash::default(), 0)); // time filled below
            components.push(Builder::tick(&mut chain));
        }
        "B-abandoned-prefix" | "C-split-header" => {
            // header names the parent; an abandoned batch with transfer X; an
            // UpdateParent marker; a suffix batch; footer; tick. One component
            // per FEC set, so the marker lands in FEC set 2 (shreds 64..95)
            // and replay starts at shred 64 (the corpus `voted(2, 64, 96)`
            // shape).
            //
            // B: the marker names an OLDER ancestor (the parent's parent), the
            //    legitimate fast-leader-handover case; the block ends up on
            //    that ancestor.
            // C: the header is split 20/34 across shreds 0 and 1, and the
            //    marker names the SAME parent as the header (the split-header
            //    bug): the blockstore records no header parent, so the marker
            //    is not compared with it.
            let header_parent = parent.block_ref;
            let marker_parent = if case == "B-abandoned-prefix" {
                match ancestor_of(parent) {
                    Some((reference, bank)) => {
                        replay_parent = bank.clone();
                        replay_parent_slot = reference.slot;
                        replay_blockhash = bank.last_blockhash();
                        reference
                    }
                    None => {
                        // No older ancestor held: fall back to the header's
                        // parent. Agave refuses this at insert
                        // (UpdateParentMatchesBlockHeader); the report captures
                        // it.
                        parent.block_ref
                    }
                }
            } else {
                // C: marker names the same parent as the header.
                parent.block_ref
            };

            components.push(Builder::header(&header_parent));
            // Abandoned prefix: transfer X, chained on the header parent.
            let (txx, tox) = builder.transfer(b"X-abandoned", 3_000_000, parent.blockhash);
            payments.push(Payment {
                recipient: tox,
                lamports: 3_000_000,
                abandoned: true,
                signature: sig_of(&txx),
            });
            components.push(Builder::batch(&mut chain, vec![vec![txx]]));
            // The UpdateParent marker: entries after it are chained on the
            // marker parent's bank, so restart the hash chain from it.
            components.push(Builder::update_parent(&marker_parent));
            chain = replay_blockhash;
            let (txs, tos) = builder.transfer(b"S-suffix", 2_000_000, replay_blockhash);
            payments.push(Payment {
                recipient: tos,
                lamports: 2_000_000,
                abandoned: false,
                signature: sig_of(&txs),
            });
            components.push(Builder::batch(&mut chain, vec![vec![txs]]));
            components.push(Builder::footer(Hash::default(), 0));
            components.push(Builder::tick(&mut chain));

            replay_start = 64;
            if case == "C-split-header" {
                split_header_at = Some(20);
            }
        }
        _ => return None,
    }

    // Footer time is read from the replay parent (the bank the child is built
    // on), as the oracle does.
    let footer_time = footer_time(&replay_parent, replay_parent_slot, slot);
    let footer_index = components.len() - 2;
    components[footer_index] = Builder::footer(Hash::default(), footer_time);

    // First pass: shred and sign with a placeholder footer hash.
    let payloads = builder.shred_and_sign(
        slot,
        &parent.block_ref,
        &components,
        split_header_at,
        leader,
    );

    // Settle the footer bank hash by replaying against a child of the replay
    // parent on a scratch blockstore.
    let (bank_hash, scratch) = scratch_bank_hash(
        &replay_parent,
        leader_slot,
        slot,
        &payloads,
        migration_status,
        shred_version,
        replay_start,
    );

    // Rebuild the footer with the settled hash, if we got one.
    let (payloads, bank_hash, scratch) = if let Some(hash) = bank_hash {
        components[footer_index] = Builder::footer(hash, footer_time);
        let payloads = builder.shred_and_sign(
            slot,
            &parent.block_ref,
            &components,
            split_header_at,
            leader,
        );
        (payloads, Some(hash), format!("{scratch} (footer rebuilt)"))
    } else {
        (payloads, None, scratch)
    };

    Some(Built {
        payloads,
        payments,
        replay_start,
        bank_hash,
        scratch,
    })
}

/// The parent's own parent, as a `BlockRef` and its bank, if the validator
/// still holds it frozen with an id. The older ancestor an UpdateParent names
/// in case B.
fn ancestor_of(parent: &LiveParent) -> Option<(BlockRef, Arc<Bank>)> {
    let grandparent = parent.bank.parent()?;
    if !grandparent.is_frozen() {
        return None;
    }
    let id = grandparent.block_id()?.to_bytes();
    let reference = BlockRef {
        slot: grandparent.slot(),
        id,
    };
    Some((reference, grandparent))
}

/// The midpoint of the footer clock bounds for `slot` built on `parent`,
/// from Agave's own `nanosecond_time_bounds`. Mirrors `Oracle::footer_time`.
fn footer_time(parent: &Arc<Bank>, parent_slot: u64, slot: u64) -> u64 {
    let parent_nanos = parent
        .get_nanosecond_clock()
        .unwrap_or_else(|| parent.clock().unix_timestamp.saturating_mul(1_000_000_000));
    let elapsed = parent.slot_range_duration_nanos(parent_slot + 1, slot);
    let (low, high) = BlockComponentProcessor::nanosecond_time_bounds(parent_nanos, elapsed);
    let mid = low + (high - low) / 2;
    u64::try_from(mid).unwrap_or(0)
}

fn sig_of(tx: &VersionedTransaction) -> [u8; 64] {
    tx.signatures[0].into()
}

/// Builds `BlockData` for the injected slots and the slots around them from
/// the target validator's blockstore, finds a footer finality certificate,
/// and verifies a claim on X and on a suffix transaction with the REAL
/// certificate and the REAL validator set.
fn verifier_pass(
    target: &solana_core::validator::Validator,
    injected: &[(
        String,
        u64,
        Option<Pubkey>,
        Option<Pubkey>,
        Option<[u8; 32]>,
    )],
    out: &Path,
    shred_version: u16,
    say: &mut dyn FnMut(String),
) {
    let blockstore = &target.blockstore;
    let root = target.bank_forks.read().unwrap().root();

    // Read shreds for a window of slots covering the injected ones and later
    // ones (which may carry certificates).
    let min = injected.iter().map(|c| c.1).min().unwrap_or(0);
    let max = root.max(injected.iter().map(|c| c.1).max().unwrap_or(0) + 64);
    let mut blocks: BTreeMap<u64, BlockData> = BTreeMap::new();
    for slot in min.saturating_sub(2)..=max {
        let Ok(shreds) = blockstore.get_data_shreds_for_slot(slot, 0) else {
            continue;
        };
        if shreds.is_empty() {
            continue;
        }
        let payloads: Vec<Vec<u8>> = shreds.iter().map(|s| s.payload().to_vec()).collect();
        if let Ok(block) = BlockData::from_shreds(&payloads) {
            blocks.insert(slot, block);
        }
    }
    say(format!(
        "  indexed {} blocks from the target blockstore",
        blocks.len()
    ));

    // Build the verifier with the recorded validator set(s).
    let mut params = ClusterParams::mainnet(shred_version);
    params.slots_per_epoch = SLOTS_PER_EPOCH;
    let mut client = ThinClient::new(params);
    // Load every recorded epoch set.
    let mut any_set = false;
    for epoch in 0..16u64 {
        let path = out.join(format!("vote-accounts-epoch-{epoch}.json"));
        if !path.exists() {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let accounts = parse_vote_accounts(&doc);
        if let Ok(set) = ValidatorSet::from_vote_accounts(&accounts) {
            let hash = set.hash();
            // The set fetched in epoch E governs E + 1.
            let _ = client.trust_validator_set(epoch, set.clone(), &hash);
            let _ = client.trust_validator_set(epoch + 1, set, &hash);
            any_set = true;
        }
    }
    if !any_set {
        say("  no recorded validator set; verifier cannot check certificates".into());
        return;
    }

    // Collect footer certificates.
    let mut certs: BTreeMap<u64, FinalityCert> = BTreeMap::new();
    for (slot, block) in &blocks {
        let Some((_, footer)) = block.footer() else {
            continue;
        };
        let Some(cert) = footer.finality else {
            continue;
        };
        match client.verify_finality(&cert) {
            Ok(finalized) => {
                certs.entry(finalized.block.slot).or_insert(cert);
            }
            Err(error) => {
                say(format!("  footer cert in slot {slot} rejected: {error}"));
            }
        }
    }
    say(format!(
        "  {} verified footer certificate(s) found",
        certs.len()
    ));

    // For each injected case, try to prove X and a suffix transaction.
    for (name, slot, x, _suffix, _id) in injected {
        say(format!("  case {name} (slot {slot}):"));
        let Some(block) = blocks.get(slot) else {
            say(format!(
                "    no indexed block at slot {slot}; nothing to prove"
            ));
            continue;
        };
        let signatures = block.signatures();
        say(format!(
            "    block carries {} transaction signature(s)",
            signatures.len()
        ));
        // Find the nearest certificate at or after this slot.
        let Some((&certified, cert)) = certs.range(*slot..).next() else {
            say(format!(
                "    no finality certificate at or after slot {slot}: block not finalized on the live cluster, so the verifier has no real certificate to check (expected if the injected block did not finalize)"
            ));
            let _ = x;
            continue;
        };
        // Build the ancestry chain from the certified block down to ours.
        let mut chain = vec![&blocks[&certified]];
        while chain.last().unwrap().block().slot != *slot {
            let p = chain.last().unwrap().parent();
            match blocks.get(&p.slot) {
                Some(b) if p.slot >= *slot => chain.push(b),
                _ => break,
            }
        }
        if chain.last().unwrap().block().slot != *slot {
            say(format!(
                "    slot {slot} is not an ancestor of certified slot {certified}; cannot prove"
            ));
            continue;
        }
        for signature in signatures.iter() {
            let result = prover::prove(cert.clone(), &chain, signature, true).and_then(|proof| {
                let bytes = proof.to_bytes();
                let decoded = TxProof::from_bytes(&bytes, &Limits::default())?;
                let verified = client.verify_signature(&decoded, signature)?;
                Ok((bytes.len(), verified))
            });
            match result {
                Ok((size, verified)) => {
                    let fin = match verified.finalized_by.finality {
                        Finality::Fast => "fast",
                        Finality::Slow => "slow",
                    };
                    say(format!(
                        "    proved {}... via a {fin} certificate on slot {certified}, {size} bytes",
                        hex::encode(&signature[..6])
                    ));
                }
                Err(error) => {
                    say(format!(
                        "    {}...: verifier refused: {error}",
                        hex::encode(&signature[..6])
                    ));
                }
            }
        }
    }
}

fn parse_vote_accounts(doc: &serde_json::Value) -> Vec<VoteAccount> {
    let hex32 = |v: &serde_json::Value| -> [u8; 32] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    doc["accounts"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|a| VoteAccount {
                    vote_pubkey: hex32(&a["vote_pubkey"]),
                    node_pubkey: hex32(&a["node_pubkey"]),
                    bls_pubkey: a["bls_pubkey"]
                        .as_str()
                        .map(|s| hex::decode(s).unwrap().try_into().unwrap()),
                    stake: a["stake"].as_u64().unwrap(),
                })
                .collect()
        })
        .unwrap_or_default()
}
