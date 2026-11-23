//! Runs a four-validator Alpenglow cluster in this process and leaves its
//! ledger behind for `ledger-dump`.
//!
//! `solana-test-validator` has one signer, so its certificates say nothing
//! about aggregation or thresholds. This uses Agave's own `LocalCluster`:
//! four real validators with 40%, 30%, 20% and 10% of stake, voting over the
//! loopback network.
//!
//! 1. All four online: blocks finalize fast (80% or more notarize).
//! 2. The 30% validator is stopped: 70% remains, which is enough to finalize
//!    but only by the slow path, and its leader slots are skipped.
//!
//! ```text
//! cluster-run <out dir>
//! ```
//!
//! Epochs are 64 slots, and stake moves at every boundary because voting
//! validators earn rewards and the stopped one does not. So the run also
//! shows which epoch's stake a certificate is checked against.
//!
//! Writes to `<out dir>`:
//!
//! * `vote-accounts-epoch-<E>.json`: `getVoteAccounts` as seen during epoch
//!   `E`, one file per epoch, in the form `ValidatorSet::from_vote_accounts`
//!   takes;
//! * `ledger/`: the bootstrap validator's ledger, for `ledger-dump`;
//! * `cluster.json`: shred version, epoch length, the slot at which the
//!   validator was stopped.

use {
    serde_json::json,
    solana_core::validator::ValidatorConfig,
    solana_keypair::{Keypair, keypair_from_seed},
    solana_local_cluster::{
        cluster::Cluster,
        cluster_tests,
        integration_tests::{DEFAULT_NODE_STAKE, ValidatorKeys},
        local_cluster::{ClusterConfig, LocalCluster},
        validator_configs::make_identical_validator_configs,
    },
    solana_net_utils::SocketAddrSpace,
    solana_rpc_client::rpc_client::RpcClient,
    solana_signer::Signer,
    std::{
        collections::HashSet,
        env, fs,
        path::{Path, PathBuf},
        process::exit,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    },
};

const SLOTS_PER_EPOCH: u64 = 64;
const STAKE_SHARES: [u64; 4] = [4, 3, 2, 1];
/// Which validator is stopped for the second phase: the one with 30%.
const STOPPED: usize = 1;

/// Saves `getVoteAccounts` once per epoch until told to stop.
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
                let vote_pubkey: solana_pubkey::Pubkey = vote.vote_pubkey.parse().ok()?;
                let node_pubkey: solana_pubkey::Pubkey = vote.node_pubkey.parse().ok()?;
                let data = rpc.get_account_data(&vote_pubkey).ok()?;
                // VoteStateV4: a u32 version tag of 3, then Option<[u8; 48]> at byte 144.
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
        // The epoch may have turned between the two calls. Keep the file only
        // if it did not.
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: cluster-run <out dir>");
        exit(2);
    }
    let out = Path::new(&args[1]);
    fs::create_dir_all(out).expect("create the output directory");

    let keys: Vec<(ValidatorKeys, bool)> = (0..STAKE_SHARES.len())
        .map(|i| {
            (
                ValidatorKeys {
                    node_keypair: Arc::new(keypair_from_seed(&[i as u8 + 1; 32]).unwrap()),
                    vote_keypair: Arc::new(Keypair::new()),
                },
                true,
            )
        })
        .collect();
    let mut validator_config = ValidatorConfig::default_for_test();
    validator_config.wait_for_supermajority = Some(0);
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
    let bootstrap = keys[0].0.node_keypair.pubkey();
    let shred_version = cluster.entry_point_info.shred_version();
    let ledger = cluster.ledger_path(&bootstrap);
    // Taken now: a stopped validator is forgotten by the cluster.
    let others: Vec<PathBuf> = keys[1..]
        .iter()
        .map(|(k, _)| cluster.ledger_path(&k.node_keypair.pubkey()))
        .collect();
    eprintln!("cluster up, shred version {shred_version}");

    // The validator set, as an RPC client would fetch it, every epoch.
    let rpc = cluster.build_rpc_client(&bootstrap).expect("rpc client");
    let stop = Arc::new(AtomicBool::new(false));
    let recorder = {
        let (rpc, out, stop) = (rpc.clone(), out.to_path_buf(), stop.clone());
        thread::spawn(move || record_vote_accounts(rpc, out, stop))
    };

    // ---- Phase 1: everyone votes.
    cluster_tests::spend_and_verify_all_nodes(
        &cluster.entry_point_info,
        &cluster.funding_keypair,
        keys.len(),
        HashSet::new(),
        SocketAddrSpace::Unspecified,
        &cluster_tests::TpuSender::new(),
    );
    cluster.check_for_new_roots(
        3 * SLOTS_PER_EPOCH as usize,
        "all online",
        SocketAddrSpace::Unspecified,
    );

    // ---- Phase 2: 30% of stake goes away. 70% is short of fast finality.
    let stopped_at = rpc.get_slot().expect("getSlot");
    let stopped = keys[STOPPED].0.node_keypair.pubkey();
    eprintln!("stopping the 30% validator at slot {stopped_at}");
    cluster.exit_node(&stopped);
    cluster_tests::spend_and_verify_all_nodes(
        &cluster.entry_point_info,
        &cluster.funding_keypair,
        keys.len() - 1,
        HashSet::from([stopped]),
        SocketAddrSpace::Unspecified,
        &cluster_tests::TpuSender::new(),
    );
    cluster.check_for_new_roots(
        4 * SLOTS_PER_EPOCH as usize,
        "one offline",
        SocketAddrSpace::Unspecified,
    );
    let last = rpc.get_slot().expect("getSlot");
    stop.store(true, Ordering::Relaxed);
    recorder.join().expect("recorder");

    cluster.close_preserve_ledgers();

    // LocalCluster puts ledgers beside its own source file. Keep the
    // bootstrap validator's, next to the other outputs, and drop the rest.
    let kept = out.join("ledger");
    let _ = fs::remove_dir_all(&kept);
    fs::rename(&ledger, &kept).expect("move the ledger (same filesystem as the Agave checkout?)");
    for other in others {
        let _ = fs::remove_dir_all(other);
    }

    fs::write(
        out.join("cluster.json"),
        json!({
            "ledger": kept,
            "shred_version": shred_version,
            "slots_per_epoch": SLOTS_PER_EPOCH,
            "stopped_at_slot": stopped_at,
            "last_slot": last,
            "stake_shares": STAKE_SHARES,
        })
        .to_string(),
    )
    .expect("write cluster.json");
    println!("{}", kept.display());
}
