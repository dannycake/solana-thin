//! Differential testing of solana-thin against Agave.
//!
//! `diff-fuzz --smoke` builds one honest block, has Agave judge it, and
//! checks that the light client reads the same block out of the same shreds.
//! It then asks Agave a few questions about shred layout whose answers the
//! full oracle depends on, and prints them.
//!
//! Exit status is non-zero if any `CHECK` line fails. `ANSWER` lines report
//! what Agave did and never fail the run.
//!
//! The other modes run the full harness (`agave_fixtures::harness`), each in
//! two worlds, fast leader handover on and off:
//!
//! * `--corpus [DUMP_DIR]` runs every named case and prints a table.
//! * `--random N --seed S` runs N generated cases, cycling through the
//!   mutator families.
//! * `--emit DIR` writes the corpus as frozen vectors for the main
//!   workspace's `tests/oracle_corpus.rs`.
//!
//! They exit non-zero on any P0, P1, P2 or premise violation, and when a
//! mutator family that should be able to get Agave's vote never did.

use {
    agave_fixtures::{
        corpus::{Tally, check_floors, corpus, generate},
        harness::{Case, Item, Outcome, UPSTREAM_ORDER, World, freeze},
        oracle::{
            AbandonedPrefix, FEC_SET, HonestBlock, HonestSpec, JudgeOptions, Oracle, OracleConfig,
            Replay, Verdict, set_layout, split_first,
        },
    },
    solana_hash::Hash,
    solana_thin::{BlockRef, prover::BlockData},
    solana_transaction::versioned::VersionedTransaction,
    std::{
        collections::{BTreeMap, BTreeSet},
        path::{Path, PathBuf},
        process::ExitCode,
        time::Instant,
    },
};

/// First slot of epoch 1 with the default 32-slot epochs: the first slot
/// where shred rules gated on a genesis-activated feature apply.
const PARENT_SLOT: u64 = 32;
/// The slot under test: epoch 1, first slot of a leader window, so an
/// UpdateParent marker would be legal in it.
const TEST_SLOT: u64 = 36;

struct Checks {
    failed: usize,
}

impl Checks {
    fn check(&mut self, what: &str, ok: bool) {
        println!("CHECK {} {what}", if ok { "ok  " } else { "FAIL" });
        if !ok {
            self.failed += 1;
        }
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

fn short(signature: &[u8; 64]) -> String {
    hex(&signature[..6])
}

/// Builds an honest block for `spec`, finding its bank hash in two passes.
fn honest(oracle: &Oracle, mut spec: HonestSpec) -> (HonestBlock, Vec<Vec<u8>>, Verdict) {
    let (computed, first) = oracle.settle_bank_hash(&spec);
    let Some(bank_hash) = computed else {
        panic!(
            "pass 1 for slot {} did not stop at a bank hash mismatch:\n{first}",
            spec.slot
        );
    };
    spec.bank_hash = bank_hash;
    let block = oracle.build_honest(&spec);
    let payloads = oracle.shred_and_sign(block.slot, block.parent, &block.components);
    let verdict = oracle.judge(block.slot, &payloads);
    (block, payloads, verdict)
}

/// Judges a block on [`PARENT_SLOT`] at [`TEST_SLOT`] holding exactly these
/// transactions, settling the bank hash in a second pass if the first one
/// gets that far.
fn judge_transactions(oracle: &Oracle, batches: &[Vec<Vec<VersionedTransaction>>]) -> Verdict {
    let build = |bank_hash: Hash| {
        let parent = oracle.block_ref(PARENT_SLOT);
        let mut chain = oracle.last_blockhash(PARENT_SLOT);
        let mut components = vec![Oracle::header_bytes(&parent)];
        for batch in batches {
            components.push(Oracle::entry_batch_bytes(&mut chain, batch.clone()));
        }
        components.push(Oracle::footer_bytes(
            bank_hash,
            oracle.footer_time(PARENT_SLOT, TEST_SLOT),
        ));
        components.push(Oracle::entry_batch_bytes(&mut chain, vec![vec![]]));
        oracle.shred_and_sign(TEST_SLOT, parent, &components)
    };
    let first = oracle.judge(TEST_SLOT, &build(Hash::default()));
    match &first.replay {
        Replay::Failed {
            bank_hash_mismatch: Some((_, computed)),
            ..
        } => oracle.judge(TEST_SLOT, &build(*computed)),
        _ => first,
    }
}

/// Judges the same shreds in other arrival orders and reports whether the
/// verdict moves. This is a preview of the full oracle's order property, on
/// one block; it reports and does not fail the run.
fn arrival_orders(oracle: &Oracle, what: &str, payloads: &[Vec<u8>], forward: &Verdict) {
    let mut reversed = payloads.to_vec();
    reversed.reverse();
    let mut shuffled = payloads.to_vec();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for i in (1..shuffled.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        shuffled.swap(i, (state >> 33) as usize % (i + 1));
    }
    let whole = JudgeOptions::default();
    let single = JudgeOptions {
        batch: Some(1),
        ..JudgeOptions::default()
    };
    let mut moved = Vec::new();
    let cases = [
        ("reversed, one insert call", &reversed, &whole),
        ("shuffled, one insert call", &shuffled, &whole),
        ("forward, one shred per call", &payloads.to_vec(), &single),
        ("reversed, one shred per call", &reversed, &single),
        ("shuffled, one shred per call", &shuffled, &single),
    ];
    for (name, shreds, options) in cases {
        let other = oracle.judge_with(forward.slot, shreds, options);
        if other.order_independent() != forward.order_independent() {
            println!("       {what}, {name}: verdict DIFFERS from forward:\n{other}");
            moved.push(name);
        }
    }
    println!(
        "ANSWER order, {what}: reversed and shuffled, in one insert call and one shred per call: \
         {}",
        if moved.is_empty() {
            "same verdict as forward in all 5".to_string()
        } else {
            format!("verdict moved in {moved:?}")
        },
    );
}

/// Shred index each component starts at in the plain layout.
fn component_starts(payloads: &[Vec<u8>], components: &[Vec<u8>]) -> Vec<u32> {
    let data = BlockData::from_shreds(payloads).expect("honest block indexes");
    let starts: Vec<u32> = data.components().map(|(start, _)| start).collect();
    assert_eq!(starts.len(), components.len());
    starts
}

fn smoke() -> ExitCode {
    let mut checks = Checks { failed: 0 };
    let started = Instant::now();
    let oracle = Oracle::new(OracleConfig::default());
    println!(
        "oracle: genesis {} shred version {} leader {} fast leader handover {} ({:.0} ms)",
        oracle.genesis_hash(),
        oracle.config().shred_version,
        oracle.leader(),
        oracle.fast_leader_handover(),
        started.elapsed().as_secs_f64() * 1e3,
    );

    println!(
        "shred-level Alpenglow rules: slot 31 {}, slot {PARENT_SLOT} {}, slot {TEST_SLOT} {}",
        oracle.alpenglow_shred_rules(31),
        oracle.alpenglow_shred_rules(PARENT_SLOT),
        oracle.alpenglow_shred_rules(TEST_SLOT),
    );
    checks.check(
        "test slots are past the one-epoch delay of shred rules",
        !oracle.alpenglow_shred_rules(31)
            && oracle.alpenglow_shred_rules(PARENT_SLOT)
            && oracle.alpenglow_shred_rules(TEST_SLOT),
    );

    // A parent with a real block id, so the defer rule has something to
    // compare against. Its own parent is genesis.
    println!("\n== parent block, slot {PARENT_SLOT} on genesis ==");
    let (_, _, parent_verdict) = honest(
        &oracle,
        HonestSpec {
            slot: PARENT_SLOT,
            parent_slot: 0,
            batches: vec![vec![1]],
            bank_hash: Hash::default(),
            seed: 0,
            abandoned: None,
        },
    );
    println!("{parent_verdict}");
    checks.check("parent block voted", parent_verdict.voted);
    if !parent_verdict.voted {
        return ExitCode::FAILURE;
    }
    let parent = oracle.block_ref(PARENT_SLOT);
    checks.check(
        "parent bank carries the blockstore's block id",
        Some(Hash::new_from_array(parent.id)) == parent_verdict.block_id,
    );

    // The block under test.
    println!("\n== honest block, slot {TEST_SLOT} on {PARENT_SLOT} ==");
    let spec = HonestSpec {
        slot: TEST_SLOT,
        parent_slot: PARENT_SLOT,
        batches: vec![vec![2, 1, 2], vec![1, 3]],
        bank_hash: Hash::default(),
        seed: 1,
        abandoned: None,
    };
    let (computed, first) = oracle.settle_bank_hash(&spec);
    println!("pass 1 (placeholder bank hash):\n{first}");
    let Some(bank_hash) = computed else {
        checks.check("pass 1 stops at a bank hash mismatch", false);
        return ExitCode::FAILURE;
    };
    checks.check("pass 1 stops at a bank hash mismatch", true);
    checks.check("pass 1 leaves the slot dead", first.dead && !first.voted);

    let spec = HonestSpec { bank_hash, ..spec };
    let block = oracle.build_honest(&spec);
    let payloads = oracle.shred_and_sign(block.slot, block.parent, &block.components);
    let verdict = oracle.judge(TEST_SLOT, &payloads);
    println!("pass 2 (bank hash {bank_hash}):\n{verdict}");

    checks.check(
        "every shred passes filter, sigverify and parse",
        verdict.shreds.iter().all(|s| s.accepted()),
    );
    checks.check(
        "insert raised no error and no duplicate",
        verdict.insert_error.is_none() && verdict.duplicates.is_empty(),
    );
    checks.check("voted", verdict.voted);
    checks.check(
        "bank hash is the footer's",
        verdict.bank_hash == Some(bank_hash),
    );

    // The light client, on the same shreds.
    let data = match BlockData::from_shreds(&payloads) {
        Ok(data) => data,
        Err(error) => {
            println!("light client: {error:?}");
            checks.check("light client indexes the block", false);
            return ExitCode::FAILURE;
        }
    };
    println!(
        "block id: agave {} light client {}",
        verdict.block_id.map(hex).unwrap_or_else(|| "none".into()),
        hex(data.block().id),
    );
    checks.check(
        "block id: light client equals Agave's double merkle root",
        verdict.block_id.map(|id| id.to_bytes()) == Some(data.block().id),
    );
    println!(
        "parent: agave {:?} light client {:?} built {:?}",
        verdict.parent().map(|p| (p.slot, hex(p.id))),
        (data.parent().slot, hex(data.parent().id)),
        (block.parent.slot, hex(block.parent.id)),
    );
    checks.check(
        "parent: light client equals Agave's slot meta",
        verdict.parent() == Some(data.parent()),
    );
    checks.check(
        "parent: is the parent bank's block",
        data.parent() == parent,
    );

    let starts = component_starts(&payloads, &block.components);
    println!("executed (component start, entry, tx, signature, commit) vs built:");
    let executed = verdict.executed.clone().unwrap_or_default();
    for (i, built) in block.transactions.iter().enumerate() {
        let agave = executed.get(i);
        println!(
            "  built ({:>3},{},{}) {}   agave {}",
            starts[built.component],
            built.entry,
            built.tx,
            short(&built.signature),
            match agave {
                Some(tx) => format!(
                    "({:>3},{},{}) {} {:?}",
                    tx.component_start,
                    tx.entry,
                    tx.tx,
                    short(&tx.signature),
                    tx.commit
                ),
                None => "missing".into(),
            },
        );
    }
    checks.check(
        "executed: status drain and replay's component view agree",
        verdict.executed.is_some(),
    );
    checks.check(
        "executed: equals what was built, coordinates included",
        executed.len() == block.transactions.len()
            && executed.iter().zip(&block.transactions).all(|(a, b)| {
                (a.component_start, a.entry, a.tx, a.signature)
                    == (starts[b.component], b.entry, b.tx, b.signature)
            }),
    );
    checks.check(
        "executed: every transaction committed successfully",
        executed.iter().all(|tx| tx.commit == Ok(Ok(()))),
    );
    let bank = oracle.bank(TEST_SLOT).expect("voted bank is held");
    checks.check(
        "executed: every recipient holds its transfer in the frozen bank",
        block
            .transactions
            .iter()
            .all(|tx| bank.get_balance(&tx.recipient) == tx.lamports),
    );
    drop(bank);
    let built: Vec<[u8; 64]> = block.transactions.iter().map(|tx| tx.signature).collect();
    checks.check(
        "light client signatures equal Agave's executed list, in order",
        data.signatures() == executed.iter().map(|tx| tx.signature).collect::<Vec<_>>()
            && data.signatures() == built,
    );
    let honest_view = verdict.order_independent();

    // (ii) Data-only FEC sets.
    println!("\n== questions ==");
    println!(
        "ANSWER (ii) data-only FEC sets (no coding shreds inserted): full={} block id {}",
        verdict.meta.as_ref().is_some_and(|m| m.full),
        if verdict.block_id.is_some() {
            "present"
        } else {
            "absent"
        },
    );

    // P0 preview: arrival order.
    arrival_orders(&oracle, "honest block", &payloads, &verdict);

    // (i) Is the bank hash independent of shred layout? Same component
    // bytes, same footer, but the first entry batch's first shred carries
    // only 100 bytes and the rest moves into the shreds after it.
    let mut builder = oracle.shred(block.slot, block.parent, &block.components);
    let batch = &block.components[1];
    set_layout(&mut builder, starts[1], &split_first(batch, 100));
    let mut relaid = builder.build();
    oracle.sign(&mut relaid);
    let moved = relaid
        .iter()
        .zip(&payloads)
        .filter(|(a, b)| a[64..] != b[64..])
        .count();
    let relaid_verdict = oracle.judge(TEST_SLOT, &relaid);
    println!(
        "ANSWER (i) re-split of the first entry batch ({} bytes, first shred cut to 100; {moved} \
         payloads differ): voted={} bank hash {} block id {}",
        batch.len(),
        relaid_verdict.voted,
        match relaid_verdict.bank_hash {
            Some(hash) if hash == bank_hash => "unchanged".to_string(),
            Some(hash) => format!("CHANGED to {hash}"),
            None => "none".to_string(),
        },
        match (relaid_verdict.block_id, verdict.block_id) {
            (Some(a), Some(b)) if a == b => "unchanged",
            (Some(_), _) => "changed",
            (None, _) => "none",
        },
    );
    if !relaid_verdict.voted {
        println!("{relaid_verdict}");
    }
    let relaid_data = BlockData::from_shreds(&relaid);
    println!(
        "       light client on the re-split block: {}",
        match &relaid_data {
            Ok(data) => format!(
                "block id {} Agave's, signatures {} Agave's",
                if Some(data.block().id) == relaid_verdict.block_id.map(|id| id.to_bytes()) {
                    "equals"
                } else {
                    "DIFFERS from"
                },
                if Some(data.signatures())
                    == relaid_verdict
                        .executed
                        .as_ref()
                        .map(|list| list.iter().map(|tx| tx.signature).collect::<Vec<_>>())
                {
                    "equal"
                } else {
                    "DIFFER from"
                },
            ),
            Err(error) => format!("refused: {error:?}"),
        },
    );

    // (iv) The split header: the header's 54 bytes cut 20/34 across shreds
    // 0 and 1, everything else honest.
    let header = &block.components[0];
    let mut builder = oracle.shred(block.slot, block.parent, &block.components);
    set_layout(&mut builder, 0, &[&header[..20], &header[20..]]);
    let mut split = builder.build();
    oracle.sign(&mut split);
    let split_verdict = oracle.judge(TEST_SLOT, &split);
    println!(
        "ANSWER (iv) split header ({} bytes cut 20/{}): voted={} replay={:?}",
        header.len(),
        header.len() - 20,
        split_verdict.voted,
        split_verdict.replay,
    );
    println!("{split_verdict}");
    println!(
        "       light client on the split-header block: {}",
        match BlockData::from_shreds(&split) {
            Ok(data) => format!(
                "indexes it; block id {} Agave's; parent {:?}",
                if Some(data.block().id) == split_verdict.block_id.map(|id| id.to_bytes()) {
                    "equals"
                } else {
                    "DIFFERS from"
                },
                (data.parent().slot, hex(data.parent().id)),
            ),
            Err(error) => format!("refused: {error:?}"),
        },
    );
    let zero_parent = BlockRef {
        slot: PARENT_SLOT,
        id: [0; 32],
    };
    println!(
        "       block id with a zero parent id (what Agave's slot meta holds): {}",
        match BlockData::from_shreds_with_final_parent(&split, zero_parent) {
            Ok(data) => format!(
                "{} Agave's",
                if Some(data.block().id) == split_verdict.block_id.map(|id| id.to_bytes()) {
                    "equals"
                } else {
                    "DIFFERS from"
                }
            ),
            Err(error) => format!("refused: {error:?}"),
        },
    );

    arrival_orders(&oracle, "split header", &split, &split_verdict);

    // Teeth: the verdict must change when the block is wrong.
    println!("\n== teeth ==");
    let unsigned = oracle
        .shred(block.slot, block.parent, &block.components)
        .build();
    let v = oracle.judge(TEST_SLOT, &unsigned);
    println!(
        "unsigned shreds: {} bad signature, meta {}, voted={}",
        v.bad_signatures(),
        if v.meta.is_some() { "present" } else { "none" },
        v.voted
    );
    checks.check(
        "teeth: unsigned shreds all fail sigverify and nothing is stored",
        v.bad_signatures() == unsigned.len() && v.meta.is_none() && !v.voted,
    );

    let mut wrong_version = solana_thin::testkit::BlockBuilder::new(
        block.slot,
        block.parent,
        oracle.config().shred_version + 1,
    );
    for component in &block.components {
        wrong_version = wrong_version.component(component);
    }
    let mut wrong_version = wrong_version.build();
    oracle.sign(&mut wrong_version);
    let v = oracle.judge(TEST_SLOT, &wrong_version);
    println!(
        "wrong shred version: {} discarded, reason {:?}, voted={}",
        v.discarded(),
        v.shreds[0].discarded,
        v.voted
    );
    checks.check(
        "teeth: a wrong shred version is discarded by the filter",
        v.discarded() == wrong_version.len()
            && v.shreds[0].discarded.as_deref() == Some("shred_version_mismatch")
            && !v.voted,
    );

    // One bit of a transaction signature: the entry hash no longer matches
    // and neither does the signature.
    let mut tampered = block.components.clone();
    let at = tampered[1]
        .windows(64)
        .position(|w| w == block.transactions[0].signature)
        .expect("signature is in the batch");
    tampered[1][at + 5] ^= 1;
    let v = oracle.judge(
        TEST_SLOT,
        &oracle.shred_and_sign(block.slot, block.parent, &tampered),
    );
    println!(
        "tampered transaction signature: {:?} dead={}",
        v.replay, v.dead
    );
    checks.check(
        "teeth: a tampered transaction signature fails replay and kills the slot",
        matches!(v.replay, Replay::Failed { .. }) && v.dead && !v.voted,
    );

    // A header naming the right slot and the wrong block id.
    let mut wrong_parent = block.components.clone();
    wrong_parent[0] = Oracle::header_bytes(&BlockRef {
        slot: PARENT_SLOT,
        id: [7; 32],
    });
    let v = oracle.judge(
        TEST_SLOT,
        &oracle.shred_and_sign(block.slot, block.parent, &wrong_parent),
    );
    println!("header with a wrong parent id: {:?}", v.replay);
    checks.check(
        "teeth: a header naming another parent block is deferred",
        matches!(v.replay, Replay::Deferred(_)) && !v.voted && !v.dead,
    );

    // A footer one nanosecond past the clock bound.
    let (earliest, latest) = oracle.footer_time_bounds(PARENT_SLOT, TEST_SLOT);
    println!(
        "footer time bounds for {TEST_SLOT} on {PARENT_SLOT}: {earliest}..={latest} ({} ms wide)",
        (latest - earliest + 1) / 1_000_000
    );
    let late = latest + 1;
    let mut late_footer = block.components.clone();
    late_footer[block.footer] = Oracle::footer_bytes(bank_hash, late);
    let v = oracle.judge(
        TEST_SLOT,
        &oracle.shred_and_sign(block.slot, block.parent, &late_footer),
    );
    println!("footer past the clock bound: {:?}", v.replay);
    checks.check(
        "teeth: a footer time past the upper bound fails replay",
        matches!(&v.replay, Replay::Failed { error, .. } if error.contains("clock")) && v.dead,
    );
    let mut on_bound = block.components.clone();
    on_bound[block.footer] = Oracle::footer_bytes(bank_hash, late - 1);
    let v = oracle.judge(
        TEST_SLOT,
        &oracle.shred_and_sign(block.slot, block.parent, &on_bound),
    );
    println!("footer exactly on the clock bound: {:?}", v.replay);
    checks.check(
        "teeth: a footer time on the upper bound gets as far as the bank hash",
        matches!(
            &v.replay,
            Replay::Failed {
                bank_hash_mismatch: Some(_),
                ..
            }
        ),
    );
    let mut early_footer = block.components.clone();
    early_footer[block.footer] = Oracle::footer_bytes(bank_hash, earliest - 1);
    let v = oracle.judge(
        TEST_SLOT,
        &oracle.shred_and_sign(block.slot, block.parent, &early_footer),
    );
    println!("footer at the parent's time: {:?}", v.replay);
    checks.check(
        "teeth: a footer time not after the parent's fails replay",
        matches!(&v.replay, Replay::Failed { error, .. } if error.contains("clock")) && v.dead,
    );

    // A transaction whose signature is wrong, inside an entry whose hash
    // is right for it: only signature verification can catch this.
    let blockhash = oracle.last_blockhash(PARENT_SLOT);
    let mut forged = oracle.transfer(b"forged", 5, blockhash);
    let mut signature: [u8; 64] = forged.signatures[0].into();
    signature[5] ^= 1;
    forged.signatures[0] = signature.into();
    let v = judge_transactions(&oracle, &[vec![vec![forged]]]);
    println!(
        "forged transaction signature, entry hash consistent: {:?}",
        v.replay
    );
    checks.check(
        "teeth: a forged transaction signature fails replay and kills the slot",
        matches!(
            &v.replay,
            Replay::Failed {
                bank_hash_mismatch: None,
                ..
            }
        ) && v.dead,
    );

    // A transaction naming a blockhash no bank has seen cannot be committed.
    let stale = oracle.transfer(b"stale", 5, Hash::new_from_array([9; 32]));
    let v = judge_transactions(&oracle, &[vec![vec![stale]]]);
    println!("transaction with an unknown blockhash: {:?}", v.replay);
    checks.check(
        "teeth: an uncommittable transaction fails replay and kills the slot",
        matches!(
            &v.replay,
            Replay::Failed {
                bank_hash_mismatch: None,
                ..
            }
        ) && v.dead,
    );

    // A transaction that is committed and fails: the mint cannot pay this.
    let good = oracle.transfer(b"good", 5, blockhash);
    let broke = oracle.transfer(b"broke", u64::MAX, blockhash);
    let v = judge_transactions(&oracle, &[vec![vec![good, broke]]]);
    let commits: Vec<_> = v
        .executed
        .iter()
        .flatten()
        .map(|tx| tx.commit.clone())
        .collect();
    println!(
        "ANSWER a block holding a transfer that fails: voted={} commit statuses {commits:?} \
         recipient balance {:?}",
        v.voted,
        oracle
            .bank(TEST_SLOT)
            .map(|bank| bank.get_balance(&Oracle::recipient(b"broke"))),
    );
    checks.check(
        "a failing transaction is committed as failed and the block still votes",
        v.voted
            && commits.len() == 2
            && commits[0] == Ok(Ok(()))
            && matches!(commits[1], Ok(Err(_))),
    );

    // (v) A real UpdateParent block. Slot 33 is built on 32; the leader of
    // 36 starts on 33, then switches to 32.
    println!("\n== UpdateParent ==");
    let (_, _, optimistic) = honest(
        &oracle,
        HonestSpec {
            slot: PARENT_SLOT + 1,
            parent_slot: PARENT_SLOT,
            batches: vec![vec![1]],
            bank_hash: Hash::default(),
            seed: 2,
            abandoned: None,
        },
    );
    checks.check("slot 33 on 32 voted", optimistic.voted);
    let (switched, switched_payloads, v) = honest(
        &oracle,
        HonestSpec {
            slot: TEST_SLOT,
            parent_slot: PARENT_SLOT,
            batches: vec![vec![2], vec![1]],
            bank_hash: Hash::default(),
            seed: 3,
            abandoned: Some(AbandonedPrefix {
                header_parent_slot: PARENT_SLOT + 1,
                batches: vec![vec![2, 1]],
            }),
        },
    );
    println!("{v}");
    let bank = oracle.bank(TEST_SLOT);
    let kept: Vec<_> = switched
        .transactions
        .iter()
        .filter(|t| !t.abandoned)
        .collect();
    let doomed: Vec<_> = switched
        .transactions
        .iter()
        .filter(|t| t.abandoned)
        .collect();
    println!(
        "ANSWER (v) header on 33, {} abandoned transactions, UpdateParent to 32 at component {}, \
         {} kept transactions: voted={} parent in slot meta {:?} replay from shred {} executed {} \
         bank parent {:?}",
        doomed.len(),
        switched.update_parent.unwrap(),
        kept.len(),
        v.voted,
        v.meta.as_ref().and_then(|m| m.parent_slot),
        v.replay_start,
        v.executed.as_ref().map(|e| e.len()).unwrap_or(0),
        bank.as_ref().map(|b| b.parent_slot()),
    );
    if let (true, Some(bank), Some(executed)) = (v.voted, &bank, &v.executed) {
        println!(
            "       executed are exactly the kept ones: {}; kept recipients funded: {}; abandoned \
             recipients empty: {}",
            executed.iter().map(|t| t.signature).collect::<Vec<_>>()
                == kept.iter().map(|t| t.signature).collect::<Vec<_>>(),
            kept.iter()
                .all(|t| bank.get_balance(&t.recipient) == t.lamports),
            doomed.iter().all(|t| bank.get_balance(&t.recipient) == 0),
        );
    }
    drop(bank);
    println!(
        "       light client on the UpdateParent block: {}",
        match BlockData::from_shreds(&switched_payloads) {
            Ok(data) => format!(
                "indexes it; parent {:?}; {} signatures",
                (data.parent().slot, hex(data.parent().id)),
                data.signatures().len()
            ),
            Err(error) => format!("refused: {error:?}"),
        },
    );
    println!(
        "       block id with the final parent given: {}",
        match BlockData::from_shreds_with_final_parent(&switched_payloads, switched.final_parent) {
            Ok(data) => format!(
                "{} Agave's",
                if Some(data.block().id) == v.block_id.map(|id| id.to_bytes()) {
                    "equals"
                } else {
                    "DIFFERS from"
                }
            ),
            Err(error) => format!("refused: {error:?}"),
        },
    );

    arrival_orders(&oracle, "UpdateParent block", &switched_payloads, &v);

    // (iii) Wall time per case, on warm state.
    println!("\n== timing ==");
    let rounds = 5;
    let timer = Instant::now();
    let (mut ingest, mut replay) = (0.0, 0.0);
    for _ in 0..rounds {
        let again = oracle.judge(TEST_SLOT, &payloads);
        assert!(again.voted);
        ingest += again.ingest_time.as_secs_f64() * 1e3;
        replay += again.replay_time.as_secs_f64() * 1e3;
    }
    println!(
        "ANSWER (iii) per case over {rounds} repeats of the honest block ({} shreds, {} FEC sets, \
         {} transactions): {:.1} ms total, of which ingest {:.1} ms and replay {:.1} ms",
        payloads.len(),
        payloads.len() as u32 / FEC_SET,
        block.transactions.len(),
        timer.elapsed().as_secs_f64() * 1e3 / rounds as f64,
        ingest / rounds as f64,
        replay / rounds as f64,
    );
    let timer = Instant::now();
    let (big, big_payloads, big_verdict) = honest(
        &oracle,
        HonestSpec {
            slot: TEST_SLOT,
            parent_slot: PARENT_SLOT,
            batches: vec![vec![10; 25], vec![10; 25]],
            bank_hash: Hash::default(),
            seed: 4,
            abandoned: None,
        },
    );
    println!(
        "ANSWER (iii) a block of {} transactions in {} shreds: voted={}, two passes with building \
         and shredding {:.1} ms, second pass ingest {:.1} ms and replay {:.1} ms",
        big.transactions.len(),
        big_payloads.len(),
        big_verdict.voted,
        timer.elapsed().as_secs_f64() * 1e3,
        big_verdict.ingest_time.as_secs_f64() * 1e3,
        big_verdict.replay_time.as_secs_f64() * 1e3,
    );
    let final_verdict = oracle.judge(TEST_SLOT, &payloads);
    checks.check(
        "the honest block still gets the same verdict after all of the above",
        final_verdict.order_independent() == honest_view && final_verdict.replay == Replay::Ok,
    );

    println!(
        "\nsmoke: {} ({:.1} s)",
        if checks.failed == 0 {
            "all checks passed".to_string()
        } else {
            format!("{} CHECK(S) FAILED", checks.failed)
        },
        started.elapsed().as_secs_f64(),
    );
    if checks.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// What the harness modes share.
struct Options {
    /// Worlds to run in: fast leader handover on, off, or both.
    handover: Vec<bool>,
    /// Only cases whose name contains this.
    filter: Option<String>,
    /// Print every case's verdict in full.
    verbose: bool,
    /// Where cases with a violation are written.
    dump: PathBuf,
}

/// At most this many violating cases are dumped per run.
const MAX_DUMPS: usize = 30;

fn slug(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn agave_summary(outcome: &Outcome) -> String {
    let verdict = &outcome.verdict;
    let executed = verdict.executed.as_ref().map(Vec::len).unwrap_or(0);
    let mut text = match &verdict.replay {
        Replay::Ok => format!(
            "ok from shred {}, {executed} executed",
            verdict.replay_start
        ),
        Replay::Deferred(_) => "deferred (parent id)".to_string(),
        Replay::NotReplayable(reason) => {
            let dropped = verdict.discarded();
            match dropped {
                0 => reason.clone(),
                _ => format!("{reason}, {dropped} shred(s) discarded"),
            }
        }
        Replay::Failed { error, .. } => {
            let error: String = error.chars().take(60).collect();
            format!("dead: {error}")
        }
        Replay::Skipped => "skipped".to_string(),
    };
    if let Some(error) = &verdict.insert_error {
        let error: String = error.chars().take(50).collect();
        text = format!("{text}; insert: {error}");
    }
    if outcome.meta_moved {
        text.push_str(" [meta moves with arrival order]");
    }
    if let Some(error) = &outcome.raw_error {
        text = format!("{text} [light client: {error}]");
    }
    text
}

/// Violations that count against a run: everything but the known upstream
/// order dependence, which is Agave disagreeing with itself.
fn against_the_verifier(outcome: &Outcome) -> usize {
    outcome
        .violations
        .iter()
        .filter(|v| v.property != UPSTREAM_ORDER)
        .count()
}

fn violation_summary(outcome: &Outcome) -> String {
    let mut parts = Vec::new();
    for property in [
        "P0",
        "P1",
        "P2",
        "premise",
        "opening",
        "oracle",
        UPSTREAM_ORDER,
    ] {
        match outcome.count(property) {
            0 => {}
            n => parts.push(format!("{property}x{n}")),
        }
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

/// Writes a violating case where it can be picked up again: the frozen form
/// plus the full payloads.
fn dump(outcome: &Outcome, world: &World, dir: &Path) {
    let mut value = freeze(outcome, world, usize::MAX);
    value["payloads"] = outcome
        .realised
        .payloads
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>()
        .into();
    value["violations"] = outcome
        .violations
        .iter()
        .map(|v| format!("{}: {}", v.property, v.detail))
        .collect::<Vec<_>>()
        .into();
    let path = dir.join(format!(
        "{}-handover-{}.json",
        slug(&outcome.case.name),
        if world.handover { "on" } else { "off" }
    ));
    if std::fs::create_dir_all(dir).is_ok() && std::fs::write(&path, value.to_string()).is_ok() {
        println!("    dumped to {}", path.display());
    }
}

#[derive(Default)]
struct Totals {
    cases: usize,
    violations: usize,
    floor_failures: usize,
}

/// Runs `cases` in one world and prints what the brief asks for: a row per
/// case (if `table`), every violation, the per-family tally, the floors and
/// the coverage report. Returns the outcomes.
fn run_cases(
    world: &World,
    cases: &[Case],
    options: &Options,
    table: bool,
    totals: &mut Totals,
) -> Vec<Outcome> {
    let started = Instant::now();
    println!(
        "\n== fast leader handover {}: {} cases ==",
        if world.handover { "ON" } else { "OFF" },
        cases.len()
    );
    if table {
        println!(
            "{:<68} {:>5} {:>6} {:>8} {:<14} agave",
            "name", "voted", "claims", "accepted", "violations"
        );
    }
    let mut outcomes = Vec::with_capacity(cases.len());
    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    let mut coverage: BTreeMap<String, usize> = BTreeMap::new();
    let mut shown: BTreeMap<(String, &'static str), usize> = BTreeMap::new();
    let mut dumped = 0;
    let mut meta_moved = 0;
    for case in cases {
        let outcome = world.run(case);
        let tally = tallies.entry(case.family.to_string()).or_default();
        tally.cases += 1;
        tally.voted += usize::from(outcome.voted);
        tally.claims += outcome.claims.len();
        tally.accepted += outcome.accepted();
        tally.violations += against_the_verifier(&outcome);
        meta_moved += usize::from(outcome.meta_moved);
        for (reason, n) in &outcome.coverage {
            *coverage.entry(reason.clone()).or_insert(0) += n;
        }
        if table {
            println!(
                "{:<68} {:>5} {:>6} {:>8} {:<14} {}",
                case.name,
                if outcome.voted { "yes" } else { "no" },
                if outcome.voted {
                    outcome.claims.len().to_string()
                } else {
                    format!("({})", outcome.enumerated)
                },
                if outcome.voted {
                    outcome.accepted().to_string()
                } else {
                    "-".to_string()
                },
                violation_summary(&outcome),
                agave_summary(&outcome),
            );
        }
        if options.verbose {
            println!("  recipe: {:?}", case.recipe);
            println!("{}", outcome.verdict);
            for claim in &outcome.claims {
                let show = |observed: &Result<(), String>| match observed {
                    Ok(()) => "ACCEPTED".to_string(),
                    Err(error) => format!("rejected: {error}"),
                };
                println!(
                    "  claim ({}, {}, {}) footer {:?}: fewest shreds {}; every shred {} (executed \
                     there: {})",
                    claim.component_start,
                    claim.entry,
                    claim.transaction,
                    claim.footer_start,
                    show(&claim.observed),
                    show(&claim.observed_full),
                    claim.executed,
                );
            }
        }
        if !outcome.violations.is_empty() {
            totals.violations += against_the_verifier(&outcome);
            // In a long run, the first few of a kind are shown in full.
            let mut printed_header = false;
            for violation in &outcome.violations {
                let seen = shown
                    .entry((case.family.to_string(), violation.property))
                    .or_insert(0);
                *seen += 1;
                if !table && *seen > 3 {
                    continue;
                }
                if !printed_header {
                    println!(
                        "  VIOLATION in {} (handover {}):",
                        case.name,
                        if world.handover { "on" } else { "off" }
                    );
                    println!("    recipe: {:?}", case.recipe.items);
                    if case.recipe.layout != Default::default() {
                        println!("    layout: {:?}", case.recipe.layout);
                    }
                    printed_header = true;
                }
                println!("    {}: {}", violation.property, violation.detail);
            }
            if printed_header && dumped < MAX_DUMPS {
                dump(&outcome, world, &options.dump);
                dumped += 1;
            }
        }
        outcomes.push(outcome);
    }
    totals.cases += outcomes.len();

    println!(
        "\n-- per family, handover {} --",
        if world.handover { "on" } else { "off" }
    );
    println!(
        "{:<42} {:>6} {:>6} {:>7} {:>9} {:>10}",
        "family", "cases", "voted", "claims", "accepted", "violations"
    );
    for (family, tally) in &tallies {
        println!(
            "{:<42} {:>6} {:>6} {:>7} {:>9} {:>10}",
            family, tally.cases, tally.voted, tally.claims, tally.accepted, tally.violations
        );
    }
    let all = tallies.values().fold(Tally::default(), |mut all, tally| {
        all.cases += tally.cases;
        all.voted += tally.voted;
        all.claims += tally.claims;
        all.accepted += tally.accepted;
        all.violations += tally.violations;
        all
    });
    println!(
        "{:<42} {:>6} {:>6} {:>7} {:>9} {:>10}",
        "total", all.cases, all.voted, all.claims, all.accepted, all.violations
    );
    let by_property =
        |property: &str| -> usize { outcomes.iter().map(|o| o.count(property)).sum::<usize>() };
    println!(
        "known upstream finding, not counted: Agave's verdict depended on arrival order in {} \
         run(s) of a zero-parent UpdateParent block",
        by_property(UPSTREAM_ORDER),
    );
    println!(
        "violations by property: P0 {} P1 {} P2 {} premise {} opening {} oracle {}; cases whose \
         SlotMeta moved with arrival order without any order voting: {meta_moved}",
        by_property("P0"),
        by_property("P1"),
        by_property("P2"),
        by_property("premise"),
        by_property("opening"),
        by_property("oracle"),
    );

    // Which blocks the violations are in: by family, by the parent the
    // header names and the parents UpdateParent markers name.
    let mut where_found: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for outcome in outcomes.iter().filter(|o| !o.violations.is_empty()) {
        let recipe = &outcome.case.recipe;
        let switches: Vec<String> = recipe
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Switch(parent) => Some(format!("{parent:?}")),
                _ => None,
            })
            .collect();
        let properties: BTreeSet<&str> = outcome.violations.iter().map(|v| v.property).collect();
        let key = format!(
            "{} | header {:?} | UpdateParent to [{}] | {}",
            outcome.case.family,
            recipe.header_parent(),
            switches.join(", "),
            properties.into_iter().collect::<Vec<_>>().join("+"),
        );
        let entry = where_found.entry(key).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += outcome.violations.len();
    }
    if !where_found.is_empty() {
        println!("-- cases with violations: family | header parent | markers | properties --");
        for (key, (cases, violations)) in &where_found {
            println!("{cases:>5} cases {violations:>5} violations  {key}");
        }
    }

    let floors = check_floors(&tallies, world.handover);
    for failure in &floors {
        println!("{failure}");
    }
    totals.floor_failures += floors.len();
    if floors.is_empty() {
        println!("floors: every family that should vote did, and none that should not did");
    }

    println!("-- P3 coverage: transactions Agave executed, by what the honest prover did --");
    for (reason, n) in &coverage {
        println!("{n:>7}  {reason}");
    }
    println!("({:.1} s)", started.elapsed().as_secs_f64());
    outcomes
}

fn worlds(options: &Options) -> Vec<World> {
    options.handover.iter().map(|on| World::new(*on)).collect()
}

fn finish(totals: &Totals) -> ExitCode {
    println!(
        "\n{} case runs, {} violation(s), {} floor failure(s)",
        totals.cases, totals.violations, totals.floor_failures
    );
    if totals.violations == 0 && totals.floor_failures == 0 {
        println!("RESULT: clean");
        ExitCode::SUCCESS
    } else {
        println!("RESULT: FAILED");
        ExitCode::FAILURE
    }
}

fn corpus_cases(options: &Options) -> Vec<Case> {
    corpus()
        .into_iter()
        .filter(|case| {
            options
                .filter
                .as_ref()
                .is_none_or(|filter| case.name.contains(filter.as_str()))
        })
        .collect()
}

fn run_corpus(options: &Options) -> ExitCode {
    let cases = corpus_cases(options);
    let mut totals = Totals::default();
    for world in worlds(options) {
        run_cases(&world, &cases, options, true, &mut totals);
    }
    finish(&totals)
}

fn run_random(options: &Options, count: u64, seed: u64) -> ExitCode {
    let mut totals = Totals::default();
    for world in worlds(options) {
        let cases: Vec<Case> = (0..count)
            .map(|n| generate(&world, seed, n))
            .filter(|case| {
                options
                    .filter
                    .as_ref()
                    .is_none_or(|filter| case.name.contains(filter.as_str()))
            })
            .collect();
        println!("random: {count} cases from seed {seed}");
        run_cases(&world, &cases, options, false, &mut totals);
    }
    finish(&totals)
}

/// Writes one frozen file per corpus case, from the world with fast leader
/// handover on, for the main workspace's `tests/oracle_corpus.rs`.
fn emit(options: &Options, dir: &Path) -> ExitCode {
    /// Encoded proofs kept per case. The shreds rebuild every claim; the
    /// proofs pin the wire format and what the verifier did with them.
    const PROOFS_PER_CASE: usize = 1;
    /// A case larger than this is not written.
    const MAX_FILE: usize = 96 * 1024;

    let world = World::new(true);
    let cases = corpus_cases(options);
    let mut totals = Totals::default();
    let outcomes = run_cases(&world, &cases, options, true, &mut totals);
    std::fs::create_dir_all(dir).expect("output directory");
    for entry in std::fs::read_dir(dir).expect("output directory lists") {
        let path = entry.expect("directory entry").path();
        if path.extension().is_some_and(|e| e == "json") {
            std::fs::remove_file(&path).expect("stale vector removed");
        }
    }
    let (mut written, mut bytes, mut skipped) = (0, 0, Vec::new());
    for outcome in outcomes.iter().filter(|o| o.case.freeze) {
        let value = freeze(outcome, &world, PROOFS_PER_CASE);
        let mut text = serde_json::to_string(&value).expect("vector serializes");
        text.push('\n');
        if text.len() > MAX_FILE {
            skipped.push(format!("{} ({} bytes)", outcome.case.name, text.len()));
            continue;
        }
        let path = dir.join(format!("{}.json", slug(&outcome.case.name)));
        std::fs::write(&path, &text).expect("vector written");
        written += 1;
        bytes += text.len();
    }
    println!(
        "\nemit: {written} files, {bytes} bytes, into {}; skipped as too large: {skipped:?}",
        dir.display()
    );
    println!(
        "emit: {} violation(s) and {} floor failure(s) in the emitted run (frozen as observed)",
        totals.violations, totals.floor_failures
    );
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: diff-fuzz --smoke\n       diff-fuzz --corpus [DUMP_DIR] [options]\n       \
         diff-fuzz --random N --seed S [options]\n       diff-fuzz --emit DIR [options]\n\
         options: --handover on|off|both (default both)   --filter SUBSTRING   --verbose   \
         --dump DIR"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    // Agave explains most refusals only in its log.
    if let Ok(filter) = std::env::var("DIFF_FUZZ_LOG") {
        agave_logger::setup_with(&filter);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = Options {
        handover: vec![true, false],
        filter: None,
        verbose: false,
        dump: std::env::temp_dir().join("solana-thin-diff-fuzz-dumps"),
    };
    let mut mode: Option<&str> = None;
    let mut positional: Option<String> = None;
    let mut count = 0u64;
    let mut seed = 1u64;
    let mut i = 0;
    while i < args.len() {
        let value = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match args[i].as_str() {
            "--smoke" => mode = Some("smoke"),
            "--corpus" => mode = Some("corpus"),
            "--emit" => mode = Some("emit"),
            "--random" => {
                mode = Some("random");
                let Some(n) = value(&mut i).and_then(|v| v.parse().ok()) else {
                    return usage();
                };
                count = n;
            }
            "--seed" => {
                let Some(s) = value(&mut i).and_then(|v| v.parse().ok()) else {
                    return usage();
                };
                seed = s;
            }
            "--handover" => {
                options.handover = match value(&mut i).as_deref() {
                    Some("on") => vec![true],
                    Some("off") => vec![false],
                    Some("both") => vec![true, false],
                    _ => return usage(),
                }
            }
            "--filter" => options.filter = value(&mut i),
            "--dump" => match value(&mut i) {
                Some(dir) => options.dump = PathBuf::from(dir),
                None => return usage(),
            },
            "--verbose" => options.verbose = true,
            other if !other.starts_with("--") && positional.is_none() => {
                positional = Some(other.to_string())
            }
            _ => return usage(),
        }
        i += 1;
    }
    match mode {
        Some("smoke") => smoke(),
        Some("corpus") => {
            if let Some(dir) = positional {
                options.dump = PathBuf::from(dir);
            }
            run_corpus(&options)
        }
        Some("random") => run_random(&options, count, seed),
        Some("emit") => match positional {
            Some(dir) => emit(&options, Path::new(&dir)),
            None => usage(),
        },
        _ => usage(),
    }
}
