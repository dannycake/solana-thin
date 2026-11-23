//! Anchoring: proving that a piece of data existed inside a time window,
//! without trusting whoever relays the proof.
//!
//! This is the pattern a local-first ledger needs from a chain. Nothing is
//! "spent" on chain and no program state is read back. A device commits a
//! fingerprint, and later anyone can check, offline, from a small proof:
//!
//! * **not after**: the fingerprint is in a finalized block, so it existed by
//!   that block's time;
//! * **not before**: the fingerprint was computed over an earlier finalized
//!   block's id (a public value nobody could predict), so it did not exist
//!   before that block.
//!
//! The chain here is simulated with the crate's test builders so the example
//! runs anywhere. The verifying half is exactly what runs against mainnet.
//!
//!     cargo run --example anchor --features testkit

use solana_thin::merkle::sha256;
use solana_thin::prover::{self, BlockData};
use solana_thin::testkit::*;
use solana_thin::*;

const SHRED_VERSION: u16 = 50093;

fn main() -> Result<()> {
    // ----------------------------------------------------------------------
    // The network: validators, and a chain they finalize.
    // ----------------------------------------------------------------------
    let validators = TestValidators::new(40, |i| 2_000_000 - 30_000 * i as u64);
    let genesis = BlockRef {
        slot: 4_999,
        id: [0x38; 32],
    };
    let pulse_block: BlockData = simple_block(5_000, genesis, SHRED_VERSION, &[], None);

    // ----------------------------------------------------------------------
    // Device A makes something and commits to it.
    // ----------------------------------------------------------------------
    let artifact = b"a photo, a note, a log entry: anything";
    // The pulse: the id of a block A has seen finalized. Mixing it in proves
    // the fingerprint was made after that block existed.
    let pulse = pulse_block.block();
    let fingerprint = sha256(&[b"stamp/entry/v1", &pulse.id, &sha256(&[artifact])]);
    let mut memo = b"stamp:v1:".to_vec();
    memo.extend_from_slice(&fingerprint);

    // A signs a transaction carrying the memo and sends it to any RPC node.
    // (Builder stand-in: a real wallet would sign this.)
    let anchor_tx = legacy_transaction(7, &[&memo]);
    let anchor_signature = signature_for(7);

    // ----------------------------------------------------------------------
    // The network includes it, among other traffic, and finalizes.
    // ----------------------------------------------------------------------
    let traffic: Vec<Vec<u8>> = (100..140)
        .map(|i| legacy_transaction(i, &[b"gm"]))
        .collect();
    let mut entry = traffic;
    entry.insert(17, anchor_tx);
    let anchor_block = simple_block(5_003, pulse, SHRED_VERSION, &[vec![entry]], None);
    let later_block = simple_block(5_004, anchor_block.block(), SHRED_VERSION, &[], None);
    let signers = validators.ranks_reaching(8_000);
    let certificate = validators.fast_cert(later_block.block(), &signers, SHRED_VERSION);

    // ----------------------------------------------------------------------
    // Any node that kept the shreds builds the proof. It holds no keys and is
    // not trusted: a relay, a friend's phone, a public server.
    // ----------------------------------------------------------------------
    let proof = prover::prove(
        certificate,
        &[&later_block, &anchor_block],
        &anchor_signature,
        true,
    )?;
    let wire = proof.to_bytes();
    println!("proof: {} bytes", wire.len());

    // ----------------------------------------------------------------------
    // Device B verifies, offline. Its whole trust is two values.
    // ----------------------------------------------------------------------
    let pinned_hash = validators.set().hash(); // obtained out of band
    let mut client = ThinClient::new(ClusterParams::mainnet(SHRED_VERSION));
    client.trust_validator_set(0, validators.set(), &pinned_hash)?;

    let verified = client.verify_transaction_bytes(&wire)?;
    assert!(
        verified.has_memo(&memo),
        "the proof is for some other transaction"
    );

    // B recomputes the fingerprint from the artifact it was sent and the pulse
    // it names, and checks the pulse really is an earlier finalized block: it
    // is the anchor block's own parent here, which the proof already covers.
    let recomputed = sha256(&[b"stamp/entry/v1", &verified.parent.id, &sha256(&[artifact])]);
    assert_eq!(recomputed, fingerprint);

    let seconds = verified.block_time_nanos().unwrap() / 1_000_000_000;
    println!("fingerprint {}", hex(&fingerprint));
    println!(
        "  made after  slot {} (it commits to that block's id)",
        verified.parent.slot
    );
    println!(
        "  made before slot {} (unix time {seconds})",
        verified.block.slot
    );
    println!(
        "  finalized by a {:?} certificate on slot {}, {} of {} validators signing",
        verified.finalized_by.finality,
        verified.finalized_by.block.slot,
        signers.len(),
        validators.len()
    );
    println!(
        "  included, position {:?}; execution status is not part of the claim",
        verified.position
    );

    // ----------------------------------------------------------------------
    // A relay that lies gets nowhere.
    // ----------------------------------------------------------------------
    let mut tampered = wire.clone();
    let at = tampered.len() / 2;
    tampered[at] ^= 1;
    println!(
        "tampered proof: {}",
        client.verify_transaction_bytes(&tampered).unwrap_err()
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
