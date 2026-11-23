//! Writes conformance vectors for solana-thin using Agave's own code.
//!
//! Everything in the output that solana-thin has an opinion about is produced
//! by the validator implementation, not by this file:
//!
//! * blocks are serialized by `solana-entry` and shredded by `solana-ledger`'s
//!   `Shredder`, coding shreds and all;
//! * block ids are read back from a real `Blockstore` after inserting the
//!   shreds;
//! * vote payloads come from `agave-votor-messages`, signatures from
//!   `solana-bls-signatures`, bitmaps from `solana-signer-store`;
//! * each certificate's verdict comes from `agave-bls-cert-verify`;
//! * validator ranking comes from `solana-runtime`'s `BLSPubkeyToRankMap`.
//!
//! Usage: `cargo run --release -- <output.json>`

use {
    agave_bls_cert_verify::cert_verify::verify_certificate,
    agave_votor_messages::{
        certificate::CertificateType, consensus_message::Block,
        unverified_vote_message::UnverifiedCertificate, vote::Vote,
        wire::get_vote_payload_to_sign,
    },
    bitvec::prelude::*,
    serde_json::{Value, json},
    solana_bls_signatures::{
        Keypair as BlsKeypair, Signature as BlsSignature, SignatureCompressed,
        SignatureProjective,
        pubkey::{PopVerified, PubkeyAffine, PubkeyCompressed},
    },
    solana_entry::{
        block_component::{
            BlockComponent, BlockFinalizationCert, BlockFooterV1, VersionedBlockMarker,
            VotesAggregate,
        },
        entry::Entry,
    },
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        blockstore::Blockstore,
        blockstore_meta::BlockLocation,
        get_tmp_ledger_path_auto_delete,
        shred::{ProcessShredsStats, ReedSolomonCache, Shred, Shredder},
    },
    solana_message::{
        AddressLookupTableAccount, Message, VersionedMessage, v0,
    },
    solana_pubkey::Pubkey,
    solana_runtime::epoch_stakes::BLSPubkeyToRankMap,
    solana_sha256_hasher::hashv,
    solana_signer::Signer,
    solana_signer_store::encode_base2,
    solana_system_interface::instruction as system_instruction,
    solana_transaction::{Transaction, versioned::VersionedTransaction},
    solana_vote::vote_account::{VoteAccount, VoteAccountsHashMap},
    std::num::NonZero,
};

const SHRED_VERSION: u16 = 50093;

fn hx(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

/// Validators with known BLS keys, ranked by the rule `BLSPubkeyToRankMap`
/// applies (stake descending, then compressed key bytes). That rule itself is
/// checked against Agave separately in `rank_vectors`.
struct Validators {
    keypairs: Vec<BlsKeypair>,
    stakes: Vec<u64>,
}

impl Validators {
    fn new(stakes: &[u64]) -> Self {
        let mut pairs: Vec<(BlsKeypair, u64, [u8; 48])> = stakes
            .iter()
            .enumerate()
            .map(|(i, stake)| {
                let ikm = hashv(&[b"agave-fixtures", &(i as u64).to_le_bytes()]);
                let keypair = BlsKeypair::derive(ikm.as_ref()).unwrap();
                let compressed = PubkeyCompressed::try_from(&*keypair.public).unwrap().0;
                (keypair, *stake, compressed)
            })
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));
        Self {
            stakes: pairs.iter().map(|p| p.1).collect(),
            keypairs: pairs.into_iter().map(|p| p.0).collect(),
        }
    }

    fn compressed(&self, rank: usize) -> [u8; 48] {
        PubkeyCompressed::try_from(&*self.keypairs[rank].public)
            .unwrap()
            .0
    }

    fn total(&self) -> u64 {
        self.stakes.iter().sum()
    }

    /// Aggregates `ranks`' signatures on `vote`. Returns the affine signature
    /// Agave's verifier takes and the bitmap.
    fn aggregate(&self, vote: Vote, shred_version: u16, ranks: &[usize]) -> (BlsSignature, Vec<u8>) {
        let payload = get_vote_payload_to_sign(vote, shred_version);
        let max = ranks.iter().max().unwrap() + 1;
        let mut bitmap: BitVec<u8, Lsb0> = BitVec::repeat(false, max);
        let mut signature = SignatureProjective::identity();
        for &rank in ranks {
            bitmap.set(rank, true);
            let s = self.keypairs[rank].sign(&payload);
            signature.aggregate_with(std::iter::once(&s)).unwrap();
        }
        (signature.into(), encode_base2(&bitmap).unwrap())
    }

    /// Agave's verdict on one aggregate interpreted as `cert_type`.
    fn agave_accepts(&self, cert_type: CertificateType, signature: BlsSignature, bitmap: &[u8]) -> bool {
        let cert = UnverifiedCertificate {
            cert_type,
            signature,
            bitmap: bitmap.to_vec(),
            shred_version: SHRED_VERSION,
        };
        verify_certificate(
            cert,
            self.keypairs.len(),
            NonZero::new(self.total()).unwrap(),
            |rank| {
                let keypair = self.keypairs.get(rank)?;
                let key: PubkeyAffine = *keypair.public;
                // Test keys: possession is known by construction.
                Some((NonZero::new(self.stakes[rank]).unwrap(), unsafe {
                    PopVerified::new_unchecked(key)
                }))
            },
            None,
        )
        .is_ok()
    }
}

fn compress(signature: &BlsSignature) -> [u8; 96] {
    SignatureCompressed::try_from(signature).unwrap().0
}

fn aggregate_json(signature: &BlsSignature, bitmap: &[u8]) -> Value {
    json!({ "signature": hx(compress(signature)), "bitmap": hx(bitmap) })
}

/// Certificates and what Agave makes of them.
fn certificate_vectors(validators: &Validators, block: Block) -> Vec<Value> {
    let n = validators.keypairs.len();
    let all: Vec<usize> = (0..n).collect();
    let notar = Vote::new_notarization_vote(block);
    let finalize = Vote::new_finalization_vote(block.slot);
    let mut out = Vec::new();

    let mut fast = |name: &str, vote: Vote, version: u16, ranks: &[usize], claimed: Block| {
        let (signature, bitmap) = validators.aggregate(vote, version, ranks);
        let ok = validators.agave_accepts(CertificateType::FinalizeFast(claimed), signature, &bitmap);
        out.push(json!({
            "name": name, "kind": "fast",
            "slot": claimed.slot, "block_id": hx(claimed.block_id),
            "notar": aggregate_json(&signature, &bitmap),
            "agave_accepts": ok,
        }));
    };
    fast("fast: everyone signs", notar, SHRED_VERSION, &all, block);
    fast("fast: exactly 80% of stake", notar, SHRED_VERSION, &all[..8], block);
    fast("fast: 70% of stake is a notarization, not finality", notar, SHRED_VERSION, &all[..7], block);
    fast("fast: scattered signers at 80%", notar, SHRED_VERSION, &[0, 1, 2, 4, 5, 6, 8, 9], block);
    fast("fast: signed for another cluster", notar, SHRED_VERSION + 1, &all, block);
    fast("fast: finalize votes are not notarize votes", finalize, SHRED_VERSION, &all, block);
    fast(
        "fast: certificate re-pointed at another block",
        notar,
        SHRED_VERSION,
        &all,
        Block { slot: block.slot, block_id: Hash::new_from_array([0xee; 32]) },
    );
    fast(
        "fast: certificate re-pointed at another slot",
        notar,
        SHRED_VERSION,
        &all,
        Block { slot: block.slot + 1, block_id: block.block_id },
    );

    let mut slow = |name: &str, notar_ranks: &[usize], final_ranks: &[usize], final_slot: u64| {
        let (notar_sig, notar_bitmap) = validators.aggregate(notar, SHRED_VERSION, notar_ranks);
        let (final_sig, final_bitmap) = validators.aggregate(
            Vote::new_finalization_vote(final_slot),
            SHRED_VERSION,
            final_ranks,
        );
        let ok = validators.agave_accepts(CertificateType::Notarize(block), notar_sig, &notar_bitmap)
            && validators.agave_accepts(CertificateType::Finalize(block.slot), final_sig, &final_bitmap);
        out.push(json!({
            "name": name, "kind": "slow",
            "slot": block.slot, "block_id": hx(block.block_id),
            "notar": aggregate_json(&notar_sig, &notar_bitmap),
            "finalize": aggregate_json(&final_sig, &final_bitmap),
            "agave_accepts": ok,
        }));
    };
    slow("slow: 60% and 60%", &all[..6], &all[4..], block.slot);
    slow("slow: notarization one validator short", &all[..5], &all, block.slot);
    slow("slow: finalization one validator short", &all, &all[..5], block.slot);
    slow("slow: finalize votes for a different slot", &all, &all, block.slot + 1);

    // The right signers, with one extra rank claimed in the bitmap.
    {
        let (signature, _) = validators.aggregate(notar, SHRED_VERSION, &all[..9]);
        let (_, bitmap) = validators.aggregate(notar, SHRED_VERSION, &all);
        let ok = validators.agave_accepts(CertificateType::FinalizeFast(block), signature, &bitmap);
        out.push(json!({
            "name": "fast: bitmap claims a signer who did not sign", "kind": "fast",
            "slot": block.slot, "block_id": hx(block.block_id),
            "notar": aggregate_json(&signature, &bitmap),
            "agave_accepts": ok,
        }));
    }
    out
}

/// Random vote accounts and the ranking Agave gives them.
fn rank_vectors() -> Value {
    let mut accounts = VoteAccountsHashMap::default();
    let mut listed = Vec::new();
    let stakes = [500u64, 7, 0, 500, 31, 31, 31, 2, 900, 1, 64, 0, 12];
    let mut made = Vec::new();
    for stake in stakes {
        let account = VoteAccount::new_random();
        let vote_pubkey = Pubkey::new_unique();
        made.push((vote_pubkey, stake, account));
    }
    // Two entries sharing one vote account's state: same node identity and
    // same BLS key under two vote addresses. Agave drops both.
    let twin = made[4].2.clone();
    made.push((Pubkey::new_unique(), 77, twin));
    for (vote_pubkey, stake, account) in made {
        let view = account.vote_state_view();
        listed.push(json!({
            "vote_pubkey": hx(vote_pubkey),
            "node_pubkey": hx(view.node_pubkey()),
            "bls_pubkey": view.bls_pubkey_compressed().map(hx),
            "stake": stake,
        }));
        accounts.insert(vote_pubkey, (stake, account));
    }
    let map = BLSPubkeyToRankMap::new(&accounts);
    let ranked: Vec<Value> = (0..map.len())
        .map(|rank| {
            let entry = map.get_pubkey_stake_entry(rank).unwrap();
            let compressed = PubkeyCompressed::try_from(&*entry.bls_pubkey).unwrap().0;
            json!({ "bls_pubkey": hx(compressed), "stake": entry.stake.get() })
        })
        .collect();
    json!({
        "accounts": listed,
        "ranked": ranked,
        "total_stake": map.total_stake().get(),
    })
}

/// Proofs of possession made the way the vote program expects them.
fn pop_vectors() -> Vec<Value> {
    (0..3u64)
        .map(|i| {
            let keypair = BlsKeypair::derive(hashv(&[b"pop", &i.to_le_bytes()]).as_ref()).unwrap();
            let vote_pubkey = Pubkey::new_unique();
            let mut message = b"ALPENGLOW".to_vec();
            message.extend_from_slice(vote_pubkey.as_ref());
            let pop = keypair.proof_of_possession(Some(&message));
            let pop: solana_bls_signatures::ProofOfPossessionCompressed =
                solana_bls_signatures::ProofOfPossession::from(pop).try_into().unwrap();
            let compressed = PubkeyCompressed::try_from(&*keypair.public).unwrap().0;
            // Ask the same routine the vote program calls.
            use solana_bls_signatures::pubkey::VerifyPop;
            let ok = PubkeyCompressed(compressed)
                .verify_proof_of_possession(&pop, Some(&message))
                .is_ok();
            assert!(ok);
            json!({
                "vote_pubkey": hx(vote_pubkey),
                "bls_pubkey": hx(compressed),
                "proof_of_possession": hx(pop.0),
            })
        })
        .collect()
}

fn transfer(payer: &Keypair, blockhash: Hash, lamports: u64) -> VersionedTransaction {
    let to = Pubkey::new_unique();
    let ix = system_instruction::transfer(&payer.pubkey(), &to, lamports);
    let message = Message::new(&[ix], Some(&payer.pubkey()));
    VersionedTransaction::from(Transaction::new(&[payer], message, blockhash))
}

fn memo_legacy(payer: &Keypair, blockhash: Hash, memo: &[u8]) -> VersionedTransaction {
    let memo_program: Pubkey = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".parse().unwrap();
    let ix = solana_message::Instruction {
        program_id: memo_program,
        accounts: vec![],
        data: memo.to_vec(),
    };
    let message = Message::new(&[ix], Some(&payer.pubkey()));
    VersionedTransaction::from(Transaction::new(&[payer], message, blockhash))
}

fn transfer_v0(payer: &Keypair, blockhash: Hash, lamports: u64) -> VersionedTransaction {
    let table = AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses: (0..6).map(|_| Pubkey::new_unique()).collect(),
    };
    let ixs = [
        system_instruction::transfer(&payer.pubkey(), &table.addresses[2], lamports),
        system_instruction::transfer(&payer.pubkey(), &table.addresses[5], lamports + 1),
    ];
    let message = v0::Message::try_compile(&payer.pubkey(), &ixs, &[table], blockhash).unwrap();
    VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer]).unwrap()
}

struct BuiltBlock {
    slot: u64,
    parent: Block,
    id: Hash,
    data_shreds: Vec<Vec<u8>>,
    transactions: Vec<Value>,
    footer: Value,
}

/// Builds one block the way a leader does and reads its id back from a
/// blockstore.
fn build_block(
    blockstore: &Blockstore,
    slot: u64,
    parent: Block,
    batches: Vec<Vec<Entry>>,
    footer_cert: Option<BlockFinalizationCert>,
) -> BuiltBlock {
    let leader = Keypair::new();
    let shredder = Shredder::new(slot, parent.slot, 0, SHRED_VERSION).unwrap();
    let cache = ReedSolomonCache::default();
    let mut stats = ProcessShredsStats::default();

    let bank_hash = hashv(&[b"bank", &slot.to_le_bytes()]);
    let time = 1_792_590_840_000_000_000u64 + slot * 400_000_000;
    let footer = BlockFooterV1 {
        bank_hash,
        block_producer_time_nanos: time,
        block_user_agent: b"agave-fixtures/4.4.1".to_vec(),
        block_final_cert: footer_cert,
        skip_reward_cert: None,
        notar_reward_cert: None,
    };

    let mut components = vec![BlockComponent::new_block_header(parent.slot, parent.block_id)];
    for entries in &batches {
        components.push(BlockComponent::new_entry_batch(entries.clone()).unwrap());
    }
    components.push(BlockComponent::new_block_marker(
        VersionedBlockMarker::from_block_footer(footer),
    ));
    // The closing tick.
    components.push(
        BlockComponent::new_entry_batch(vec![Entry {
            num_hashes: 1,
            hash: hashv(&[b"alpentick", &slot.to_le_bytes()]),
            transactions: vec![],
        }])
        .unwrap(),
    );

    let mut shreds: Vec<Shred> = Vec::new();
    let mut chained = hashv(&[b"chain", parent.block_id.as_ref()]);
    let (mut next_data, mut next_code) = (0u32, 0u32);
    let mut component_starts = Vec::new();
    let last = components.len() - 1;
    for (i, component) in components.iter().enumerate() {
        component_starts.push(next_data);
        let made = shredder.make_merkle_shreds_from_component(
            &leader,
            component,
            i == last,
            chained,
            next_data,
            next_code,
            &cache,
            &mut stats,
        );
        chained = made.last().unwrap().merkle_root().unwrap();
        next_data += made.iter().filter(|s| s.is_data()).count() as u32;
        next_code += made.iter().filter(|s| !s.is_data()).count() as u32;
        shreds.extend(made);
    }

    blockstore.insert_shreds(shreds.clone(), true).unwrap();
    let id = blockstore
        .get_double_merkle_root(slot, BlockLocation::Original)
        .unwrap()
        .expect("blockstore computed a block id");

    let mut transactions = Vec::new();
    for (batch_index, entries) in batches.iter().enumerate() {
        for (entry_index, entry) in entries.iter().enumerate() {
            for (tx_index, tx) in entry.transactions.iter().enumerate() {
                transactions.push(json!({
                    "signature": hx(tx.signatures[0]),
                    "component_start": component_starts[1 + batch_index],
                    "entry": entry_index,
                    "transaction": tx_index,
                    "message": hx(tx.message.serialize()),
                    "wire": hx(wincode::serialize(tx).unwrap()),
                }));
            }
        }
    }

    BuiltBlock {
        slot,
        parent,
        id,
        data_shreds: shreds
            .iter()
            .filter(|s| s.is_data())
            .map(|s| s.payload().to_vec())
            .collect(),
        transactions,
        footer: json!({
            "start": component_starts[components.len() - 2],
            "bank_hash": hx(bank_hash),
            "producer_time_nanos": time,
            "user_agent": hx(b"agave-fixtures/4.4.1"),
        }),
    }
}

fn block_json(block: &BuiltBlock) -> Value {
    json!({
        "slot": block.slot,
        "parent_slot": block.parent.slot,
        "parent_id": hx(block.parent.block_id),
        "block_id": hx(block.id),
        "data_shreds": block.data_shreds.iter().map(hx).collect::<Vec<_>>(),
        "transactions": block.transactions,
        "footer": block.footer,
    })
}

fn footer_cert(validators: &Validators, block: Block, slow: bool) -> BlockFinalizationCert {
    let n = validators.keypairs.len();
    let all: Vec<usize> = (0..n).collect();
    let notar_vote = Vote::new_notarization_vote(block);
    if slow {
        let (final_sig, final_bitmap) =
            validators.aggregate(Vote::new_finalization_vote(block.slot), SHRED_VERSION, &all[2..]);
        let (notar_sig, notar_bitmap) = validators.aggregate(notar_vote, SHRED_VERSION, &all[..7]);
        BlockFinalizationCert {
            slot: block.slot,
            block_id: block.block_id,
            final_aggregate: VotesAggregate::new(
                SignatureCompressed::try_from(&final_sig).unwrap(),
                final_bitmap,
            ),
            notar_aggregate: Some(VotesAggregate::new(
                SignatureCompressed::try_from(&notar_sig).unwrap(),
                notar_bitmap,
            )),
        }
    } else {
        let (sig, bitmap) = validators.aggregate(notar_vote, SHRED_VERSION, &all[..9]);
        BlockFinalizationCert {
            slot: block.slot,
            block_id: block.block_id,
            final_aggregate: VotesAggregate::new(SignatureCompressed::try_from(&sig).unwrap(), bitmap),
            notar_aggregate: None,
        }
    }
}

fn main() {
    let out_path = std::env::args().nth(1).expect("usage: agave-fixtures <output.json>");

    // Ten validators with equal stake make the 60% and 80% lines land exactly
    // on a validator boundary.
    let validators = Validators::new(&[1_000_000; 10]);

    let ledger = get_tmp_ledger_path_auto_delete!();
    let blockstore = Blockstore::open(ledger.path()).unwrap();
    let payer = Keypair::new();
    let blockhash = Hash::new_from_array([0x42; 32]);
    let entry = |i: u64, transactions: Vec<VersionedTransaction>| Entry {
        num_hashes: 1 + i,
        hash: hashv(&[b"entry", &i.to_le_bytes()]),
        transactions,
    };

    let genesis = Block {
        slot: 459_652_999,
        block_id: Hash::new_from_array([0x38; 32]),
    };

    // Block 1: one small batch.
    let b1 = build_block(
        &blockstore,
        genesis.slot + 1,
        genesis,
        vec![vec![
            entry(0, vec![transfer(&payer, blockhash, 1), memo_legacy(&payer, blockhash, b"solana-thin")]),
            entry(1, vec![]),
            entry(2, vec![transfer_v0(&payer, blockhash, 5)]),
        ]],
        None,
    );
    let b1_ref = Block { slot: b1.slot, block_id: b1.id };

    // Block 2 skips a slot. One batch that overflows a FEC set, one small one,
    // and a footer carrying a fast certificate for block 1.
    let big: Vec<Entry> = (0..12)
        .map(|i| entry(i, (0..20).map(|j| transfer(&payer, blockhash, 100 + i * 20 + j)).collect()))
        .collect();
    let b2 = build_block(
        &blockstore,
        b1.slot + 2,
        b1_ref,
        vec![
            big,
            vec![entry(0, vec![
                memo_legacy(&payer, blockhash, &[0xab; 600]),
                transfer_v0(&payer, blockhash, 9),
                memo_legacy(&payer, blockhash, b"anchor"),
            ])],
        ],
        Some(footer_cert(&validators, b1_ref, false)),
    );
    let b2_ref = Block { slot: b2.slot, block_id: b2.id };

    // Block 3: footer carries a slow certificate for block 2.
    let b3 = build_block(
        &blockstore,
        b2.slot + 1,
        b2_ref,
        vec![vec![entry(0, vec![transfer(&payer, blockhash, 77)])]],
        Some(footer_cert(&validators, b2_ref, true)),
    );
    let b3_ref = Block { slot: b3.slot, block_id: b3.id };

    let ranked: Vec<Value> = (0..validators.keypairs.len())
        .map(|rank| json!({ "bls_pubkey": hx(validators.compressed(rank)), "stake": validators.stakes[rank] }))
        .collect();

    let payloads = json!({
        "notarize": hx(get_vote_payload_to_sign(Vote::new_notarization_vote(b3_ref), SHRED_VERSION)),
        "finalize": hx(get_vote_payload_to_sign(Vote::new_finalization_vote(b3_ref.slot), SHRED_VERSION)),
        "slot": b3_ref.slot,
        "block_id": hx(b3_ref.block_id),
    });

    let doc = json!({
        "source": "anza-xyz/agave v4.4.1 (5bb304027fe1a166b02cb26dc8c161593f416fca)",
        "shred_version": SHRED_VERSION,
        "validators": ranked,
        "blocks": [block_json(&b1), block_json(&b2), block_json(&b3)],
        "certificates": certificate_vectors(&validators, b3_ref),
        "vote_payloads": payloads,
        "ranking": rank_vectors(),
        "proofs_of_possession": pop_vectors(),
    });
    std::fs::write(&out_path, serde_json::to_string(&doc).unwrap()).unwrap();
    println!("wrote {out_path}");
}
