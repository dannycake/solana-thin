//! Deterministic validators, transactions and blocks for tests and examples.
//!
//! Nothing here is needed to verify a proof. It exists so that the test suite
//! can build blocks the way a leader does, sign them the way validators do,
//! and then try to cheat.
//!
//! The block builder follows Agave's shredding rules (one component per run of
//! FEC sets, padded with empty shreds, `DATA_COMPLETE` on the last shred of
//! the run). The one shortcut is the coding shreds: their leaves are filler
//! hashes rather than real Reed-Solomon parity. The verifier never looks at
//! parity, only at the Merkle tree, and the conformance suite covers real
//! coding shreds produced by Agave itself.

use crate::block::TxPosition;
use crate::certificate::{
    encode_bitmap, finalize_payload, notarize_payload, Aggregate, BlockRef, FinalityCert,
};
use crate::merkle::{self, Hash, Tree, DATA_SHREDS_PER_FEC_SET};
pub use crate::prover::RawBlock;
use crate::prover::{self, BlockData};
use crate::shred::{
    body_capacity, DataShred, DATA_HEADERS_SIZE, FLAG_DATA_COMPLETE, VARIANT_DATA,
    VARIANT_DATA_RESIGNED,
};
use crate::transaction::MEMO_PROGRAM_ID;
use crate::validator_set::{ProofOfPossession, Validator, ValidatorSet};
use crate::wire::write_short_u16;
use blst::min_pk::{AggregateSignature, SecretKey, Signature};

const SIGNATURE_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const FLAG_LAST_IN_SLOT: u8 = 0b1100_0000;

/// A set of validators whose secret keys the test holds.
pub struct TestValidators {
    secrets: Vec<SecretKey>,
    set: ValidatorSet,
}

impl TestValidators {
    /// `n` validators; `stake(i)` gives the stake of the `i`-th one created.
    /// Afterward validators are addressed by rank, not creation order.
    pub fn new(n: usize, stake: impl Fn(usize) -> u64) -> Self {
        Self::with_seed(0, n, stake)
    }

    /// Like [`new`](Self::new) with a different, unrelated set of keys.
    pub fn with_seed(seed: u64, n: usize, stake: impl Fn(usize) -> u64) -> Self {
        let mut pairs: Vec<(SecretKey, Validator)> = (0..n)
            .map(|i| {
                let ikm = merkle::sha256(&[
                    b"testkit-key",
                    &seed.to_le_bytes(),
                    &(i as u64).to_le_bytes(),
                ]);
                let secret = SecretKey::key_gen(&ikm, &[]).expect("32 bytes of key material");
                let validator = Validator {
                    bls_pubkey: secret.sk_to_pk().compress(),
                    stake: stake(i),
                };
                (secret, validator)
            })
            .collect();
        pairs.sort_by(|a, b| {
            b.1.stake
                .cmp(&a.1.stake)
                .then_with(|| a.1.bls_pubkey.cmp(&b.1.bls_pubkey))
        });
        let set = ValidatorSet::from_ranked(pairs.iter().map(|p| p.1).collect())
            .expect("test validators form a valid set");
        Self {
            secrets: pairs.into_iter().map(|p| p.0).collect(),
            set,
        }
    }

    /// The validator set.
    pub fn set(&self) -> ValidatorSet {
        self.set.clone()
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether there are no validators.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Compressed public key of the validator at `rank`.
    pub fn pubkey(&self, rank: usize) -> [u8; 48] {
        self.set.validators()[rank].bls_pubkey
    }

    /// Secret key of the validator at `rank`, for tests that forge.
    pub fn secret(&self, rank: usize) -> &SecretKey {
        &self.secrets[rank]
    }

    /// One validator's signature over `message`.
    pub fn sign(&self, rank: usize, message: &[u8]) -> Signature {
        self.secrets[rank].sign(message, SIGNATURE_DST, &[])
    }

    /// The aggregate of the given ranks' signatures over `message`.
    pub fn aggregate(&self, ranks: &[usize], message: &[u8]) -> Aggregate {
        let signatures: Vec<Signature> = ranks.iter().map(|r| self.sign(*r, message)).collect();
        Aggregate {
            signature: aggregate_signatures(&signatures),
            bitmap: encode_bitmap(ranks),
        }
    }

    /// A proof of possession for the key at `rank`, registered to `vote_pubkey`.
    pub fn proof_of_possession(&self, rank: usize, vote_pubkey: [u8; 32]) -> ProofOfPossession {
        let mut message = b"ALPENGLOW".to_vec();
        message.extend_from_slice(&vote_pubkey);
        message.extend_from_slice(&self.pubkey(rank));
        ProofOfPossession {
            vote_pubkey,
            signature: self.secrets[rank].sign(&message, POP_DST, &[]).compress(),
        }
    }

    /// The fewest top ranks whose stake reaches `bps` basis points of the total.
    pub fn ranks_reaching(&self, bps: u32) -> Vec<usize> {
        let total = u128::from(self.set.total_stake());
        let mut signed: u128 = 0;
        let mut ranks = Vec::new();
        for (rank, v) in self.set.validators().iter().enumerate() {
            if signed * 10_000 >= total * u128::from(bps) {
                break;
            }
            signed += u128::from(v.stake);
            ranks.push(rank);
        }
        ranks
    }

    /// A fast finality certificate for `block` signed by `ranks`.
    pub fn fast_cert(&self, block: BlockRef, ranks: &[usize], shred_version: u16) -> FinalityCert {
        FinalityCert::Fast {
            block,
            notar: self.aggregate(ranks, &notarize_payload(&block, shred_version)),
        }
    }

    /// A slow finality certificate for `block`.
    pub fn slow_cert(
        &self,
        block: BlockRef,
        notar_ranks: &[usize],
        finalize_ranks: &[usize],
        shred_version: u16,
    ) -> FinalityCert {
        FinalityCert::Slow {
            block,
            finalize: self.aggregate(finalize_ranks, &finalize_payload(block.slot, shred_version)),
            notar: self.aggregate(notar_ranks, &notarize_payload(&block, shred_version)),
        }
    }
}

/// Adds signatures together into one compressed aggregate.
pub fn aggregate_signatures(signatures: &[Signature]) -> [u8; 96] {
    let refs: Vec<&Signature> = signatures.iter().collect();
    AggregateSignature::aggregate(&refs, false)
        .expect("at least one signature")
        .to_signature()
        .compress()
}

fn fake_signature(seed: u64) -> [u8; 64] {
    let a = merkle::sha256(&[b"testkit-sig-a", &seed.to_le_bytes()]);
    let b = merkle::sha256(&[b"testkit-sig-b", &seed.to_le_bytes()]);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&a);
    out[32..].copy_from_slice(&b);
    out
}

/// The signature the transaction builders give the transaction made from `seed`.
pub fn signature_for(seed: u64) -> [u8; 64] {
    fake_signature(seed)
}

fn payer(seed: u64) -> Hash {
    merkle::sha256(&[b"testkit-payer", &seed.to_le_bytes()])
}

fn legacy_message(seed: u64, memos: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![1, 0, 1];
    write_short_u16(&mut out, 2);
    out.extend_from_slice(&payer(seed));
    out.extend_from_slice(&MEMO_PROGRAM_ID);
    out.extend_from_slice(&merkle::sha256(&[
        b"testkit-blockhash",
        &seed.to_le_bytes(),
    ]));
    write_short_u16(&mut out, memos.len() as u16);
    for memo in memos {
        out.push(1);
        write_short_u16(&mut out, 0);
        write_short_u16(&mut out, memo.len() as u16);
        out.extend_from_slice(memo);
    }
    out
}

/// A legacy transaction with one Memo instruction per element of `memos`.
/// The signature is filler: the verifier relies on the validators for that.
pub fn legacy_transaction(seed: u64, memos: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&fake_signature(seed));
    out.extend_from_slice(&legacy_message(seed, memos));
    out
}

/// A version 0 transaction with Memo instructions and one address table lookup.
pub fn v0_transaction(seed: u64, memos: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&fake_signature(seed));
    out.push(0x80);
    out.extend_from_slice(&legacy_message(seed, memos));
    write_short_u16(&mut out, 1);
    out.extend_from_slice(&[0x17; 32]);
    write_short_u16(&mut out, 2);
    out.extend_from_slice(&[1, 2]);
    write_short_u16(&mut out, 1);
    out.push(3);
    out
}

/// A version 1 transaction with Memo instructions, a priority fee and a
/// compute unit limit.
pub fn v1_transaction(seed: u64, memos: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0x81, 1, 0, 1];
    out.extend_from_slice(&0b111u32.to_le_bytes());
    out.extend_from_slice(&merkle::sha256(&[
        b"testkit-blockhash",
        &seed.to_le_bytes(),
    ]));
    out.push(memos.len() as u8);
    out.push(2);
    out.extend_from_slice(&payer(seed));
    out.extend_from_slice(&MEMO_PROGRAM_ID);
    out.extend_from_slice(&5_000u64.to_le_bytes());
    out.extend_from_slice(&200_000u32.to_le_bytes());
    for memo in memos {
        out.extend_from_slice(&[1, 0]);
        out.extend_from_slice(&(memo.len() as u16).to_le_bytes());
    }
    for memo in memos {
        out.extend_from_slice(memo);
    }
    out.extend_from_slice(&fake_signature(seed));
    out
}

fn marker(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = 0u64.to_le_bytes().to_vec();
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(kind);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn parent_body(parent: &BlockRef) -> Vec<u8> {
    let mut body = vec![1];
    body.extend_from_slice(&parent.slot.to_le_bytes());
    body.extend_from_slice(&parent.id);
    body
}

/// The header marker naming `parent`.
pub fn header_component(parent: &BlockRef) -> Vec<u8> {
    marker(1, &parent_body(parent))
}

/// An UpdateParent marker switching to `parent`.
pub fn update_parent_component(parent: &BlockRef) -> Vec<u8> {
    marker(2, &parent_body(parent))
}

/// A footer marker.
pub fn footer_component(
    bank_hash: Hash,
    producer_time_nanos: u64,
    user_agent: &[u8],
    finality: Option<&FinalityCert>,
) -> Vec<u8> {
    let aggregate = |out: &mut Vec<u8>, a: &Aggregate| {
        out.extend_from_slice(&a.signature);
        out.extend_from_slice(&(a.bitmap.len() as u16).to_le_bytes());
        out.extend_from_slice(&a.bitmap);
    };
    let mut body = vec![1];
    body.extend_from_slice(&bank_hash);
    body.extend_from_slice(&producer_time_nanos.to_le_bytes());
    body.push(user_agent.len() as u8);
    body.extend_from_slice(user_agent);
    match finality {
        None => body.push(0),
        Some(cert) => {
            body.push(1);
            let block = cert.block();
            body.extend_from_slice(&block.slot.to_le_bytes());
            body.extend_from_slice(&block.id);
            match cert {
                FinalityCert::Fast { notar, .. } => {
                    aggregate(&mut body, notar);
                    body.push(0);
                }
                FinalityCert::Slow {
                    finalize, notar, ..
                } => {
                    aggregate(&mut body, finalize);
                    body.push(1);
                    aggregate(&mut body, notar);
                }
            }
        }
    }
    // No skip reward certificate, no notarization reward certificate.
    body.extend_from_slice(&[0, 0]);
    marker(0, &body)
}

/// An entry batch: one entry per inner vector, holding those transactions.
pub fn entry_batch(entries: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut out = (entries.len() as u64).to_le_bytes().to_vec();
    for (i, transactions) in entries.iter().enumerate() {
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&merkle::sha256(&[
            b"testkit-entry",
            &(i as u64).to_le_bytes(),
        ]));
        out.extend_from_slice(&(transactions.len() as u64).to_le_bytes());
        for tx in transactions {
            out.extend_from_slice(tx);
        }
    }
    out
}

/// Cuts components into data shreds and builds the block's Merkle trees.
pub struct BlockBuilder {
    slot: u64,
    parent: BlockRef,
    shred_version: u16,
    variant: u8,
    shreds: Vec<DataShred>,
}

impl BlockBuilder {
    /// Starts a block. No component is added implicitly, not even the header.
    pub fn new(slot: u64, parent: BlockRef, shred_version: u16) -> Self {
        Self {
            slot,
            parent,
            shred_version,
            variant: VARIANT_DATA,
            shreds: Vec::new(),
        }
    }

    /// Makes subsequent shreds of the "resigned" variant, with its shorter body.
    pub fn resigned(mut self, resigned: bool) -> Self {
        self.variant = if resigned {
            VARIANT_DATA_RESIGNED
        } else {
            VARIANT_DATA
        };
        self
    }

    /// Index the next component will start at.
    pub fn next_index(&self) -> u32 {
        self.shreds.len() as u32
    }

    /// Adds the header marker for the block's parent.
    pub fn header(self) -> Self {
        let bytes = header_component(&self.parent);
        self.component(&bytes)
    }

    /// Adds one component: its bytes cut into shreds, padded with empty shreds
    /// to a whole number of FEC sets, the last one flagged `DATA_COMPLETE`.
    pub fn component(mut self, bytes: &[u8]) -> Self {
        let capacity = body_capacity(self.variant).unwrap();
        let parent_offset = (self.slot - self.parent.slot) as u16;
        let mut chunks: Vec<&[u8]> = bytes.chunks(capacity).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        while chunks.len() % DATA_SHREDS_PER_FEC_SET != 0 {
            chunks.push(&[]);
        }
        for chunk in chunks {
            let trimmed = chunk.len() - chunk.iter().rev().take_while(|b| **b == 0).count();
            self.shreds.push(DataShred {
                variant: self.variant,
                parent_offset,
                flags: 0,
                size: (DATA_HEADERS_SIZE + chunk.len()) as u16,
                body: chunk[..trimmed].to_vec(),
            });
        }
        self.shreds.last_mut().unwrap().flags |= FLAG_DATA_COMPLETE;
        self
    }

    /// Appends shreds exactly as given: no padding to a whole FEC set, no
    /// flags set. For layouts [`component`](Self::component) cannot make,
    /// such as a component that ends mid-set. The block must still come to
    /// a whole number of FEC sets before [`build`](Self::build).
    pub fn push_shreds(mut self, shreds: impl IntoIterator<Item = DataShred>) -> Self {
        self.shreds.extend(shreds);
        self
    }

    /// A shred holding `data`, with this builder's variant and parent offset
    /// and no flags. `data` must fit one shred.
    pub fn shred(&self, data: &[u8]) -> DataShred {
        assert!(data.len() <= body_capacity(self.variant).unwrap());
        let trimmed = data.len() - data.iter().rev().take_while(|b| **b == 0).count();
        DataShred {
            variant: self.variant,
            parent_offset: (self.slot - self.parent.slot) as u16,
            flags: 0,
            size: (DATA_HEADERS_SIZE + data.len()) as u16,
            body: data[..trimmed].to_vec(),
        }
    }

    /// Direct access to a shred, for tests that need a malformed block.
    pub fn shred_mut(&mut self, index: u32) -> &mut DataShred {
        &mut self.shreds[index as usize]
    }

    /// Finishes the block: returns every data shred as a full wire payload.
    pub fn build(mut self) -> Vec<Vec<u8>> {
        assert!(!self.shreds.is_empty() && self.shreds.len() % DATA_SHREDS_PER_FEC_SET == 0);
        self.shreds.last_mut().unwrap().flags |= FLAG_LAST_IN_SLOT;
        let mut payloads = Vec::with_capacity(self.shreds.len());
        let mut chained_root = merkle::sha256(&[b"testkit-chain", &self.parent.id]);
        for (set, shreds) in self.shreds.chunks(DATA_SHREDS_PER_FEC_SET).enumerate() {
            let fec_set_index = (set * DATA_SHREDS_PER_FEC_SET) as u32;
            let leaf_bytes: Vec<Vec<u8>> = shreds
                .iter()
                .enumerate()
                .map(|(i, shred)| {
                    // Unchecked: tests build shreds no validator would keep.
                    shred
                        .leaf_bytes_unchecked(
                            self.slot,
                            fec_set_index + i as u32,
                            self.shred_version,
                            fec_set_index,
                            &chained_root,
                        )
                        .expect("a known variant and a body that fits")
                })
                .collect();
            let mut leaves: Vec<Hash> = leaf_bytes.iter().map(|b| merkle::shred_leaf(b)).collect();
            for i in 0..DATA_SHREDS_PER_FEC_SET as u64 {
                leaves.push(merkle::sha256(&[
                    b"testkit-coding",
                    &self.slot.to_le_bytes(),
                    &(set as u64).to_le_bytes(),
                    &i.to_le_bytes(),
                ]));
            }
            let tree = Tree::new(leaves);
            for (i, leaf) in leaf_bytes.iter().enumerate() {
                let mut payload = vec![0u8; 64];
                payload.extend_from_slice(leaf);
                for node in tree.path(i) {
                    payload.extend_from_slice(&node);
                }
                payload.resize(crate::shred::DATA_SHRED_SIZE, 0);
                payloads.push(payload);
            }
            chained_root = tree.root();
        }
        payloads
    }
}

/// A block with a header, the given entry batches (each a list of entries,
/// each a list of transactions) and a footer.
pub fn simple_block(
    slot: u64,
    parent: BlockRef,
    shred_version: u16,
    batches: &[Vec<Vec<Vec<u8>>>],
    footer_cert: Option<&FinalityCert>,
) -> BlockData {
    let mut builder = BlockBuilder::new(slot, parent, shred_version).header();
    for batch in batches {
        builder = builder.component(&entry_batch(batch));
    }
    let footer = footer_component(
        merkle::sha256(&[b"testkit-bank", &slot.to_le_bytes()]),
        1_792_590_840_000_000_000 + slot * 400_000_000,
        b"testkit",
        footer_cert,
    );
    let tick = entry_batch(&[vec![]]);
    let payloads = builder.component(&footer).component(&tick).build();
    BlockData::from_shreds(&payloads).expect("builder output is a valid block")
}

/// A ready-made validator set, block and proof, for documentation examples.
pub struct DemoWorld {
    /// Hash of `set`.
    pub set_hash: Hash,
    /// The validators of epoch 0.
    pub set: ValidatorSet,
    /// An encoded proof for the transaction with `signature`.
    pub proof_bytes: Vec<u8>,
    /// The proven transaction's signature.
    pub signature: [u8; 64],
    /// Where the transaction sits.
    pub position: TxPosition,
}

/// Builds a [`DemoWorld`] on shred version 50093.
pub fn demo_world() -> DemoWorld {
    let validators = TestValidators::new(12, |i| 1_000 + i as u64);
    let genesis = BlockRef {
        slot: 99,
        id: [9; 32],
    };
    let txs: Vec<Vec<u8>> = (0..5).map(|i| legacy_transaction(i, &[b"hello"])).collect();
    let block = simple_block(100, genesis, 50093, &[vec![txs]], None);
    let cert = validators.fast_cert(block.block(), &validators.ranks_reaching(8_000), 50093);
    let signature = signature_for(3);
    let proof =
        prover::prove(cert, &[&block], &signature, true).expect("transaction is in the block");
    DemoWorld {
        set_hash: validators.set().hash(),
        set: validators.set(),
        proof_bytes: proof.to_bytes().expect("a small proof encodes"),
        signature,
        position: proof.position,
    }
}
