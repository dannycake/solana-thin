//! A small chain shared by the integration tests.
#![allow(dead_code)]

use solana_thin::prover::BlockData;
use solana_thin::testkit::*;
use solana_thin::*;

pub const SHRED_VERSION: u16 = 50093;

pub struct World {
    pub validators: TestValidators,
    pub client: ThinClient,
    pub genesis: BlockRef,
    /// Three blocks, each the parent of the next.
    pub blocks: Vec<BlockData>,
}

/// A memo-carrying transaction of roughly `size` bytes.
pub fn sized_transaction(seed: u64, size: usize) -> Vec<u8> {
    let memo = vec![0xa5u8; size.saturating_sub(140)];
    legacy_transaction(seed, &[&memo])
}

/// Twenty validators with uneven stake, a client that trusts them for epoch 0,
/// and a three-block chain:
///
/// * block 1 (slot 1000): one small batch of five transactions;
/// * block 2 (slot 1002): a batch spanning two FEC sets, then a small batch
///   mixing all three transaction encodings, and a footer with a certificate
///   for block 1;
/// * block 3 (slot 1003): one transaction.
pub fn world() -> World {
    let validators = TestValidators::new(20, |i| 1_000_000 + 37_000 * (i as u64 % 7));
    let mut client = ThinClient::new(ClusterParams::mainnet(SHRED_VERSION));
    let set = validators.set();
    let hash = set.hash();
    client.trust_validator_set(0, set, &hash).unwrap();

    let genesis = BlockRef {
        slot: 999,
        id: [0x11; 32],
    };
    let b1 = simple_block(
        1000,
        genesis,
        SHRED_VERSION,
        &[vec![(0..5).map(|i| legacy_transaction(i, &[b"block one"])).collect()]],
        None,
    );
    let cert_b1 = validators.fast_cert(b1.block(), &validators.ranks_reaching(8_000), SHRED_VERSION);
    let big: Vec<Vec<Vec<u8>>> = (0..6)
        .map(|e| (0..25).map(|t| sized_transaction(100 + e * 25 + t, 300)).collect())
        .collect();
    let mixed = vec![vec![
        legacy_transaction(500, &[b"legacy"]),
        v0_transaction(501, &[b"v0", b"second memo"]),
        v1_transaction(502, &[b"v1"]),
        legacy_transaction(503, &[b"anchor:0123456789abcdef"]),
    ]];
    let b2 = simple_block(1002, b1.block(), SHRED_VERSION, &[big, mixed], Some(&cert_b1));
    let b3 = simple_block(
        1003,
        b2.block(),
        SHRED_VERSION,
        &[vec![vec![legacy_transaction(900, &[b"block three"])]]],
        None,
    );
    World {
        validators,
        client,
        genesis,
        blocks: vec![b1, b2, b3],
    }
}

impl World {
    /// A fast certificate for block `i`, signed by just enough stake.
    pub fn fast_cert(&self, i: usize) -> FinalityCert {
        self.validators.fast_cert(
            self.blocks[i].block(),
            &self.validators.ranks_reaching(8_000),
            SHRED_VERSION,
        )
    }

    /// A proof for `signature` in block `i`, certified at that same block.
    pub fn proof(&self, i: usize, signature: &[u8; 64]) -> TxProof {
        prover::prove(self.fast_cert(i), &[&self.blocks[i]], signature, false).unwrap()
    }
}
