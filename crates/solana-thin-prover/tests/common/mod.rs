//! A stand-in for a cluster: blocks built with the verifier's testkit, and
//! validators on loopback that serve them over the repair protocol, some of
//! them dishonestly.
#![allow(dead_code)]

use serde_json::{json, Value};
use solana_thin::merkle::{self, Hash, Tree};
use solana_thin::prover::BlockData;
use solana_thin::shred::RawDataShred;
use solana_thin::testkit::{
    entry_batch, footer_component, legacy_transaction, signature_for, BlockBuilder, TestValidators,
};
use solana_thin::{BlockRef, ClusterParams, FinalityCert, ParentLink, ThinClient};
use solana_thin_prover::fetch::{FetchConfig, Fetcher};
use solana_thin_prover::prove::{Prover, ProverConfig};
use solana_thin_prover::wire::{pong_hash, Identity, Incoming, PingKind, Reply, Request};
use solana_thin_prover::{Net, PeerBook, Schedule, Store, Trust};
use solana_thin_setlog::{SetFile, Source, KIND_SNAPSHOT};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// The test cluster's shred version.
pub const VERSION: u16 = 4242;
/// Its name in set files.
pub const CLUSTER: &str = "localnet";
/// Transactions in every block.
pub const TRANSACTIONS: u64 = 3;

/// A block as a leader would have shredded it.
#[derive(Clone)]
pub struct Built {
    pub block: BlockRef,
    pub parent: BlockRef,
    pub payloads: Vec<Vec<u8>>,
    pub signatures: Vec<[u8; 64]>,
}

/// Builds the block of `slot` on `parent`: a header, one batch holding the
/// transactions made from `seeds`, a footer carrying `certificate`, a tick.
pub fn build(
    slot: u64,
    parent: BlockRef,
    seeds: &[u64],
    certificate: Option<&FinalityCert>,
) -> Built {
    let transactions: Vec<Vec<u8>> = seeds
        .iter()
        .map(|seed| legacy_transaction(*seed, &[b"prover test"]))
        .collect();
    let footer = footer_component(
        merkle::sha256(&[b"bank", &slot.to_le_bytes()]),
        1_792_590_840_000_000_000 + slot * 400_000_000,
        b"testkit",
        certificate,
    );
    let payloads = BlockBuilder::new(slot, parent, VERSION)
        .header()
        .component(&entry_batch(&[transactions]))
        .component(&footer)
        .component(&entry_batch(&[vec![]]))
        .build();
    let block = BlockData::from_shreds(&payloads).unwrap().block();
    Built {
        block,
        parent,
        payloads,
        signatures: seeds.iter().map(|seed| signature_for(*seed)).collect(),
    }
}

/// A finalized chain and the validators that signed it.
pub struct Chain {
    pub slots_per_epoch: u64,
    validators: Vec<TestValidators>,
    pub blocks: BTreeMap<u64, Built>,
    tip: BlockRef,
}

impl Chain {
    /// An empty chain whose first block will build on `parent_slot`.
    pub fn new(slots_per_epoch: u64, parent_slot: u64) -> Self {
        Self {
            slots_per_epoch,
            validators: (0..8)
                .map(|epoch| TestValidators::with_seed(epoch, 5, |i| 1_000 + i as u64))
                .collect(),
            blocks: BTreeMap::new(),
            tip: BlockRef {
                slot: parent_slot,
                id: [9; 32],
            },
        }
    }

    /// Blocks at `slots`, each one's footer carrying the certificate for
    /// the block before it. One epoch, long enough never to end.
    pub fn linear(slots: impl IntoIterator<Item = u64>) -> Self {
        let mut chain = Self::new(432_000, 99);
        for slot in slots {
            let before = chain.tip.slot;
            chain.push(slot, Some(before));
        }
        chain
    }

    pub fn epoch_of(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    pub fn validators(&self, epoch: u64) -> &TestValidators {
        &self.validators[epoch as usize]
    }

    /// The fast certificate the validators of its epoch give the block of
    /// `slot`.
    pub fn certificate(&self, slot: u64) -> FinalityCert {
        let validators = self.validators(self.epoch_of(slot));
        validators.fast_cert(
            self.blocks[&slot].block,
            &validators.ranks_reaching(8_000),
            VERSION,
        )
    }

    /// The seeds of the transactions in the block of `slot`.
    pub fn seeds(slot: u64) -> Vec<u64> {
        (0..TRANSACTIONS).map(|i| slot * 100 + i).collect()
    }

    /// Adds the block of `slot` on the tip. Its footer carries the
    /// certificate for the block of `carries`, if that block exists.
    pub fn push(&mut self, slot: u64, carries: Option<u64>) -> BlockRef {
        let certificate = carries
            .filter(|slot| self.blocks.contains_key(slot))
            .map(|slot| self.certificate(slot));
        self.push_with(slot, certificate.as_ref())
    }

    /// Adds the block of `slot` on the tip with this footer certificate.
    pub fn push_with(&mut self, slot: u64, certificate: Option<&FinalityCert>) -> BlockRef {
        let built = build(slot, self.tip, &Self::seeds(slot), certificate);
        self.tip = built.block;
        self.blocks.insert(slot, built);
        self.tip
    }

    /// Adds a block built elsewhere on the tip.
    pub fn adopt(&mut self, built: Built) {
        assert_eq!(built.parent, self.tip);
        self.tip = built.block;
        self.blocks.insert(built.block.slot, built);
    }

    pub fn tip(&self) -> BlockRef {
        self.tip
    }

    pub fn block(&self, slot: u64) -> BlockRef {
        self.blocks[&slot].block
    }

    pub fn signature(&self, slot: u64, n: usize) -> [u8; 64] {
        self.blocks[&slot].signatures[n]
    }

    pub fn set_file(&self, epoch: u64) -> SetFile {
        SetFile::new(
            CLUSTER,
            VERSION,
            epoch,
            self.validators(epoch).set().to_bytes(),
            vec![Source::new(KIND_SNAPSHOT, "node-1", epoch * self.slots_per_epoch).unwrap()],
        )
        .unwrap()
    }

    /// What a prover pins when given the sets of `epochs`.
    pub fn trust(&self, epochs: &[u64]) -> Arc<Trust> {
        let files = epochs.iter().map(|epoch| self.set_file(*epoch)).collect();
        Arc::new(Trust::new(files, None, Schedule::Flat(self.slots_per_epoch)).unwrap())
    }

    /// A verifier that has only the sets and the shred version: what a
    /// client of the prover holds.
    pub fn client(&self, epochs: &[u64]) -> ThinClient {
        let params = ClusterParams::without_warmup(VERSION, self.slots_per_epoch).unwrap();
        let mut client = ThinClient::new(params);
        for epoch in epochs {
            let set = self.validators(*epoch).set();
            let hash = set.hash();
            client.trust_validator_set(*epoch, set, &hash).unwrap();
        }
        client
    }
}

/// How a stand-in validator misbehaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    /// Serves what it holds, after a ping, as a validator does.
    Honest,
    /// Never sends anything, not even a ping.
    Silent,
    /// Sends every answer twice.
    Duplicates,
    /// Changes a byte in every shred it serves by block id.
    CorruptShreds,
    /// Serves the shred after the one asked for.
    WrongIndex,
    /// Answers every request by block id from another block it holds.
    OtherBlock,
    /// Names another parent.
    WrongParent,
    /// Changes a byte in every FEC set root.
    CorruptRoots,
    /// Leaves every third request unanswered.
    Lossy,
    /// Sends the parent link and the roots, and never a shred.
    WithholdsShreds,
}

struct Served {
    block: BlockRef,
    parent: BlockRef,
    payloads: Vec<Vec<u8>>,
    roots: Vec<Hash>,
    tree: Tree,
}

impl Served {
    fn new(built: &Built) -> Self {
        let roots: Vec<Hash> = built
            .payloads
            .chunks(32)
            .map(|set| {
                RawDataShred::parse_layout(&set[0])
                    .unwrap()
                    .fec_set_root()
                    .unwrap()
            })
            .collect();
        let mut leaves = roots.clone();
        leaves.push(merkle::sha256(&[
            &built.parent.slot.to_le_bytes(),
            &built.parent.id,
            &(roots.len() as u32).to_le_bytes(),
        ]));
        let tree = Tree::new(leaves);
        assert_eq!(tree.root(), built.block.id);
        Self {
            block: built.block,
            parent: built.parent,
            payloads: built.payloads.clone(),
            roots,
            tree,
        }
    }
}

struct State {
    behavior: Behavior,
    by_id: HashMap<Hash, Served>,
    by_slot: HashMap<u64, Vec<Vec<u8>>>,
    decoy: Option<Served>,
    ponged: HashSet<SocketAddr>,
    tokens: HashMap<SocketAddr, [u8; 32]>,
    seen: Vec<Request>,
    counter: u64,
}

/// A validator on loopback.
pub struct FakePeer {
    pub id: [u8; 32],
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakePeer {
    /// Starts a validator that holds every block of `chain`, by id and by
    /// slot, and behaves as `behavior` says.
    pub fn start(seed: u8, chain: &Chain, behavior: Behavior) -> Self {
        let identity = Identity::from_seed([seed; 32]).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            behavior,
            by_id: chain
                .blocks
                .values()
                .map(|built| (built.block.id, Served::new(built)))
                .collect(),
            by_slot: chain
                .blocks
                .iter()
                .map(|(slot, built)| (*slot, built.payloads.clone()))
                .collect(),
            decoy: None,
            ponged: HashSet::new(),
            tokens: HashMap::new(),
            seen: Vec::new(),
            counter: 0,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let id = identity.public_key();
        let thread = {
            let (state, stop) = (Arc::clone(&state), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut buffer = [0u8; 2048];
                while !stop.load(Ordering::SeqCst) {
                    let Ok((len, from)) = socket.recv_from(&mut buffer) else {
                        continue;
                    };
                    let mut state = state.lock().unwrap();
                    for packet in state.handle(&identity, &buffer[..len], from) {
                        let _ = socket.send_to(&packet, from);
                    }
                }
            })
        };
        Self {
            id,
            addr,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// Changes how it behaves from now on.
    pub fn behave(&self, behavior: Behavior) {
        self.state.lock().unwrap().behavior = behavior;
    }

    /// Makes it serve `built` when asked for that block's slot, in place of
    /// the finalized block: a block the cluster abandoned.
    pub fn serve_by_slot(&self, built: &Built) {
        self.state
            .lock()
            .unwrap()
            .by_slot
            .insert(built.block.slot, built.payloads.clone());
    }

    /// Makes it hold `built` by id as well.
    pub fn hold(&self, built: &Built) {
        let mut state = self.state.lock().unwrap();
        state.by_id.insert(built.block.id, Served::new(built));
    }

    /// Makes it forget the block of `slot`, by slot and by id.
    pub fn forget(&self, slot: u64) {
        let mut state = self.state.lock().unwrap();
        state.by_slot.remove(&slot);
        state.by_id.retain(|_, served| served.block.slot != slot);
    }

    /// The block [`Behavior::OtherBlock`] answers from.
    pub fn set_decoy(&self, built: &Built) {
        self.state.lock().unwrap().decoy = Some(Served::new(built));
    }

    /// Every request it answered or chose not to, in order.
    pub fn seen(&self) -> Vec<Request> {
        self.state.lock().unwrap().seen.clone()
    }

    /// How many of those were by slot and by block id.
    pub fn seen_by_kind(&self) -> (usize, usize) {
        let seen = self.seen();
        let by_slot = seen
            .iter()
            .filter(|request| {
                matches!(
                    request,
                    Request::WindowIndex { .. } | Request::HighestWindowIndex { .. }
                )
            })
            .count();
        (by_slot, seen.len() - by_slot)
    }

    /// Its entry in a `getClusterNodes` answer.
    pub fn node(&self) -> Value {
        json!({
            "pubkey": bs58::encode(self.id).into_string(),
            "serveRepair": self.addr.to_string(),
            "shredVersion": VERSION,
            "version": "4.4.1",
            "clientId": "Agave",
            "gossip": null,
        })
    }
}

impl Drop for FakePeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl State {
    /// The packets to send back for one received packet.
    fn handle(&mut self, identity: &Identity, packet: &[u8], from: SocketAddr) -> Vec<Vec<u8>> {
        if self.behavior == Behavior::Silent {
            return vec![];
        }
        let (nonce, request) = match Incoming::decode(packet) {
            Some(Incoming::Pong { token_hash, .. }) => {
                if self.tokens.get(&from).map(pong_hash) == Some(token_hash) {
                    self.ponged.insert(from);
                }
                return vec![];
            }
            Some(Incoming::Request {
                recipient,
                nonce,
                request,
                ..
            }) if recipient == identity.public_key() => (nonce, request),
            _ => return vec![],
        };
        if !self.ponged.contains(&from) {
            self.counter += 1;
            let token = merkle::sha256(&[b"token", &self.counter.to_le_bytes()]);
            self.tokens.insert(from, token);
            let kind = match request {
                Request::WindowIndex { .. } | Request::HighestWindowIndex { .. } => PingKind::Slot,
                _ => PingKind::BlockId,
            };
            return vec![Reply::ping(identity, &token, kind)];
        }
        self.seen.push(request);
        self.counter += 1;
        if self.behavior == Behavior::Lossy && self.counter % 3 == 0 {
            return vec![];
        }
        let Some(reply) = self.reply(nonce, &request) else {
            return vec![];
        };
        let packet = reply.encode().unwrap();
        if self.behavior == Behavior::Duplicates {
            vec![packet.clone(), packet]
        } else {
            vec![packet]
        }
    }

    fn served(&self, block: &BlockRef) -> Option<&Served> {
        if self.behavior == Behavior::OtherBlock {
            return self.decoy.as_ref();
        }
        self.by_id
            .get(&block.id)
            .filter(|served| served.block.slot == block.slot)
    }

    fn reply(&self, nonce: u32, request: &Request) -> Option<Reply> {
        match request {
            Request::WindowIndex { slot, index } => {
                let payload = self.by_slot.get(slot)?.get(*index as usize)?.clone();
                Some(Reply::Shred { payload, nonce })
            }
            Request::HighestWindowIndex { slot, .. } => {
                let payload = self.by_slot.get(slot)?.last()?.clone();
                Some(Reply::Shred { payload, nonce })
            }
            Request::ParentAndFecSetCount { block } => {
                let served = self.served(block)?;
                let mut parent = served.parent;
                if self.behavior == Behavior::WrongParent {
                    parent.id[0] ^= 1;
                }
                let link = ParentLink {
                    parent,
                    fec_set_count: served.roots.len() as u32,
                    path: served.tree.path(served.roots.len()),
                };
                Some(Reply::ParentFecSetCount { link, nonce })
            }
            Request::FecSetRoot {
                block,
                fec_set_index,
            } => {
                let served = self.served(block)?;
                let set = (*fec_set_index / 32) as usize;
                let mut root = merkle::truncate(served.roots.get(set)?);
                if self.behavior == Behavior::CorruptRoots {
                    root[0] ^= 1;
                }
                let path = served.tree.path(set);
                Some(Reply::FecSetRoot { root, path, nonce })
            }
            Request::WindowIndexForBlockId { block, index } => {
                let served = self.served(block)?;
                let index = match self.behavior {
                    Behavior::WithholdsShreds => return None,
                    Behavior::WrongIndex => (*index as usize + 1) % served.payloads.len(),
                    _ => *index as usize,
                };
                let mut payload = served.payloads.get(index)?.clone();
                if self.behavior == Behavior::CorruptShreds {
                    payload[100] ^= 1;
                }
                Some(Reply::Shred { payload, nonce })
            }
        }
    }
}

/// A `getClusterNodes` answer listing `peers`.
pub fn nodes(peers: &[&FakePeer]) -> Value {
    json!(peers.iter().map(|peer| peer.node()).collect::<Vec<_>>())
}

/// A directory of its own for one test, empty at the start.
pub fn directory(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("prover")
        .join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fetch settings for loopback: nothing takes long there, so a missing
/// answer is noticed quickly.
pub fn quick() -> FetchConfig {
    FetchConfig {
        holders: 3,
        max_asked: 6,
        footer_peers: 2,
        round_wait: Duration::from_millis(250),
        max_rounds: 6,
        ..FetchConfig::default()
    }
}

/// A fetcher that asks `peers`, quickly.
pub fn fetcher(peers: &[&FakePeer], config: FetchConfig) -> Fetcher {
    let (book, census) = PeerBook::from_cluster_nodes(&nodes(peers), VERSION, 7);
    assert_eq!(census.kept, peers.len());
    let net = Net::open("127.0.0.1:0".parse().unwrap(), 20_000).unwrap();
    Fetcher::new(net, book, config)
}

/// A prover over `chain`'s epoch-zero set (or `epochs`), a fresh store
/// directory and `peers`.
pub fn prover(test: &str, chain: &Chain, epochs: &[u64], peers: &[&FakePeer]) -> Prover {
    let store = Arc::new(Store::open(&directory(test), 64 << 20).unwrap());
    Prover::new(
        chain.trust(epochs),
        store,
        fetcher(peers, quick()),
        searching(),
    )
}

/// Prover settings for loopback: a short window, read twice, quickly.
pub fn searching() -> ProverConfig {
    ProverConfig {
        certificate_window: 6,
        certificate_passes: 2,
        pass_wait: Duration::from_millis(30),
        ..ProverConfig::default()
    }
}
