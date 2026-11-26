//! The repair protocol's packets, as validators read and write them.
//!
//! A request is one UDP packet: a `u32` kind, an Ed25519 signature, the
//! sender's and the recipient's keys, a millisecond timestamp, a `u32`
//! nonce, then the fields of that kind. The signature covers everything but
//! itself. The first request a validator sees from an address earns a ping
//! instead of an answer; it serves once the pong has come back.
//!
//! Three kinds name a block by its id, and their answers can each be checked
//! against that id alone:
//!
//! | Request | Answer | Checked by |
//! |---|---|---|
//! | `ParentAndFecSetCount` | the parent, the number of FEC sets, a Merkle path | the path leads from the parent leaf to the block id |
//! | `FecSetRoot` | one FEC set's root and a Merkle path | the path leads from the root to the block id |
//! | `WindowIndexForBlockId` | one data shred | the shred's own path leads to its set's root |
//!
//! The two older kinds name a slot (`WindowIndex`, `HighestWindowIndex`).
//! Nothing ties their answers to a block anyone voted for.
//!
//! Both directions are here: the prover writes requests and reads answers,
//! and the tests' stand-in for a validator does the reverse.

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use solana_thin::merkle::{self, Hash, Node};
use solana_thin::shred::DATA_SHRED_SIZE;
use solana_thin::{BlockRef, ParentLink};

const PONG: u32 = 7;
const WINDOW_INDEX: u32 = 8;
const HIGHEST_WINDOW_INDEX: u32 = 9;
const PARENT_AND_FEC_SET_COUNT: u32 = 12;
const FEC_SET_ROOT: u32 = 13;
const WINDOW_INDEX_FOR_BLOCK_ID: u32 = 14;

/// Kind, signature, sender, recipient, timestamp, nonce.
const HEADER_SIZE: usize = 4 + 64 + 32 + 32 + 8 + 4;
/// A ping and a pong are the same size: a kind, a key, 32 bytes, a signature.
const PING_SIZE: usize = 4 + 32 + 32 + 64;
/// Longest Merkle path read from an answer. A block has at most 1,024 FEC
/// sets, which is a path of 11.
const MAX_PATH: usize = 16;
const PING_PONG_PREFIX: &[u8] = b"SOLANA_PING_PONG";

/// The flags a slot's last data shred carries.
pub const LAST_IN_SLOT: u8 = 0b1100_0000;

/// The key repair requests are signed with.
///
/// Validators answer any key, staked or not, so this one is made when the
/// process starts and is never written anywhere.
pub struct Identity(KeyPair);

impl Identity {
    /// A new key from the system's randomness.
    pub fn generate() -> Result<Self, String> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| format!("no randomness from the system: {e}"))?;
        Self::from_seed(seed)
    }

    /// The key for `seed`, for tests that need the same key twice.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, String> {
        KeyPair::try_from_seed(Seed::new(seed))
            .map(Self)
            .map_err(|_| "not a usable key seed".to_string())
    }

    /// The public half, which is how a validator names this client.
    pub fn public_key(&self) -> [u8; 32] {
        *self.0.pk
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        *self.0.sk.sign(message, None)
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity({})", hex::encode(self.public_key()))
    }
}

fn verifies(signer: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    PublicKey::new(*signer)
        .verify(message, &Signature::new(*signature))
        .is_ok()
}

/// What can be asked of a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// The data shred at `index` of whatever block the validator holds for
    /// `slot`.
    WindowIndex {
        /// The slot.
        slot: u64,
        /// The shred's index.
        index: u64,
    },
    /// The highest data shred the validator holds for `slot`, at or above
    /// `index`. From a complete slot that is its last shred.
    HighestWindowIndex {
        /// The slot.
        slot: u64,
        /// The lowest index of interest.
        index: u64,
    },
    /// The parent and FEC set count of `block`.
    ParentAndFecSetCount {
        /// The block, by slot and id.
        block: BlockRef,
    },
    /// The root of one FEC set of `block`.
    FecSetRoot {
        /// The block, by slot and id.
        block: BlockRef,
        /// Index of the set's first shred: a multiple of 32.
        fec_set_index: u32,
    },
    /// The data shred at `index` of `block`.
    WindowIndexForBlockId {
        /// The block, by slot and id.
        block: BlockRef,
        /// The shred's index.
        index: u32,
    },
}

impl Request {
    fn kind(&self) -> u32 {
        match self {
            Request::WindowIndex { .. } => WINDOW_INDEX,
            Request::HighestWindowIndex { .. } => HIGHEST_WINDOW_INDEX,
            Request::ParentAndFecSetCount { .. } => PARENT_AND_FEC_SET_COUNT,
            Request::FecSetRoot { .. } => FEC_SET_ROOT,
            Request::WindowIndexForBlockId { .. } => WINDOW_INDEX_FOR_BLOCK_ID,
        }
    }

    /// The signed packet that asks `recipient` for this.
    pub fn encode(
        &self,
        identity: &Identity,
        recipient: &[u8; 32],
        timestamp_ms: u64,
        nonce: u32,
    ) -> Vec<u8> {
        let mut packet = Vec::with_capacity(HEADER_SIZE + 48);
        packet.extend_from_slice(&self.kind().to_le_bytes());
        packet.extend_from_slice(&[0u8; 64]);
        packet.extend_from_slice(&identity.public_key());
        packet.extend_from_slice(recipient);
        packet.extend_from_slice(&timestamp_ms.to_le_bytes());
        packet.extend_from_slice(&nonce.to_le_bytes());
        match self {
            Request::WindowIndex { slot, index } | Request::HighestWindowIndex { slot, index } => {
                packet.extend_from_slice(&slot.to_le_bytes());
                packet.extend_from_slice(&index.to_le_bytes());
            }
            Request::ParentAndFecSetCount { block } => {
                packet.extend_from_slice(&block.slot.to_le_bytes());
                packet.extend_from_slice(&block.id);
            }
            Request::FecSetRoot {
                block,
                fec_set_index,
            } => {
                packet.extend_from_slice(&block.slot.to_le_bytes());
                packet.extend_from_slice(&block.id);
                packet.extend_from_slice(&fec_set_index.to_le_bytes());
            }
            Request::WindowIndexForBlockId { block, index } => {
                packet.extend_from_slice(&block.slot.to_le_bytes());
                packet.extend_from_slice(&index.to_le_bytes());
                packet.extend_from_slice(&block.id);
            }
        }
        let signature = identity.sign(&signed_part(&packet));
        packet[4..68].copy_from_slice(&signature);
        packet
    }
}

/// What a request's signature covers: the packet without the signature.
fn signed_part(packet: &[u8]) -> Vec<u8> {
    [&packet[..4], &packet[68..]].concat()
}

/// The answer to a ping: proof that this address reads what is sent to it.
pub fn pong(identity: &Identity, token: &[u8; 32]) -> Vec<u8> {
    let hash = merkle::sha256(&[PING_PONG_PREFIX, token]);
    let mut packet = Vec::with_capacity(PING_SIZE);
    packet.extend_from_slice(&PONG.to_le_bytes());
    packet.extend_from_slice(&identity.public_key());
    packet.extend_from_slice(&hash);
    packet.extend_from_slice(&identity.sign(&hash));
    packet
}

/// A packet a validator receives, with its signature checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// The answer to a ping sent with `token`.
    Pong {
        /// Who answers.
        from: [u8; 32],
        /// The token the pong answers.
        token_hash: Hash,
    },
    /// A request.
    Request {
        /// Who asks.
        sender: [u8; 32],
        /// Whom the request is addressed to.
        recipient: [u8; 32],
        /// The sender's clock, in milliseconds since the Unix epoch.
        timestamp_ms: u64,
        /// Echoed at the end of the answer.
        nonce: u32,
        /// What is asked.
        request: Request,
    },
}

impl Incoming {
    /// Reads a packet as a validator does. `None` for anything malformed,
    /// unsigned or of a kind no validator answers.
    pub fn decode(packet: &[u8]) -> Option<Self> {
        let kind = u32::from_le_bytes(*packet.first_chunk()?);
        if kind == PONG {
            if packet.len() != PING_SIZE {
                return None;
            }
            let from: [u8; 32] = packet[4..36].try_into().ok()?;
            let token_hash: Hash = packet[36..68].try_into().ok()?;
            let signature: [u8; 64] = packet[68..].try_into().ok()?;
            return verifies(&from, &token_hash, &signature)
                .then_some(Incoming::Pong { from, token_hash });
        }
        if packet.len() < HEADER_SIZE {
            return None;
        }
        let signature: [u8; 64] = packet[4..68].try_into().ok()?;
        let sender: [u8; 32] = packet[68..100].try_into().ok()?;
        let recipient: [u8; 32] = packet[100..132].try_into().ok()?;
        let timestamp_ms = u64::from_le_bytes(packet[132..140].try_into().ok()?);
        let nonce = u32::from_le_bytes(packet[140..144].try_into().ok()?);
        let tail = &packet[HEADER_SIZE..];
        let u64_at = |at: usize| Some(u64::from_le_bytes(*tail.get(at..)?.first_chunk()?));
        let u32_at = |at: usize| Some(u32::from_le_bytes(*tail.get(at..)?.first_chunk()?));
        let id_at = |at: usize| tail.get(at..)?.first_chunk::<32>().copied();
        let (request, len) = match kind {
            WINDOW_INDEX => (
                Request::WindowIndex {
                    slot: u64_at(0)?,
                    index: u64_at(8)?,
                },
                16,
            ),
            HIGHEST_WINDOW_INDEX => (
                Request::HighestWindowIndex {
                    slot: u64_at(0)?,
                    index: u64_at(8)?,
                },
                16,
            ),
            PARENT_AND_FEC_SET_COUNT => {
                let (slot, id) = (u64_at(0)?, id_at(8)?);
                let block = BlockRef { slot, id };
                (Request::ParentAndFecSetCount { block }, 40)
            }
            FEC_SET_ROOT => {
                let (slot, id) = (u64_at(0)?, id_at(8)?);
                let block = BlockRef { slot, id };
                let fec_set_index = u32_at(40)?;
                (
                    Request::FecSetRoot {
                        block,
                        fec_set_index,
                    },
                    44,
                )
            }
            WINDOW_INDEX_FOR_BLOCK_ID => {
                let (slot, index, id) = (u64_at(0)?, u32_at(8)?, id_at(12)?);
                let block = BlockRef { slot, id };
                (Request::WindowIndexForBlockId { block, index }, 44)
            }
            _ => return None,
        };
        if tail.len() != len || !verifies(&sender, &signed_part(packet), &signature) {
            return None;
        }
        Some(Incoming::Request {
            sender,
            recipient,
            timestamp_ms,
            nonce,
            request,
        })
    }
}

/// A packet a validator sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Not an answer: the validator wants proof that this address reads its
    /// mail. Answer with [`pong`] and ask again.
    Ping {
        /// The validator's key. Its signature over the token was checked.
        from: [u8; 32],
        /// What to hash into the pong.
        token: [u8; 32],
    },
    /// A data shred, as stored.
    Shred {
        /// The shred's 1,203 bytes.
        payload: Vec<u8>,
        /// The nonce of the request it answers.
        nonce: u32,
    },
    /// A block's parent and FEC set count. Unchecked: hold it to the block
    /// id with [`ParentLink::verify`].
    ParentFecSetCount {
        /// The parent, the count and the Merkle path.
        link: ParentLink,
        /// The nonce of the request it answers.
        nonce: u32,
    },
    /// One FEC set's root. Unchecked: hold it to the block id with
    /// [`fec_set_root_is_in`].
    FecSetRoot {
        /// The root, as it appears in the block's tree.
        root: Node,
        /// Merkle path from the root to the block id.
        path: Vec<Node>,
        /// The nonce of the request it answers.
        nonce: u32,
    },
}

/// Which protocol a ping came in, which decides its first four bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingKind {
    /// In answer to a request by slot.
    Slot,
    /// In answer to a request by block id.
    BlockId,
}

fn nodes(bytes: &[u8]) -> Option<Vec<Node>> {
    if bytes.len() % 20 != 0 || bytes.len() / 20 > MAX_PATH {
        return None;
    }
    Some(
        bytes
            .chunks_exact(20)
            .map(|c| c.try_into().unwrap())
            .collect(),
    )
}

/// Splits a length-prefixed byte string that runs to the end of `bytes`.
fn byte_string(bytes: &[u8]) -> Option<&[u8]> {
    let len = u64::from_le_bytes(*bytes.first_chunk()?);
    let rest = &bytes[8..];
    (rest.len() as u64 == len).then_some(rest)
}

impl Reply {
    /// Reads a packet from a validator. `None` for anything that is not one
    /// of the four shapes, or a ping whose signature is wrong.
    pub fn decode(packet: &[u8]) -> Option<Self> {
        // A shred starts with a signature, so only its size tells it apart.
        if packet.len() == DATA_SHRED_SIZE + 4 {
            let (payload, nonce) = packet.split_at(DATA_SHRED_SIZE);
            return Some(Reply::Shred {
                payload: payload.to_vec(),
                nonce: u32::from_le_bytes(nonce.try_into().ok()?),
            });
        }
        let kind = u32::from_le_bytes(*packet.first_chunk()?);
        // Neither of the two answers below can be this size.
        if packet.len() == PING_SIZE {
            if kind != 0 && kind != 2 {
                return None;
            }
            let from: [u8; 32] = packet[4..36].try_into().ok()?;
            let token: [u8; 32] = packet[36..68].try_into().ok()?;
            let signature: [u8; 64] = packet[68..].try_into().ok()?;
            return verifies(&from, &token, &signature).then_some(Reply::Ping { from, token });
        }
        let (body, nonce) = packet[4..].split_last_chunk::<4>()?;
        let nonce = u32::from_le_bytes(*nonce);
        match kind {
            0 => {
                let fec_set_count = u32::from_le_bytes(*body.first_chunk()?);
                let slot = u64::from_le_bytes(*body.get(4..)?.first_chunk()?);
                let id: Hash = *body.get(12..)?.first_chunk()?;
                let path = nodes(byte_string(body.get(44..)?)?)?;
                Some(Reply::ParentFecSetCount {
                    link: ParentLink {
                        parent: BlockRef { slot, id },
                        fec_set_count,
                        path,
                    },
                    nonce,
                })
            }
            1 => {
                let root: Node = *body.first_chunk()?;
                let path = nodes(byte_string(body.get(20..)?)?)?;
                Some(Reply::FecSetRoot { root, path, nonce })
            }
            _ => None,
        }
    }

    /// A validator's ping, signed by `identity`.
    pub fn ping(identity: &Identity, token: &[u8; 32], kind: PingKind) -> Vec<u8> {
        let variant: u32 = match kind {
            PingKind::Slot => 0,
            PingKind::BlockId => 2,
        };
        let mut packet = Vec::with_capacity(PING_SIZE);
        packet.extend_from_slice(&variant.to_le_bytes());
        packet.extend_from_slice(&identity.public_key());
        packet.extend_from_slice(token);
        packet.extend_from_slice(&identity.sign(token));
        packet
    }

    /// The packet a validator sends for an answer. A [`Reply::Ping`] has no
    /// such packet without a key: see [`Reply::ping`].
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut packet = Vec::new();
        let path_bytes = |packet: &mut Vec<u8>, path: &[Node]| {
            packet.extend_from_slice(&(path.len() as u64 * 20).to_le_bytes());
            for node in path {
                packet.extend_from_slice(node);
            }
        };
        match self {
            Reply::Ping { .. } => return None,
            Reply::Shred { payload, nonce } => {
                packet.extend_from_slice(payload);
                packet.extend_from_slice(&nonce.to_le_bytes());
            }
            Reply::ParentFecSetCount { link, nonce } => {
                packet.extend_from_slice(&0u32.to_le_bytes());
                packet.extend_from_slice(&link.fec_set_count.to_le_bytes());
                packet.extend_from_slice(&link.parent.slot.to_le_bytes());
                packet.extend_from_slice(&link.parent.id);
                path_bytes(&mut packet, &link.path);
                packet.extend_from_slice(&nonce.to_le_bytes());
            }
            Reply::FecSetRoot { root, path, nonce } => {
                packet.extend_from_slice(&1u32.to_le_bytes());
                packet.extend_from_slice(root);
                path_bytes(&mut packet, path);
                packet.extend_from_slice(&nonce.to_le_bytes());
            }
        }
        Some(packet)
    }
}

/// The hash a pong must carry for a ping sent with `token`.
pub fn pong_hash(token: &[u8; 32]) -> Hash {
    merkle::sha256(&[PING_PONG_PREFIX, token])
}

/// Whether `root` is the root of FEC set number `set` of `block`, given the
/// block's FEC set count and the path a validator sent.
///
/// The count has to come from a parent link already held to the same block
/// id: it fixes the size of the tree, and with it what an index means.
pub fn fec_set_root_is_in(
    block: &BlockRef,
    fec_set_count: u32,
    set: u32,
    root: &Node,
    path: &[Node],
) -> bool {
    let mut leaf = [0u8; 32];
    leaf[..20].copy_from_slice(root);
    merkle::root_from_path(set as usize, fec_set_count as usize + 1, leaf, path) == Ok(block.id)
}

/// Slot, index and flags of a data shred, read from its header and nothing
/// else. For answers by slot, which are not held to anything.
pub fn shred_header(payload: &[u8]) -> Option<(u64, u32, u8)> {
    if payload.len() < DATA_SHRED_SIZE {
        return None;
    }
    Some((
        u64::from_le_bytes(payload[65..73].try_into().ok()?),
        u32::from_le_bytes(payload[73..77].try_into().ok()?),
        payload[85],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(n: u8) -> Identity {
        Identity::from_seed([n; 32]).unwrap()
    }

    fn block() -> BlockRef {
        BlockRef {
            slot: 0x0102_0304_0506_0708,
            id: [0xab; 32],
        }
    }

    fn every_request() -> Vec<Request> {
        vec![
            Request::WindowIndex { slot: 7, index: 9 },
            Request::HighestWindowIndex { slot: 7, index: 0 },
            Request::ParentAndFecSetCount { block: block() },
            Request::FecSetRoot {
                block: block(),
                fec_set_index: 64,
            },
            Request::WindowIndexForBlockId {
                block: block(),
                index: 65,
            },
        ]
    }

    #[test]
    fn a_request_is_laid_out_as_a_validator_reads_it() {
        let me = identity(1);
        let request = Request::WindowIndexForBlockId {
            block: block(),
            index: 65,
        };
        let packet = request.encode(&me, &[9; 32], 1_700_000_000_123, 0xdead_beef);
        assert_eq!(packet.len(), 144 + 8 + 4 + 32);
        assert_eq!(packet[..4], 14u32.to_le_bytes());
        assert_eq!(packet[68..100], me.public_key());
        assert_eq!(packet[100..132], [9; 32]);
        assert_eq!(packet[132..140], 1_700_000_000_123u64.to_le_bytes());
        assert_eq!(packet[140..144], 0xdead_beefu32.to_le_bytes());
        // Slot, then the index, then the id: the reverse of FecSetRoot.
        assert_eq!(packet[144..152], block().slot.to_le_bytes());
        assert_eq!(packet[152..156], 65u32.to_le_bytes());
        assert_eq!(packet[156..], [0xab; 32]);

        let root = Request::FecSetRoot {
            block: block(),
            fec_set_index: 64,
        }
        .encode(&me, &[9; 32], 1, 2);
        assert_eq!(root[..4], 13u32.to_le_bytes());
        assert_eq!(root[152..184], [0xab; 32]);
        assert_eq!(root[184..], 64u32.to_le_bytes());

        let by_slot = Request::WindowIndex { slot: 7, index: 9 }.encode(&me, &[9; 32], 1, 2);
        assert_eq!(by_slot[..4], 8u32.to_le_bytes());
        assert_eq!(by_slot[144..152], 7u64.to_le_bytes());
        assert_eq!(by_slot[152..], 9u64.to_le_bytes());
    }

    #[test]
    fn the_signature_covers_everything_but_itself() {
        let me = identity(1);
        for request in every_request() {
            let packet = request.encode(&me, &[9; 32], 55, 77);
            assert_eq!(
                Incoming::decode(&packet),
                Some(Incoming::Request {
                    sender: me.public_key(),
                    recipient: [9; 32],
                    timestamp_ms: 55,
                    nonce: 77,
                    request,
                })
            );
            for at in (0..4).chain(68..packet.len()) {
                let mut changed = packet.clone();
                changed[at] ^= 1;
                assert_eq!(Incoming::decode(&changed), None, "byte {at} of {request:?}");
            }
            let mut longer = packet.clone();
            longer.push(0);
            assert_eq!(Incoming::decode(&longer), None);
            assert_eq!(Incoming::decode(&packet[..packet.len() - 1]), None);
        }
    }

    #[test]
    fn a_ping_is_answered_with_a_signed_hash_of_its_token() {
        let (validator, me) = (identity(2), identity(1));
        for kind in [PingKind::Slot, PingKind::BlockId] {
            let ping = Reply::ping(&validator, &[5; 32], kind);
            assert_eq!(ping.len(), 132);
            let Some(Reply::Ping { from, token }) = Reply::decode(&ping) else {
                panic!("a ping decodes");
            };
            assert_eq!((from, token), (validator.public_key(), [5; 32]));
            let answer = pong(&me, &token);
            assert_eq!(
                Incoming::decode(&answer),
                Some(Incoming::Pong {
                    from: me.public_key(),
                    token_hash: pong_hash(&[5; 32]),
                })
            );
            let mut forged = ping.clone();
            forged[40] ^= 1;
            assert_eq!(Reply::decode(&forged), None);
        }
        // The other answer kind a 132-byte packet could claim to be.
        let mut odd = Reply::ping(&validator, &[5; 32], PingKind::Slot);
        odd[0] = 1;
        assert_eq!(Reply::decode(&odd), None);
    }

    #[test]
    fn answers_survive_the_wire() {
        let replies = [
            Reply::Shred {
                payload: vec![7; DATA_SHRED_SIZE],
                nonce: 3,
            },
            Reply::ParentFecSetCount {
                link: ParentLink {
                    parent: block(),
                    fec_set_count: 23,
                    path: vec![[1; 20], [2; 20], [3; 20], [4; 20], [5; 20]],
                },
                nonce: 4,
            },
            Reply::FecSetRoot {
                root: [8; 20],
                path: vec![[1; 20], [2; 20]],
                nonce: 5,
            },
        ];
        for reply in replies {
            let packet = reply.encode().unwrap();
            assert_eq!(Reply::decode(&packet), Some(reply.clone()));
            // One byte short or long is not the same answer.
            assert_ne!(
                Reply::decode(&packet[..packet.len() - 1]),
                Some(reply.clone())
            );
            let mut longer = packet.clone();
            longer.push(0);
            assert_ne!(Reply::decode(&longer), Some(reply));
        }
        assert_eq!(Reply::decode(&[]), None);
        assert_eq!(Reply::decode(&[0; 3]), None);
        assert_eq!(Reply::decode(&9u32.to_le_bytes()), None);
    }

    #[test]
    fn a_path_longer_than_any_block_needs_is_refused() {
        let reply = Reply::FecSetRoot {
            root: [8; 20],
            path: vec![[1; 20]; MAX_PATH + 1],
            nonce: 5,
        };
        assert_eq!(Reply::decode(&reply.encode().unwrap()), None);
    }

    #[test]
    fn a_fec_set_root_is_held_to_the_block_id() {
        let roots: Vec<Hash> = (0..5u8).map(|i| [i; 32]).collect();
        let parent = merkle::sha256(&[b"parent"]);
        let mut leaves = roots.clone();
        leaves.push(parent);
        let tree = merkle::Tree::new(leaves);
        let block = BlockRef {
            slot: 10,
            id: tree.root(),
        };
        let root = merkle::truncate(&roots[3]);
        assert!(fec_set_root_is_in(&block, 5, 3, &root, &tree.path(3)));
        // Another position, another root, a tree of another height.
        assert!(!fec_set_root_is_in(&block, 5, 2, &root, &tree.path(3)));
        assert!(!fec_set_root_is_in(&block, 5, 3, &[9; 20], &tree.path(3)));
        assert!(!fec_set_root_is_in(&block, 2, 3, &root, &tree.path(3)));
        assert!(!fec_set_root_is_in(&block, 8, 3, &root, &tree.path(3)));
        assert!(!fec_set_root_is_in(&block, 3, 3, &root, &tree.path(3)));
    }
}
