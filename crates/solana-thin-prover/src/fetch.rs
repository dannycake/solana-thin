//! Getting blocks out of validators.
//!
//! Two ways, with different standing:
//!
//! * **By block id** ([`Fetcher::block`], [`Fetcher::parent`]). Given an id
//!   a finality certificate names, every answer is held to that id as it
//!   arrives: the parent link by its Merkle path, each FEC set root by its
//!   path, each shred by its own path to its set's root. What comes out is
//!   that block or nothing. This is the only way shreds are fetched.
//! * **By slot** ([`Fetcher::footer`]). Reads the tail of whatever block a
//!   peer holds for a slot and returns the footer found there. Nothing ties
//!   the answer to a block anyone voted for; a peer can serve a block the
//!   cluster abandoned. It is used for one thing, finding finality
//!   certificates, which carry their own proof.

use crate::net::{Net, NetStats};
use crate::peers::PeerBook;
use crate::refusal::Refusal;
use crate::wire::{self, Reply, Request, LAST_IN_SLOT};
use solana_thin::block::{self, Marker};
use solana_thin::merkle::{Hash, Node, DATA_SHREDS_PER_FEC_SET};
use solana_thin::shred::RawDataShred;
use solana_thin::{BlockRef, Footer, ParentLink};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

const PER_SET: u32 = DATA_SHREDS_PER_FEC_SET as u32;
/// Requests a holder may leave unanswered, having answered none for this
/// block, before it stops being asked for it.
const HOLDER_PATIENCE: u32 = 8;
/// Answers that fail their check before a holder stops being asked.
const HOLDER_LIES: u32 = 3;
/// Peers not yet heard from that are tried alongside each question.
const SCOUTS: usize = 2;
/// Blocks whose holders are remembered.
const HOLDERS_REMEMBERED: usize = 256;

/// How hard to try, and how politely.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Peers a block is spread over. More are asked only while fewer than
    /// this hold it.
    pub holders: usize,
    /// Most peers ever asked whether they hold one block.
    pub max_asked: usize,
    /// How many peers to get to know. While fewer have been heard from,
    /// each block is also asked of two that have not, so that the work
    /// does not stay with whoever answered first.
    pub pool: usize,
    /// Peers asked for a slot's tail when looking for a footer.
    pub footer_peers: usize,
    /// How long to wait for the answers to a round of requests before
    /// asking again for what is missing.
    pub round_wait: Duration,
    /// Rounds of asking for a block's missing pieces before giving up.
    pub max_rounds: u32,
    /// FEC sets read back from the end of a slot when looking for its
    /// footer.
    pub tail_sets: u32,
    /// Requests in a row with no packet from any peer before the fetcher
    /// stops asking.
    pub silence_limit: u64,
    /// How long it then stays quiet.
    pub cooldown: Duration,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            holders: 8,
            max_asked: 32,
            pool: 64,
            footer_peers: 3,
            round_wait: Duration::from_millis(450),
            max_rounds: 10,
            tail_sets: 4,
            silence_limit: 400,
            cooldown: Duration::from_secs(60),
        }
    }
}

/// What one fetch cost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchStats {
    /// Requests sent.
    pub requests: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Peers that showed they hold the block.
    pub holders: usize,
    /// Answers that failed their check against the block id.
    pub rejected: u64,
    /// Second copies of an answer.
    pub duplicates: u64,
    /// Pieces asked for more than once.
    pub retries: u64,
    /// Time taken.
    pub elapsed: Duration,
}

/// A block as fetched by id: every shred held to the certified id.
#[derive(Debug, Clone)]
pub struct FetchedBlock {
    /// The block that was asked for.
    pub block: BlockRef,
    /// Its parent link, held to its id.
    pub link: ParentLink,
    /// Its data shreds, in order, 1,203 bytes each.
    pub shreds: Vec<Vec<u8>>,
    /// What it cost.
    pub stats: FetchStats,
}

/// What a peer's answer to a question asked around was worth.
enum Answer<T> {
    /// The peer holds what was asked about.
    Good(T),
    /// The answer failed a check.
    Bad,
    /// A true answer that does not help.
    Useless,
}

/// The socket, the peers and the rules for asking them.
pub struct Fetcher {
    net: Net,
    peers: PeerBook,
    config: FetchConfig,
    /// Who held each block last time, so that a second fetch starts there.
    holders: HashMap<Hash, Vec<usize>>,
    paused_until: Option<Instant>,
}

impl Fetcher {
    /// A fetcher that asks `peers` over `net`.
    pub fn new(net: Net, peers: PeerBook, config: FetchConfig) -> Self {
        Self {
            net,
            peers,
            config,
            holders: HashMap::new(),
            paused_until: None,
        }
    }

    /// The peers and what is known of each.
    pub fn peers(&self) -> &PeerBook {
        &self.peers
    }

    /// Replaces the peers with a newer list. What was learned about the old
    /// ones is dropped with them.
    pub fn set_peers(&mut self, peers: PeerBook) {
        self.peers = peers;
        self.holders.clear();
    }

    /// The socket's counters.
    pub fn net_stats(&self) -> NetStats {
        self.net.stats()
    }

    /// Whether the fetcher is staying quiet because peers stopped answering.
    pub fn is_paused(&self) -> bool {
        self.paused_until
            .is_some_and(|until| Instant::now() < until)
    }

    /// Refuses while peers are not answering, so that a client nobody
    /// serves does not keep asking.
    fn may_ask(&mut self) -> Result<(), Refusal> {
        if self.peers.is_empty() {
            return Err(Refusal::NoPeers);
        }
        let unanswered = self.net.unanswered_run();
        if let Some(until) = self.paused_until {
            if Instant::now() < until {
                return Err(Refusal::PeersSilent { unanswered });
            }
            self.paused_until = None;
            self.net.forgive();
        } else if unanswered >= self.config.silence_limit {
            self.paused_until = Some(Instant::now() + self.config.cooldown);
            return Err(Refusal::PeersSilent { unanswered });
        }
        Ok(())
    }

    /// Asks `request` of a few peers, `first` among them, and returns the
    /// ones whose answer `judge` takes.
    ///
    /// A peer that has never seen this client answers its first request
    /// with a ping, so each peer is asked a second time if it pinged or has
    /// yet to answer anything. More peers are tried only while fewer than
    /// `want` gave a good answer, up to `max_asked`.
    fn ask_around<T>(
        &mut self,
        request: &Request,
        first: &[usize],
        want: usize,
        max_asked: usize,
        mut judge: impl FnMut(&Reply) -> Answer<T>,
    ) -> (Vec<(usize, T)>, usize) {
        let mut good: Vec<(usize, T)> = Vec::new();
        // Per peer: times asked, and its ping count when last asked.
        let mut asked: BTreeMap<usize, (u32, u64)> = BTreeMap::new();
        let mut done: Vec<usize> = Vec::new();
        // Each new batch of peers takes two rounds: a ping, then an answer.
        let rounds = 2 * max_asked.div_ceil(want.max(1)).clamp(1, 4);
        for round in 0..rounds {
            let mut targets: Vec<usize> = asked
                .iter()
                .filter(|(who, (times, pings))| {
                    let peer = self.peers.get(**who);
                    !done.contains(who) && *times < 2 && (peer.pings > *pings || peer.answered == 0)
                })
                .map(|(who, _)| *who)
                .collect();
            if round == 0 {
                targets.extend(first.iter().filter(|who| **who < self.peers.len()));
            }
            let in_hand = good.len() + targets.len();
            if in_hand < want && asked.len() + targets.len() < max_asked {
                let not: Vec<usize> = asked.keys().chain(&targets).copied().collect();
                let more = (want - in_hand).min(max_asked - not.len());
                targets.extend(self.peers.pick(more, &not));
            }
            // Scouts: asked along with the rest and not waited for. One
            // that is there answers with a ping and is known from then on.
            if round == 0 && self.peers.known() < self.config.pool {
                targets.extend(self.peers.pick_new(SCOUTS, &targets));
            }
            if targets.is_empty() {
                break;
            }
            let mut waiting: HashMap<u32, usize> = HashMap::new();
            for who in targets {
                let pings = self.peers.get(who).pings;
                let nonce = self.net.request(&mut self.peers, who, request);
                waiting.insert(nonce, who);
                let entry = asked.entry(who).or_insert((0, pings));
                *entry = (entry.0 + 1, pings);
            }
            let deadline = Instant::now() + self.config.round_wait;
            while !waiting.is_empty() && good.len() < want {
                let Some((who, reply)) = self.net.next_reply(&mut self.peers, deadline) else {
                    break;
                };
                if waiting.remove(&nonce_of(&reply)) != Some(who) {
                    continue;
                }
                done.push(who);
                match judge(&reply) {
                    Answer::Good(value) => good.push((who, value)),
                    Answer::Bad => self.peers.get_mut(who).rejected += 1,
                    Answer::Useless => {}
                }
            }
            if good.len() >= want || (!good.is_empty() && round % 2 == 1) {
                break;
            }
        }
        (good, asked.len())
    }

    /// The parent of `block` and how many FEC sets it has, from any peer
    /// that holds it, checked against the block's id.
    pub fn parent(&mut self, block: &BlockRef) -> Result<ParentLink, Refusal> {
        self.locate(block).map(|(link, _, _)| link)
    }

    /// Finds peers that hold `block`: the ones that send its parent link.
    fn locate(&mut self, block: &BlockRef) -> Result<(ParentLink, Vec<usize>, u64), Refusal> {
        self.may_ask()?;
        let known = self.holders.get(&block.id).cloned().unwrap_or_default();
        let mut rejected = 0;
        let (good, asked) = self.ask_around(
            &Request::ParentAndFecSetCount { block: *block },
            &known,
            self.config.holders,
            self.config.max_asked,
            |reply| match reply {
                Reply::ParentFecSetCount { link, .. } if link.verify(block).is_ok() => {
                    Answer::Good(link.clone())
                }
                _ => {
                    rejected += 1;
                    Answer::Bad
                }
            },
        );
        let Some((_, link)) = good.first() else {
            return Err(Refusal::NoHolder {
                block: *block,
                asked,
            });
        };
        let link = link.clone();
        let holders: Vec<usize> = good.iter().map(|(who, _)| *who).collect();
        if self.holders.len() >= HOLDERS_REMEMBERED {
            self.holders.clear();
        }
        self.holders.insert(block.id, holders.clone());
        Ok((link, holders, rejected))
    }

    /// Fetches every data shred of `block`, each held to the block's id.
    ///
    /// `block` must come from a verified finality certificate or from a
    /// parent link held to one. The answer is that block's shreds, whole,
    /// or a refusal.
    pub fn block(&mut self, block: &BlockRef) -> Result<FetchedBlock, Refusal> {
        let started = Instant::now();
        let before = self.net.stats();
        let (link, mut holders, mut rejected) = self.locate(block)?;
        let found = holders.len();
        let sets = link.fec_set_count;
        let mut retries = 0;

        let roots: Vec<Node> = self.collect(
            block,
            "FEC set roots",
            &mut holders,
            sets,
            (&mut rejected, &mut retries),
            |set| Request::FecSetRoot {
                block: *block,
                fec_set_index: set * PER_SET,
            },
            |set, reply| match reply {
                Reply::FecSetRoot { root, path, .. }
                    if wire::fec_set_root_is_in(block, sets, set, root, path) =>
                {
                    Some(*root)
                }
                _ => None,
            },
        )?;

        let shreds: Vec<Vec<u8>> = self.collect(
            block,
            "shreds",
            &mut holders,
            sets * PER_SET,
            (&mut rejected, &mut retries),
            |index| Request::WindowIndexForBlockId {
                block: *block,
                index,
            },
            |index, reply| {
                let Reply::Shred { payload, .. } = reply else {
                    return None;
                };
                // The shred's own path must lead to the root already held
                // to the block id for its set.
                let shred = RawDataShred::parse_layout(payload).ok()?;
                let root = shred.fec_set_root().ok()?;
                (shred.slot == block.slot
                    && shred.index == index
                    && shred.fec_set_index == index - index % PER_SET
                    && root[..20] == roots[(index / PER_SET) as usize])
                    .then(|| payload.clone())
            },
        )?;

        let after = self.net.stats();
        Ok(FetchedBlock {
            block: *block,
            link,
            shreds,
            stats: FetchStats {
                requests: after.requests - before.requests,
                bytes_sent: after.bytes_sent - before.bytes_sent,
                bytes_received: after.bytes_received - before.bytes_received,
                holders: found,
                rejected,
                duplicates: after.duplicates - before.duplicates,
                retries,
                elapsed: started.elapsed(),
            },
        })
    }

    /// Collects pieces `0..total` of `block` from its holders, spread over
    /// them in turn, keeping only answers `check` accepts and asking again,
    /// elsewhere, for what is missing.
    #[allow(clippy::too_many_arguments)]
    fn collect<T>(
        &mut self,
        block: &BlockRef,
        what: &'static str,
        holders: &mut Vec<usize>,
        total: u32,
        (rejected, retries): (&mut u64, &mut u64),
        ask: impl Fn(u32) -> Request,
        check: impl Fn(u32, &Reply) -> Option<T>,
    ) -> Result<Vec<T>, Refusal> {
        let mut have: BTreeMap<u32, T> = BTreeMap::new();
        let mut waiting: HashMap<u32, u32> = HashMap::new();
        // Per holder: asked, answered well, answered badly.
        let mut served: HashMap<usize, (u32, u32, u32)> = HashMap::new();
        let mut turn = 0usize;
        let mut take = |fetcher: &mut Self,
                        have: &mut BTreeMap<u32, T>,
                        waiting: &mut HashMap<u32, u32>,
                        served: &mut HashMap<usize, (u32, u32, u32)>,
                        until: Instant| {
            while (have.len() as u32) < total {
                let Some((who, reply)) = fetcher.net.next_reply(&mut fetcher.peers, until) else {
                    return;
                };
                let Some(piece) = waiting.remove(&nonce_of(&reply)) else {
                    continue;
                };
                let tally = served.entry(who).or_default();
                match check(piece, &reply) {
                    Some(value) => {
                        tally.1 += 1;
                        have.entry(piece).or_insert(value);
                    }
                    None => {
                        tally.2 += 1;
                        *rejected += 1;
                        fetcher.peers.get_mut(who).rejected += 1;
                    }
                }
            }
        };
        for round in 0..self.config.max_rounds {
            let missing: Vec<u32> = (0..total).filter(|i| !have.contains_key(i)).collect();
            if missing.is_empty() || holders.is_empty() {
                break;
            }
            self.may_ask()?;
            if round > 0 {
                *retries += missing.len() as u64;
            }
            // Start each round one holder along, so that a piece one peer
            // would not send is asked of another.
            turn += round as usize;
            for piece in missing {
                // A holder caught lying is not asked for the rest.
                holders.retain(|who| served.get(who).is_none_or(|tally| tally.2 < HOLDER_LIES));
                if holders.is_empty() {
                    break;
                }
                let who = holders[turn % holders.len()];
                turn += 1;
                let nonce = self.net.request(&mut self.peers, who, &ask(piece));
                waiting.insert(nonce, piece);
                served.entry(who).or_default().0 += 1;
                take(self, &mut have, &mut waiting, &mut served, Instant::now());
            }
            let deadline = Instant::now() + self.config.round_wait;
            take(self, &mut have, &mut waiting, &mut served, deadline);
            holders.retain(|who| {
                let (asked, good, bad) = served.get(who).copied().unwrap_or_default();
                !(good == 0 && asked >= HOLDER_PATIENCE) && bad < HOLDER_LIES
            });
        }
        if (have.len() as u32) < total {
            return Err(Refusal::Incomplete {
                block: *block,
                what,
                have: have.len(),
                total: total as usize,
                rejected: *rejected,
            });
        }
        Ok(have.into_values().collect())
    }

    /// The footer of whatever block a peer holds for `slot`, read from the
    /// slot's last FEC sets. `None` if no peer shows a complete slot, or
    /// the tail holds no footer.
    ///
    /// **Unverified.** The slot is named, not the block, so a peer may
    /// answer from a block the cluster abandoned, or make one up. The only
    /// safe use of the result is to take a finality certificate out of it
    /// and verify that.
    pub fn footer(&mut self, slot: u64) -> Result<Option<Footer>, Refusal> {
        self.may_ask()?;
        let (complete, _) = self.ask_around(
            &Request::HighestWindowIndex { slot, index: 0 },
            &[],
            self.config.footer_peers,
            2 * self.config.footer_peers,
            |reply| match reply {
                Reply::Shred { payload, .. } => match wire::shred_header(payload) {
                    Some((s, index, flags))
                        if s == slot && flags & LAST_IN_SLOT == LAST_IN_SLOT =>
                    {
                        Answer::Good(index)
                    }
                    Some((s, ..)) if s == slot => Answer::Useless,
                    _ => Answer::Bad,
                },
                _ => Answer::Bad,
            },
        );
        // One peer's view at a time: two peers may hold different blocks
        // for the slot, and a tail mixed from both parses as neither.
        for (who, last) in complete.into_iter().take(2) {
            if let Some(footer) = self.footer_from(who, slot, last) {
                return Ok(Some(footer));
            }
        }
        Ok(None)
    }

    /// Reads back from the last shred of `slot`, one FEC set at a time,
    /// until a footer shows.
    fn footer_from(&mut self, who: usize, slot: u64, last: u32) -> Option<Footer> {
        let total = last.checked_add(1)?;
        if total % PER_SET != 0 || total / PER_SET > solana_thin::MAX_FEC_SETS_PER_SLOT {
            return None;
        }
        let mut have: BTreeMap<u32, RawDataShred> = BTreeMap::new();
        for depth in 1..=self.config.tail_sets.min(total / PER_SET) {
            let start = total - depth * PER_SET;
            // The shred before the set says whether a component starts here.
            let wanted: Vec<u32> = (start.saturating_sub(1)..start + PER_SET).collect();
            for _ in 0..3 {
                let missing: Vec<u32> = wanted
                    .iter()
                    .copied()
                    .filter(|i| !have.contains_key(i))
                    .collect();
                if missing.is_empty() {
                    break;
                }
                let mut waiting: HashMap<u32, u32> = HashMap::new();
                for index in missing {
                    let request = Request::WindowIndex {
                        slot,
                        index: u64::from(index),
                    };
                    waiting.insert(self.net.request(&mut self.peers, who, &request), index);
                }
                let deadline = Instant::now() + self.config.round_wait;
                while !waiting.is_empty() {
                    let Some((_, reply)) = self.net.next_reply(&mut self.peers, deadline) else {
                        break;
                    };
                    let Some(index) = waiting.remove(&nonce_of(&reply)) else {
                        continue;
                    };
                    let Reply::Shred { payload, .. } = reply else {
                        continue;
                    };
                    match RawDataShred::parse_layout(&payload) {
                        Ok(shred) if shred.slot == slot && shred.index == index => {
                            have.insert(index, shred);
                        }
                        _ => return None,
                    }
                }
            }
            if wanted.iter().any(|i| !have.contains_key(i)) {
                return None;
            }
            if start > 0 && !have[&(start - 1)].shred.data_complete() {
                // The set continues a component that began earlier.
                continue;
            }
            let mut component = Vec::new();
            for index in start..total {
                let shred = &have[&index].shred;
                shred.append_data(&mut component).ok()?;
                if shred.data_complete() {
                    if !block::is_entry_batch(&component) {
                        if let Ok(Marker::Footer(footer)) = block::parse_marker(&component) {
                            return Some(*footer);
                        }
                    }
                    component.clear();
                }
            }
        }
        None
    }
}

fn nonce_of(reply: &Reply) -> u32 {
    match reply {
        Reply::Shred { nonce, .. }
        | Reply::ParentFecSetCount { nonce, .. }
        | Reply::FecSetRoot { nonce, .. } => *nonce,
        // The socket answers pings itself and never hands one up.
        Reply::Ping { .. } => u32::MAX,
    }
}
