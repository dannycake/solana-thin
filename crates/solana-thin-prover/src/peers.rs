//! The validators to ask, and what is known about each.
//!
//! Peers come from an RPC node's `getClusterNodes`: every node the cluster
//! gossips about, with the address it serves repair on, its release and its
//! shred version. That list is untrusted. A wrong one costs time, because
//! everything a peer sends is checked against a certified block id; it
//! cannot make the prover keep a block nobody voted for.

use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Requests a peer may leave unanswered, having never answered one, before
/// it is no longer asked.
const SILENT_AFTER: u64 = 8;

/// One validator.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Its identity key, which every request to it names.
    pub id: [u8; 32],
    /// Where it serves repair.
    pub addr: SocketAddr,
    /// Its client and release, as gossiped: `Agave/4.4.1`.
    pub label: String,
    /// Requests sent to it.
    pub asked: u64,
    /// Answers from it that matched a request.
    pub answered: u64,
    /// Answers from it that failed a check against a block id.
    pub rejected: u64,
    /// Pings it sent.
    pub pings: u64,
}

impl Peer {
    /// Whether it has been asked plenty and has never answered.
    pub fn is_silent(&self) -> bool {
        self.answered == 0 && self.asked >= SILENT_AFTER
    }

    /// Whether it has ever sent an answer or a ping: it is there, and it
    /// talks to this client.
    pub fn is_known(&self) -> bool {
        (self.answered > 0 || self.pings > 0) && !self.is_silent()
    }
}

/// What a `getClusterNodes` answer held.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Census {
    /// Nodes listed.
    pub listed: usize,
    /// Nodes on another shred version: another cluster, or the same one
    /// before a restart.
    pub other_shred_version: usize,
    /// Nodes with no repair address.
    pub no_repair_address: usize,
    /// Nodes on a release that does not answer the block-id requests.
    pub old_release: usize,
    /// Nodes whose entry could not be read, or that repeat an address.
    pub unusable: usize,
    /// Nodes kept.
    pub kept: usize,
}

/// Whether a node on `version` answers repair requests by block id.
///
/// Agave learned them in 4.3; nodes on 4.1 and 4.2 never answered one.
/// Other clients number their releases differently (Firedancer by date) and
/// are given the benefit of the doubt: a peer that stays silent is dropped
/// soon enough.
pub fn can_answer(version: &str) -> bool {
    let mut parts = version.split('.').map(|part| part.parse::<u32>().ok());
    match (parts.next().flatten(), parts.next().flatten()) {
        (Some(1..=3), _) => false,
        (Some(4), Some(minor)) => minor >= 3,
        _ => true,
    }
}

/// The shred version most of the listed nodes are on.
pub fn common_shred_version(nodes: &Value) -> Option<u16> {
    let mut counts: HashMap<u16, usize> = HashMap::new();
    for node in nodes.as_array()? {
        if let Some(version) = node["shredVersion"]
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
        {
            *counts.entry(version).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(version, count)| (*count, *version))
        .map(|(version, _)| version)
}

/// The peers, and a cursor for handing them out in turn.
#[derive(Debug)]
pub struct PeerBook {
    peers: Vec<Peer>,
    by_addr: HashMap<SocketAddr, usize>,
    /// Peers in the order they are tried, shuffled once.
    order: Vec<usize>,
    /// Where in that order the next untried peer is looked for.
    cursor: usize,
    /// Whose turn it is among the peers already heard from.
    known_turn: usize,
}

impl PeerBook {
    /// Reads a `getClusterNodes` result, keeping the nodes on
    /// `shred_version` that serve repair on a release that can answer.
    /// `seed` shuffles the order they are tried in.
    pub fn from_cluster_nodes(nodes: &Value, shred_version: u16, seed: u64) -> (Self, Census) {
        let mut census = Census::default();
        let mut peers = Vec::new();
        let mut by_addr = HashMap::new();
        for node in nodes.as_array().map(Vec::as_slice).unwrap_or_default() {
            census.listed += 1;
            if node["shredVersion"].as_u64() != Some(u64::from(shred_version)) {
                census.other_shred_version += 1;
                continue;
            }
            let Some(addr) = node["serveRepair"].as_str() else {
                census.no_repair_address += 1;
                continue;
            };
            let version = node["version"].as_str().unwrap_or("?");
            if !can_answer(version) {
                census.old_release += 1;
                continue;
            }
            let id = node["pubkey"]
                .as_str()
                .and_then(|key| bs58::decode(key).into_vec().ok())
                .and_then(|key| <[u8; 32]>::try_from(key).ok());
            let (Some(id), Ok(addr)) = (id, addr.parse::<SocketAddr>()) else {
                census.unusable += 1;
                continue;
            };
            // Answers are matched to a peer by where they come from.
            if by_addr.contains_key(&addr) {
                census.unusable += 1;
                continue;
            }
            let client = node["clientId"].as_str().unwrap_or("?");
            by_addr.insert(addr, peers.len());
            peers.push(Peer {
                id,
                addr,
                label: format!("{client}/{version}"),
                asked: 0,
                answered: 0,
                rejected: 0,
                pings: 0,
            });
        }
        census.kept = peers.len();
        let mut order: Vec<usize> = (0..peers.len()).collect();
        // Fisher-Yates on a small generator: which validators get asked
        // should not depend on the order an RPC node lists them in.
        let mut state = seed | 1;
        for i in (1..order.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            order.swap(i, (state % (i as u64 + 1)) as usize);
        }
        let book = Self {
            peers,
            by_addr,
            order,
            cursor: 0,
            known_turn: 0,
        };
        (book, census)
    }

    /// Number of peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether there are no peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// The peer numbered `who`.
    pub fn get(&self, who: usize) -> &Peer {
        &self.peers[who]
    }

    pub(crate) fn get_mut(&mut self, who: usize) -> &mut Peer {
        &mut self.peers[who]
    }

    /// The peer that serves repair on `addr`.
    pub fn at(&self, addr: &SocketAddr) -> Option<usize> {
        self.by_addr.get(addr).copied()
    }

    /// Every peer.
    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter()
    }

    /// Peers that have answered at least once.
    pub fn answering(&self) -> usize {
        self.peers.iter().filter(|p| p.answered > 0).count()
    }

    /// Peers that have sent anything at all, an answer or a ping.
    pub fn known(&self) -> usize {
        self.peers.iter().filter(|p| p.is_known()).count()
    }

    /// Up to `count` peers to ask next, none of them in `not`.
    ///
    /// Peers already heard from come first, in turn, so that the load
    /// spreads over all of them; then peers not yet tried. Peers that
    /// stayed silent are left out.
    pub fn pick(&mut self, count: usize, not: &[usize]) -> Vec<usize> {
        let known: Vec<usize> = self
            .order
            .iter()
            .copied()
            .filter(|who| self.peers[*who].is_known() && !not.contains(who))
            .collect();
        let mut picked: Vec<usize> = (0..known.len().min(count))
            .map(|step| known[(self.known_turn + step) % known.len()])
            .collect();
        self.known_turn = self.known_turn.wrapping_add(picked.len());
        let more = self.pick_new(count - picked.len(), not);
        picked.extend(more);
        picked
    }

    /// Up to `count` peers that have never been heard from, none of them in
    /// `not`, taken in turn.
    pub fn pick_new(&mut self, count: usize, not: &[usize]) -> Vec<usize> {
        let total = self.order.len();
        let mut picked = Vec::new();
        let mut steps = 0;
        while picked.len() < count && steps < total {
            let who = self.order[(self.cursor + steps) % total];
            steps += 1;
            let peer = &self.peers[who];
            if !peer.is_known() && !peer.is_silent() && !not.contains(&who) {
                picked.push(who);
            }
        }
        if total > 0 {
            self.cursor = (self.cursor + steps) % total;
        }
        picked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(n: u8) -> String {
        bs58::encode([n; 32]).into_string()
    }

    fn node(n: u8, version: &str, shred_version: u16, repair: Option<&str>) -> Value {
        json!({"pubkey": key(n), "version": version, "shredVersion": shred_version,
               "serveRepair": repair, "clientId": "Agave", "gossip": "192.0.2.1:8001"})
    }

    #[test]
    fn releases_that_never_answer_are_told_apart() {
        for old in ["4.1.2", "4.2.0", "4.2.1", "3.0.14", "2.3.8", "1.18.26"] {
            assert!(!can_answer(old), "{old}");
        }
        for new in [
            "4.3.0",
            "4.3.0-rc.1",
            "4.4.1",
            "4.5.0-beta.0",
            "5.0.0-alpha.1",
            "26.10.8",
            "0.1.1",
            "0.0.0",
            "?",
            "",
        ] {
            assert!(can_answer(new), "{new}");
        }
    }

    #[test]
    fn only_nodes_that_can_answer_are_kept() {
        let nodes = json!([
            node(1, "4.4.1", 50093, Some("192.0.2.1:8009")),
            node(2, "4.4.1", 50093, None),
            node(3, "4.1.2", 50093, Some("192.0.2.3:8009")),
            node(4, "4.4.1", 4711, Some("192.0.2.4:8009")),
            node(5, "26.10.8", 50093, Some("192.0.2.5:8009")),
            // The same address again, an address that is not one, a bad key.
            node(6, "4.4.1", 50093, Some("192.0.2.1:8009")),
            node(7, "4.4.1", 50093, Some("validator.example:8009")),
            json!({"pubkey": "not base58!", "version": "4.4.1", "shredVersion": 50093,
                   "serveRepair": "192.0.2.8:8009"}),
        ]);
        let (book, census) = PeerBook::from_cluster_nodes(&nodes, 50093, 7);
        assert_eq!(
            census,
            Census {
                listed: 8,
                other_shred_version: 1,
                no_repair_address: 1,
                old_release: 1,
                unusable: 3,
                kept: 2,
            }
        );
        let mut labels: Vec<&str> = book.iter().map(|p| p.label.as_str()).collect();
        labels.sort();
        assert_eq!(labels, ["Agave/26.10.8", "Agave/4.4.1"]);
        let first = book.at(&"192.0.2.1:8009".parse().unwrap()).unwrap();
        assert_eq!(book.get(first).id, [1; 32]);
        assert_eq!(book.at(&"192.0.2.3:8009".parse().unwrap()), None);
        assert_eq!(common_shred_version(&nodes), Some(50093));
        assert_eq!(common_shred_version(&json!([])), None);
        assert_eq!(common_shred_version(&json!({"error": 1})), None);
    }

    #[test]
    fn something_that_is_not_a_node_list_gives_no_peers() {
        let (book, census) = PeerBook::from_cluster_nodes(&json!({"oops": true}), 1, 1);
        assert!(book.is_empty());
        assert_eq!(census, Census::default());
    }

    fn book(count: u8) -> PeerBook {
        let nodes: Vec<Value> = (1..=count)
            .map(|n| node(n, "4.4.1", 9, Some(&format!("192.0.2.{n}:8009"))))
            .collect();
        PeerBook::from_cluster_nodes(&json!(nodes), 9, 99).0
    }

    #[test]
    fn peers_are_handed_out_in_turn() {
        let mut book = book(10);
        let first = book.pick(4, &[]);
        let second = book.pick(4, &[]);
        let third = book.pick(4, &[]);
        assert_eq!(first.len(), 4);
        assert!(second.iter().all(|who| !first.contains(who)));
        let mut seen = [first, second, third].concat();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 10);
        // More than there are, less what is excluded.
        let all = book.pick(50, &[0, 1]);
        assert_eq!(all.len(), 8);
        assert!(!all.contains(&0) && !all.contains(&1));
    }

    #[test]
    fn peers_that_answered_come_first_and_silent_ones_are_dropped() {
        let mut book = book(10);
        book.get_mut(6).answered = 3;
        book.get_mut(2).asked = SILENT_AFTER;
        assert!(book.get(2).is_silent());
        assert_eq!(book.answering(), 1);
        for _ in 0..5 {
            let picked = book.pick(3, &[]);
            assert_eq!(picked[0], 6);
            assert!(!picked.contains(&2));
        }
        // One answer, however late, makes a peer worth asking again.
        book.get_mut(2).answered = 1;
        assert!(book.pick(10, &[]).contains(&2));
        assert_eq!(book.known(), 2);
    }

    #[test]
    fn peers_heard_from_take_turns() {
        let mut book = book(12);
        // Six have answered or pinged; the load goes round all of them.
        for who in [0, 2, 4, 6] {
            book.get_mut(who).answered = 1;
        }
        book.get_mut(8).pings = 1;
        book.get_mut(10).pings = 1;
        assert_eq!(book.known(), 6);
        let mut times = [0; 12];
        for _ in 0..6 {
            let picked = book.pick(2, &[]);
            assert_eq!(picked.len(), 2);
            for who in picked {
                times[who] += 1;
            }
        }
        assert_eq!(times, [2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0]);
        // Scouts are only ever peers not heard from yet.
        let scouts = book.pick_new(4, &[1]);
        assert_eq!(scouts.len(), 4);
        assert!(scouts.iter().all(|who| who % 2 == 1 && *who != 1));
    }

    #[test]
    fn the_order_depends_on_the_seed_and_not_on_the_listing() {
        let nodes: Vec<Value> = (1..=30)
            .map(|n| node(n, "4.4.1", 9, Some(&format!("192.0.2.{n}:8009"))))
            .collect();
        let pick = |seed| {
            PeerBook::from_cluster_nodes(&json!(nodes), 9, seed)
                .0
                .pick(30, &[])
        };
        assert_eq!(pick(1), pick(1));
        assert_ne!(pick(1), pick(2));
        assert_ne!(pick(1), (0..30).collect::<Vec<_>>());
    }
}
