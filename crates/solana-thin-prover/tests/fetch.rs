//! Fetching a block by its certified id from validators on loopback, honest
//! and not. What comes back is that block, whole, or a refusal that says
//! why; never anything else.

mod common;

use common::*;
use solana_thin::prover::BlockData;
use solana_thin_prover::fetch::{FetchConfig, Fetcher};
use solana_thin_prover::wire::Request;
use solana_thin_prover::Refusal;
use std::time::{Duration, Instant};

fn chain() -> Chain {
    Chain::linear(100..104)
}

/// Fetches the block of slot 101 and holds the result to the chain.
fn fetch_101(chain: &Chain, fetcher: &mut Fetcher) -> solana_thin_prover::fetch::FetchedBlock {
    let block = chain.block(101);
    let fetched = fetcher.block(&block).unwrap();
    assert_eq!(fetched.block, block);
    assert_eq!(fetched.link.parent, chain.block(100));
    assert_eq!(fetched.shreds, chain.blocks[&101].payloads);
    let data = BlockData::from_shreds(&fetched.shreds).unwrap();
    assert_eq!(data.block(), block);
    fetched
}

#[test]
fn honest_peers_serve_a_block_by_its_id_and_share_the_work() {
    let chain = chain();
    let peers: Vec<FakePeer> = (1..=3)
        .map(|n| FakePeer::start(n, &chain, Behavior::Honest))
        .collect();
    let mut fetcher = fetcher(&peers.iter().collect::<Vec<_>>(), quick());
    let fetched = fetch_101(&chain, &mut fetcher);

    // Four FEC sets: a header, a batch, a footer, a tick.
    assert_eq!(fetched.shreds.len(), 128);
    assert_eq!(fetched.stats.holders, 3);
    assert_eq!(fetched.stats.rejected, 0);
    assert_eq!(fetched.stats.retries, 0);
    // Three pings, three parent links, four roots, 128 shreds.
    assert_eq!(fetched.stats.requests, 3 + 3 + 4 + 128);
    for peer in &peers {
        let seen = peer.seen();
        // Nothing is ever asked by slot, and nobody carries the block alone.
        assert!(seen.iter().all(|request| !matches!(
            request,
            Request::WindowIndex { .. } | Request::HighestWindowIndex { .. }
        )));
        let shreds = seen
            .iter()
            .filter(|r| matches!(r, Request::WindowIndexForBlockId { .. }))
            .count();
        assert!((40..=46).contains(&shreds), "{shreds}");
    }
    assert_eq!(fetcher.peers().answering(), 3);
}

#[test]
fn a_block_nobody_voted_for_cannot_be_fetched_by_its_id() {
    let chain = chain();
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut fetcher = fetcher(&[&peer], quick());
    let mut unknown = chain.block(101);
    unknown.id[5] ^= 1;
    assert_eq!(
        fetcher.block(&unknown).unwrap_err(),
        Refusal::NoHolder {
            block: unknown,
            asked: 1
        }
    );
    // The right id, the wrong slot: an id is not a block without its slot.
    let mut misplaced = chain.block(101);
    misplaced.slot = 102;
    assert!(matches!(
        fetcher.block(&misplaced),
        Err(Refusal::NoHolder { .. })
    ));
}

#[test]
fn duplicated_answers_are_counted_once() {
    let chain = chain();
    let peers = [
        FakePeer::start(1, &chain, Behavior::Duplicates),
        FakePeer::start(2, &chain, Behavior::Duplicates),
    ];
    let mut fetcher = fetcher(&[&peers[0], &peers[1]], quick());
    let fetched = fetch_101(&chain, &mut fetcher);
    assert_eq!(fetched.stats.rejected, 0);
    assert_eq!(fetched.stats.retries, 0);
    // The second copy of an answer is recognized and dropped. The last few
    // may still be on their way when the block is complete.
    assert!(fetched.stats.duplicates >= 100, "{:?}", fetched.stats);
    assert!(fetcher.net_stats().duplicates >= fetched.stats.duplicates);
}

#[test]
fn silent_peers_cost_time_and_nothing_else() {
    let chain = chain();
    let peers = [
        FakePeer::start(1, &chain, Behavior::Silent),
        FakePeer::start(2, &chain, Behavior::Honest),
        FakePeer::start(3, &chain, Behavior::Silent),
    ];
    let mut fetcher = fetcher(&[&peers[0], &peers[1], &peers[2]], quick());
    let fetched = fetch_101(&chain, &mut fetcher);
    assert_eq!(fetched.stats.holders, 1);
    assert_eq!(peers[0].seen().len() + peers[2].seen().len(), 0);
    assert_eq!(fetcher.peers().answering(), 1);
}

#[test]
fn when_every_peer_is_silent_the_block_has_no_holder() {
    let chain = chain();
    let peers = [
        FakePeer::start(1, &chain, Behavior::Silent),
        FakePeer::start(2, &chain, Behavior::Silent),
    ];
    let mut fetcher = fetcher(&[&peers[0], &peers[1]], quick());
    let block = chain.block(101);
    assert_eq!(
        fetcher.block(&block).unwrap_err(),
        Refusal::NoHolder { block, asked: 2 }
    );
}

#[test]
fn lost_answers_are_asked_for_again_elsewhere() {
    let chain = chain();
    let peers = [
        FakePeer::start(1, &chain, Behavior::Lossy),
        FakePeer::start(2, &chain, Behavior::Lossy),
    ];
    let mut fetcher = fetcher(&[&peers[0], &peers[1]], quick());
    let fetched = fetch_101(&chain, &mut fetcher);
    assert!(fetched.stats.retries > 20, "{:?}", fetched.stats);
    assert_eq!(fetched.stats.rejected, 0);
}

/// One liar beside one honest peer: the block arrives whole and nothing the
/// liar sent is in it.
fn fetched_despite(behavior: Behavior) -> (solana_thin_prover::fetch::FetchStats, u64) {
    let chain = chain();
    let liar = FakePeer::start(1, &chain, behavior);
    liar.set_decoy(&chain.blocks[&102]);
    let honest = FakePeer::start(2, &chain, Behavior::Honest);
    let mut fetcher = fetcher(&[&liar, &honest], quick());
    let fetched = fetch_101(&chain, &mut fetcher);
    let rejected = fetcher.peers().iter().map(|peer| peer.rejected).sum();
    (fetched.stats, rejected)
}

/// The same liar alone: nothing is returned.
fn refused_from(behavior: Behavior) -> Refusal {
    let chain = chain();
    let liar = FakePeer::start(1, &chain, behavior);
    liar.set_decoy(&chain.blocks[&102]);
    let mut fetcher = fetcher(&[&liar], quick());
    fetcher.block(&chain.block(101)).unwrap_err()
}

#[test]
fn shreds_that_do_not_hash_to_the_block_are_dropped() {
    let (stats, rejected) = fetched_despite(Behavior::CorruptShreds);
    assert!(stats.rejected >= 3, "{stats:?}");
    assert_eq!(stats.rejected, rejected);
    // Alone, the liar is dropped after a few shreds, not asked for them all.
    let Refusal::Incomplete {
        what: "shreds",
        have: 0,
        total: 128,
        rejected,
        ..
    } = refused_from(Behavior::CorruptShreds)
    else {
        panic!("a block of corrupt shreds is incomplete");
    };
    assert!((3..64).contains(&rejected), "{rejected}");
}

#[test]
fn a_real_shred_in_the_wrong_place_is_dropped() {
    let (stats, _) = fetched_despite(Behavior::WrongIndex);
    assert!(stats.rejected >= 3, "{stats:?}");
    assert!(matches!(
        refused_from(Behavior::WrongIndex),
        Refusal::Incomplete {
            what: "shreds",
            have: 0,
            ..
        }
    ));
}

#[test]
fn answers_about_another_block_are_dropped() {
    // The liar's parent link is a true one, for the block of slot 102.
    let (stats, rejected) = fetched_despite(Behavior::OtherBlock);
    assert_eq!(stats.holders, 1);
    assert!(rejected >= 1);
    assert!(matches!(
        refused_from(Behavior::OtherBlock),
        Refusal::NoHolder { asked: 1, .. }
    ));
}

#[test]
fn a_parent_the_block_does_not_commit_to_is_dropped() {
    let (stats, rejected) = fetched_despite(Behavior::WrongParent);
    assert_eq!(stats.holders, 1);
    assert!(rejected >= 1);
    assert!(matches!(
        refused_from(Behavior::WrongParent),
        Refusal::NoHolder { .. }
    ));
}

#[test]
fn fec_set_roots_that_are_not_the_blocks_are_dropped() {
    let (stats, _) = fetched_despite(Behavior::CorruptRoots);
    assert!(stats.rejected >= 2, "{stats:?}");
    assert!(matches!(
        refused_from(Behavior::CorruptRoots),
        Refusal::Incomplete {
            what: "FEC set roots",
            have: 0,
            total: 4,
            ..
        }
    ));
}

#[test]
fn a_holder_that_sends_no_shreds_is_given_up_on() {
    let chain = chain();
    let peer = FakePeer::start(1, &chain, Behavior::WithholdsShreds);
    let mut fetcher = fetcher(&[&peer], quick());
    let started = Instant::now();
    assert!(matches!(
        fetcher.block(&chain.block(101)),
        Err(Refusal::Incomplete {
            what: "shreds",
            have: 0,
            total: 128,
            rejected: 0,
            ..
        })
    ));
    // One round of asking, not all of them: it never answered once.
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        peer.seen()
            .iter()
            .filter(|r| matches!(r, Request::WindowIndexForBlockId { .. }))
            .count(),
        128
    );
}

#[test]
fn parent_links_lead_back_through_the_chain() {
    let chain = chain();
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut fetcher = fetcher(&[&peer], quick());
    let mut block = chain.block(103);
    for slot in [102, 101, 100] {
        let link = fetcher.parent(&block).unwrap();
        assert_eq!(link.parent, chain.block(slot));
        block = link.parent;
    }
    // One ping, then one request per block.
    assert_eq!(fetcher.net_stats().requests, 4);
}

#[test]
fn requests_are_paced() {
    let chain = chain();
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let (book, _) = solana_thin_prover::PeerBook::from_cluster_nodes(&nodes(&[&peer]), VERSION, 1);
    let net = solana_thin_prover::Net::open("127.0.0.1:0".parse().unwrap(), 400).unwrap();
    let mut fetcher = Fetcher::new(net, book, quick());
    let started = Instant::now();
    let fetched = fetcher.block(&chain.block(101)).unwrap();
    let floor = Duration::from_secs_f64((fetched.stats.requests - 2) as f64 / 400.0);
    assert!(started.elapsed() >= floor, "{:?}", started.elapsed());
}

#[test]
fn a_client_nobody_answers_stops_asking() {
    let chain = chain();
    let peers: Vec<FakePeer> = (1..=4)
        .map(|n| FakePeer::start(n, &chain, Behavior::Silent))
        .collect();
    let config = FetchConfig {
        silence_limit: 10,
        cooldown: Duration::from_millis(400),
        ..quick()
    };
    let mut fetcher = fetcher(&peers.iter().collect::<Vec<_>>(), config);
    let block = chain.block(101);
    let mut refusals = Vec::new();
    for _ in 0..4 {
        refusals.push(fetcher.block(&block).unwrap_err());
    }
    assert!(matches!(refusals[0], Refusal::NoHolder { .. }));
    assert!(matches!(refusals[3], Refusal::PeersSilent { unanswered } if unanswered >= 10));
    assert!(fetcher.is_paused());
    // While it is quiet it sends nothing at all.
    let sent = fetcher.net_stats().requests;
    assert!(matches!(
        fetcher.footer(102),
        Err(Refusal::PeersSilent { .. })
    ));
    assert_eq!(fetcher.net_stats().requests, sent);
    // And then it tries again.
    std::thread::sleep(Duration::from_millis(450));
    assert!(matches!(
        fetcher.block(&block),
        Err(Refusal::NoHolder { .. })
    ));
    assert!(fetcher.net_stats().requests > sent);
}

#[test]
fn a_footer_is_read_from_the_end_of_a_slot() {
    let chain = chain();
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut fetcher = fetcher(&[&peer], quick());
    let footer = fetcher.footer(102).unwrap().unwrap();
    assert_eq!(footer.finality, Some(chain.certificate(101)));
    assert_eq!(footer.user_agent, b"testkit");
    // The first block's footer carries no certificate, and a slot nobody
    // holds has no footer.
    assert_eq!(fetcher.footer(100).unwrap().unwrap().finality, None);
    assert_eq!(fetcher.footer(150).unwrap(), None);
    // Only the tail was asked for, by slot: the tick's set and the footer's.
    let (by_slot, by_id) = peer.seen_by_kind();
    assert_eq!(by_id, 0);
    assert!(by_slot < 3 * (2 + 66), "{by_slot}");
}
