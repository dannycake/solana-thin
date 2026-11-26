//! One UDP socket, one throwaway key, a pacer, and the matching of answers
//! to requests.
//!
//! Everything goes through [`Net::request`], which never sends faster than
//! the configured rate, and comes back through [`Net::next_reply`], which
//! hands over only packets that answer a request this socket sent, from the
//! address it was sent to, once. Pings are answered here and never seen
//! above.

use crate::peers::PeerBook;
use crate::wire::{self, Identity, Reply, Request};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long a request stays answerable. Later answers are dropped.
const ANSWER_WINDOW: Duration = Duration::from_secs(5);
/// A peer is sent at most one pong in this long, whatever it sends.
const PONG_INTERVAL: Duration = Duration::from_millis(200);

/// Counters since the socket was opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetStats {
    /// Requests sent.
    pub requests: u64,
    /// Bytes sent, pongs included.
    pub bytes_sent: u64,
    /// Packets received from anyone.
    pub packets: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Answers handed up.
    pub answers: u64,
    /// Second copies of an answer already handed up.
    pub duplicates: u64,
    /// Packets from an address that is not a peer's.
    pub strangers: u64,
    /// Packets from a peer that answer nothing asked of it in the last few
    /// seconds, or that are no answer at all.
    pub unsolicited: u64,
    /// Pings answered.
    pub pongs: u64,
}

struct Asked {
    who: usize,
    at: Instant,
    answered: bool,
}

/// The socket and what is outstanding on it.
pub struct Net {
    socket: UdpSocket,
    identity: Identity,
    nonce: u32,
    gap: Duration,
    next_send: Instant,
    asked: HashMap<u32, Asked>,
    last_pong: HashMap<usize, Instant>,
    inbox: VecDeque<(usize, Reply)>,
    stats: NetStats,
    /// Requests sent since a peer last sent anything at all.
    unanswered_run: u64,
}

impl Net {
    /// Opens a socket on `bind` that sends at most `per_second` requests a
    /// second, with a key made now.
    pub fn open(bind: SocketAddr, per_second: u32) -> io::Result<Self> {
        let identity = Identity::generate().map_err(io::Error::other)?;
        let socket = UdpSocket::bind(bind)?;
        // The nonce only has to be hard to guess for someone who cannot see
        // the traffic; the key's public half is as random as anything here.
        let key = identity.public_key();
        let nonce = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        Ok(Self {
            socket,
            identity,
            nonce,
            gap: Duration::from_secs(1) / per_second.max(1),
            next_send: Instant::now(),
            asked: HashMap::new(),
            last_pong: HashMap::new(),
            inbox: VecDeque::new(),
            stats: NetStats::default(),
            unanswered_run: 0,
        })
    }

    /// The counters.
    pub fn stats(&self) -> NetStats {
        self.stats
    }

    /// Requests sent since any peer last sent a packet. A long run means
    /// the peers have stopped serving this client, or the network is gone.
    pub fn unanswered_run(&self) -> u64 {
        self.unanswered_run
    }

    /// Starts the count of [`unanswered_run`](Self::unanswered_run) again.
    pub fn forgive(&mut self) {
        self.unanswered_run = 0;
    }

    /// Sends `request` to peer `who`, no sooner than the pacer allows, and
    /// returns the nonce its answer will carry. Packets that arrive while
    /// waiting are kept for [`next_reply`](Self::next_reply).
    pub fn request(&mut self, peers: &mut PeerBook, who: usize, request: &Request) -> u32 {
        // Whatever has arrived is taken off the socket before more is asked
        // for, so that answers never pile up behind a burst of requests.
        self.drain(peers);
        if self.next_send > Instant::now() {
            self.receive(peers, self.next_send);
        }
        self.next_send = self.next_send.max(Instant::now()) + self.gap;
        self.nonce = self.nonce.wrapping_add(1);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64);
        let peer = peers.get_mut(who);
        let packet = request.encode(&self.identity, &peer.id, now_ms, self.nonce);
        // A send that fails is a request that goes unanswered: the caller
        // already has to cope with those.
        let _ = self.socket.send_to(&packet, peer.addr);
        peer.asked += 1;
        self.stats.requests += 1;
        self.stats.bytes_sent += packet.len() as u64;
        self.unanswered_run += 1;
        if self.asked.len() >= 8192 {
            let now = Instant::now();
            self.asked
                .retain(|_, asked| now.duration_since(asked.at) < ANSWER_WINDOW);
        }
        self.asked.insert(
            self.nonce,
            Asked {
                who,
                at: Instant::now(),
                answered: false,
            },
        );
        self.nonce
    }

    /// The next answer to a request, with the peer it came from, or `None`
    /// once `until` has passed.
    pub fn next_reply(&mut self, peers: &mut PeerBook, until: Instant) -> Option<(usize, Reply)> {
        loop {
            if let Some(reply) = self.inbox.pop_front() {
                return Some(reply);
            }
            if Instant::now() >= until {
                self.drain(peers);
                return self.inbox.pop_front();
            }
            self.receive_one(peers, until);
        }
    }

    /// Reads packets into the inbox until `until`.
    fn receive(&mut self, peers: &mut PeerBook, until: Instant) {
        while Instant::now() < until {
            self.receive_one(peers, until);
        }
    }

    /// Takes every packet that has already arrived, without waiting.
    fn drain(&mut self, peers: &mut PeerBook) {
        if self.socket.set_nonblocking(true).is_err() {
            return;
        }
        let mut buffer = [0u8; 2048];
        while let Ok((len, from)) = self.socket.recv_from(&mut buffer) {
            self.sort(peers, &buffer[..len], from);
        }
        let _ = self.socket.set_nonblocking(false);
    }

    /// Waits for one packet, at most until `until`, and sorts it.
    fn receive_one(&mut self, peers: &mut PeerBook, until: Instant) {
        let wait = until
            .saturating_duration_since(Instant::now())
            .max(Duration::from_micros(100));
        if self.socket.set_read_timeout(Some(wait)).is_err() {
            return;
        }
        let mut buffer = [0u8; 2048];
        if let Ok((len, from)) = self.socket.recv_from(&mut buffer) {
            self.sort(peers, &buffer[..len], from);
        }
    }

    /// Files one packet: a ping is answered, an answer to something asked
    /// goes to the inbox, anything else is counted and dropped.
    fn sort(&mut self, peers: &mut PeerBook, packet: &[u8], from: SocketAddr) {
        let len = packet.len();
        self.stats.packets += 1;
        self.stats.bytes_received += len as u64;
        let Some(who) = peers.at(&from) else {
            self.stats.strangers += 1;
            return;
        };
        self.unanswered_run = 0;
        let (nonce, reply) = match Reply::decode(packet) {
            Some(Reply::Ping { from: key, token }) => {
                // Only a peer's own ping, and not a flood of them: a pong
                // goes to whatever address the ping claims to come from.
                let now = Instant::now();
                let recently = self
                    .last_pong
                    .get(&who)
                    .is_some_and(|at| now.duration_since(*at) < PONG_INTERVAL);
                if key == peers.get(who).id && !recently {
                    let pong = wire::pong(&self.identity, &token);
                    let _ = self.socket.send_to(&pong, from);
                    self.last_pong.insert(who, now);
                    self.stats.pongs += 1;
                    self.stats.bytes_sent += pong.len() as u64;
                    peers.get_mut(who).pings += 1;
                }
                return;
            }
            Some(Reply::Shred { payload, nonce }) => (nonce, Reply::Shred { payload, nonce }),
            Some(Reply::ParentFecSetCount { link, nonce }) => {
                (nonce, Reply::ParentFecSetCount { link, nonce })
            }
            Some(Reply::FecSetRoot { root, path, nonce }) => {
                (nonce, Reply::FecSetRoot { root, path, nonce })
            }
            None => {
                self.stats.unsolicited += 1;
                return;
            }
        };
        match self.asked.get_mut(&nonce) {
            Some(asked) if asked.who == who && asked.at.elapsed() < ANSWER_WINDOW => {
                if asked.answered {
                    self.stats.duplicates += 1;
                    return;
                }
                asked.answered = true;
                self.stats.answers += 1;
                peers.get_mut(who).answered += 1;
                self.inbox.push_back((who, reply));
            }
            _ => self.stats.unsolicited += 1,
        }
    }
}
