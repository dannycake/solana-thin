//! A prover that runs: it fetches finalized blocks from validators and
//! serves proofs that a transaction is in one.
//!
//! `solana-thin` verifies such a proof and builds one from a block's data
//! shreds and a finality certificate. Public RPC serves neither. Validators
//! do serve shreds, to each other and to anyone who asks, over the repair
//! protocol. This crate asks.
//!
//! * [`peers`]: whom to ask, from an RPC node's `getClusterNodes`.
//! * [`wire`], [`net`]: the repair protocol, a paced socket, and a key made
//!   at start.
//! * [`fetch`]: a block by its certified id, every answer checked against
//!   that id as it arrives; and footers by slot, to find certificates in.
//! * [`prove`]: from a signature and a slot hint to a proof the verifier
//!   accepts.
//! * [`store`]: a bounded directory of blocks, proofs and certificates.
//! * [`trust`]: the verifier and the pinned sets it checks everything with.
//! * [`serve`]: `GET /proof/<signature>` and friends.
//!
//! # What is trusted
//!
//! The pinned validator sets, and nothing else. Not the RPC node: its node
//! list decides whom to ask and its slot hints where to look, and a wrong
//! answer to either costs time. Not the validators asked: a block is known
//! by an id a verified certificate names, and a shred that does not hash up
//! to it is dropped. Not the store directory: what is read back is checked
//! like anything else. And a client trusts none of this: it verifies the
//! proof itself. See `docs/PROVER.md`.

pub mod anchor;
pub mod fetch;
pub mod net;
pub mod peers;
pub mod prove;
pub mod refusal;
pub mod rpc;
pub mod serve;
pub mod store;
pub mod trust;
pub mod wire;

pub use anchor::Anchor;
pub use fetch::{FetchConfig, FetchStats, Fetcher};
pub use net::Net;
pub use peers::PeerBook;
pub use prove::{Prover, ProverConfig};
pub use refusal::Refusal;
pub use store::Store;
pub use trust::{Schedule, Trust};
