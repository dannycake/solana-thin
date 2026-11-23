//! A thin client for Solana after Alpenglow.
//!
//! Given a proof from any untrusted source, this crate tells you whether a
//! transaction is in a block that Solana's validators finalized. It does not
//! run a node, replay blocks, or trust the server it talks to.
//!
//! ```
//! # use solana_thin::testkit::*;
//! # use solana_thin::*;
//! # let world = demo_world();
//! # let (pinned_hash, validator_set, proof_bytes, my_signature) =
//! #     (world.set_hash, world.set, world.proof_bytes, world.signature);
//! // Trust: the cluster's shred version and the hash of this epoch's validators.
//! let mut client = ThinClient::new(ClusterParams::mainnet(50093));
//! client.trust_validator_set(0, validator_set, &pinned_hash)?;
//!
//! // Proof: bytes from anyone. A relay, a friend's phone, a public server.
//! let proof = TxProof::from_bytes(&proof_bytes, &Limits::default())?;
//! let verified = client.verify_signature(&proof, &my_signature)?;
//!
//! assert_eq!(verified.transaction.signature(), &my_signature);
//! println!("final in slot {}", verified.block.slot);
//! # Ok::<(), Error>(())
//! ```
//!
//! # What is proven
//!
//! A successful [`ThinClient::verify_transaction`] means all of this held:
//!
//! 1. Validators holding at least 80% of the pinned stake signed the block (or
//!    60% signed it and 60% signed to finalize its slot), on this cluster.
//! 2. The transaction's bytes hash up to that block's id, or to an ancestor's.
//! 3. Those bytes sit where a validator parses a transaction, found by walking
//!    the block's structure from a real boundary, in a part of the block that
//!    was executed.
//!
//! # What is not proven
//!
//! * **That the transaction succeeded.** Failed transactions are included too.
//!   Nothing in a block commits to execution results in a way a small proof
//!   can open. Build on inclusion (anchoring, ordering, timestamps) or on
//!   transactions that cannot fail once included.
//! * **Account state.** Solana commits to state with a hash that has no
//!   inclusion proofs.
//! * **That your validator set is the right one.** That is your trust root:
//!   see [`ThinClient::trust_validator_set`] and `docs/DESIGN.md`.
//!
//! # Layout
//!
//! * [`ThinClient`]: the verifier. Start here.
//! * [`prover`]: builds proofs from a block's data shreds. Runs on a node.
//! * [`certificate`], [`validator_set`], [`merkle`], [`shred`], [`block`],
//!   [`transaction`]: the layers, each usable on its own.
//! * `testkit` (feature `testkit`): deterministic blocks and validators for
//!   tests and examples.

pub mod block;
pub mod certificate;
mod client;
mod error;
pub mod merkle;
mod proof;
pub mod prover;
pub mod shred;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod transaction;
pub mod validator_set;
mod wire;

pub use block::{Footer, TxPosition};
pub use certificate::{Aggregate, BlockRef, Finality, FinalityCert};
pub use client::{ClusterParams, FinalizedBlock, StalePolicy, ThinClient, VerifiedTransaction};
pub use error::{Error, Result};
pub use merkle::Hash;
pub use proof::{BlockProof, FecSetProof, Limits, ParentLink, TxProof};
pub use transaction::Transaction;
pub use validator_set::{
    Candidate, CandidateSet, ProofOfPossession, Validator, ValidatorSet, VoteAccount,
};
