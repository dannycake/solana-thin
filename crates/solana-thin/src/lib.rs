//! A thin client for Solana after Alpenglow.
//!
//! Given a proof from any untrusted source, this crate tells you whether a
//! transaction is in a block that Solana's validators finalized. It does not
//! run a node, replay blocks, or trust the server it talks to.
//!
// The example runs against the testkit, so it is a test only where that is on.
#![cfg_attr(feature = "testkit", doc = "```")]
#![cfg_attr(not(feature = "testkit"), doc = "```ignore")]
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
//! let proof = TxProof::from_bytes(&proof_bytes, client.limits())?;
//! let verified = client.verify_signature(&proof, &my_signature)?;
//!
//! assert_eq!(verified.transaction.signature(), Some(&my_signature));
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
pub use client::{ClusterParams, FinalizedBlock, ThinClient, VerifiedTransaction};
pub use error::{Error, ErrorKind, Result};
pub use merkle::Hash;
pub use proof::{BlockProof, FecSetProof, Limits, ParentLink, TxProof, MAX_FEC_SETS_PER_SLOT};
pub use transaction::Transaction;
pub use validator_set::{ProofOfPossession, Validator, ValidatorSet, VoteAccount};

/// Types that may gain variants or fields are `#[non_exhaustive]`, so that
/// adding one is not a breaking change. Each snippet below is something a
/// caller could otherwise write and that an addition would then break; each
/// must fail to compile from outside the crate.
///
/// Matching every variant with no wildcard arm:
///
/// ```compile_fail,E0004
/// fn name(finality: solana_thin::Finality) -> &'static str {
///     match finality {
///         solana_thin::Finality::Fast => "fast",
///         solana_thin::Finality::Slow => "slow",
///     }
/// }
/// ```
///
/// ```compile_fail,E0004
/// fn is_about_the_input(kind: solana_thin::ErrorKind) -> bool {
///     use solana_thin::ErrorKind::*;
///     match kind {
///         Malformed | Unsupported | LimitExceeded => true,
///         InvalidValidatorSet | EpochNotPinned | CertificateRejected => false,
///         ProofRejected | WrongTransaction | UnprovableBlock => false,
///         InvalidParameters => false,
///     }
/// }
/// ```
///
/// ```compile_fail,E0004
/// fn slot(cert: &solana_thin::FinalityCert) -> u64 {
///     match cert {
///         solana_thin::FinalityCert::Fast { block, .. } => block.slot,
///         solana_thin::FinalityCert::Slow { block, .. } => block.slot,
///     }
/// }
/// ```
///
/// ```compile_fail,E0004
/// fn is_legacy(version: solana_thin::transaction::MessageVersion) -> bool {
///     use solana_thin::transaction::MessageVersion::*;
///     match version {
///         Legacy => true,
///         V0 | V1 => false,
///     }
/// }
/// ```
///
/// ```compile_fail,E0004
/// fn names_a_parent(marker: &solana_thin::block::Marker) -> bool {
///     use solana_thin::block::Marker::*;
///     match marker {
///         Header { .. } | UpdateParent { .. } => true,
///         Footer(_) | GenesisCertificate => false,
///     }
/// }
/// ```
///
/// Building a value field by field:
///
/// ```compile_fail,E0639
/// let limits = solana_thin::Limits {
///     max_proof_bytes: 1 << 20,
///     max_ancestry: 16,
/// };
/// ```
///
/// ```compile_fail,E0639
/// let params = solana_thin::ClusterParams {
///     shred_version: 50093,
///     slots_per_epoch: 432_000,
///     first_normal_slot: 0,
///     first_normal_epoch: 0,
/// };
/// ```
///
/// ```compile_fail,E0639
/// let footer = solana_thin::Footer {
///     bank_hash: [0; 32],
///     producer_time_nanos: 0,
///     user_agent: Vec::new(),
///     finality: None,
/// };
/// ```
///
/// ```compile_fail,E0639
/// fn finalized(block: solana_thin::BlockRef) -> solana_thin::FinalizedBlock {
///     solana_thin::FinalizedBlock {
///         block,
///         finality: solana_thin::Finality::Fast,
///     }
/// }
/// ```
///
/// ```compile_fail,E0639
/// let transaction = solana_thin::Transaction {
///     version: solana_thin::transaction::MessageVersion::Legacy,
///     signatures: Vec::new(),
///     account_keys: Vec::new(),
///     recent_blockhash: [0; 32],
///     instructions: Vec::new(),
///     message: Vec::new(),
/// };
/// ```
///
/// ```compile_fail,E0639
/// fn verified(
///     transaction: solana_thin::Transaction,
///     block: solana_thin::BlockRef,
///     finalized_by: solana_thin::FinalizedBlock,
/// ) -> solana_thin::VerifiedTransaction {
///     solana_thin::VerifiedTransaction {
///         transaction,
///         block,
///         parent: block,
///         component_start: 32,
///         position: solana_thin::TxPosition {
///             entry: 0,
///             transaction: 0,
///         },
///         finalized_by,
///         footer: None,
///     }
/// }
/// ```
#[cfg(doctest)]
struct NonExhaustive;
