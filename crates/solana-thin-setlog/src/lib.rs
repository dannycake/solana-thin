//! A signed, hash-chained log of validator-set hashes.
//!
//! The thin client (`solana-thin`) trusts one thing per epoch: the hash of
//! that epoch's ranked validator set. Solana has no commitment a small proof
//! could open to check that hash, so it has to come from people who read the
//! set from the cluster and say what they found. This crate is the format
//! they say it in, and the check a client runs before it believes them.
//!
//! * A [`Record`] states the set hash of one epoch of one cluster, the
//!   [`Source`]s it was read from, and the hash of the record before it.
//! * A [`SignedRecord`] adds Ed25519 signatures over the record's bytes.
//! * A log is a file of signed records, one JSON object per line.
//!   [`verify`] checks every signature and link against the signer keys a
//!   client was shipped with and returns the hash to pin for each epoch.
//! * A [`SetFile`] carries the set itself, which the client hands to the
//!   verifier together with the pinned hash.
//!
//! The library reads and checks; it does not depend on the verifier, and
//! has no network code unless the feature `rpc` is on, which adds the
//! JSON-RPC client the tools share (module `rpc`). The `setlog` binary (feature
//! `cli`) produces logs.
//!
//! # A client's side
//!
//! ```
//! # use solana_thin::testkit::TestValidators;
//! use solana_thin::{ClusterParams, ThinClient};
//! use solana_thin_setlog::{parse, verify, SetFile};
//! # use solana_thin_setlog::{Record, SignedRecord, SigningKey, Source, KIND_SNAPSHOT};
//! # let set = TestValidators::new(4, |i| 100 + i as u64).set();
//! # let source = |n: u64| Source::new(KIND_SNAPSHOT, &format!("node-{n}"), 40 + n).unwrap();
//! # let set_file = SetFile::new("mainnet-beta", 9, 7, set.to_bytes(), vec![source(1), source(2)])?;
//! # let signers: Vec<SigningKey> =
//! #     (1..=3).map(|n| SigningKey::from_seed([n; 32]).unwrap()).collect();
//! # let mut record = SignedRecord::unsigned(set_file.candidate([0; 32])?);
//! # signers.iter().take(2).for_each(|key| record.sign(key));
//! # let (log_text, set_text) = (record.to_json() + "\n", set_file.to_json());
//! # let signer_keys: Vec<[u8; 32]> = signers.iter().map(|key| key.public_key()).collect();
//! # let epoch = 7;
//! // Shipped with the app: the signers' public keys, and how many must agree.
//! let threshold = 2;
//!
//! // Fetched from anywhere: the log, and the set for the epoch at hand.
//! let log = verify(&parse(&log_text)?, &signer_keys, threshold)?;
//! let pin = log.pin(epoch).ok_or("the log has no record for this epoch")?;
//! let set_file = SetFile::from_json(&set_text)?;
//!
//! // The hash comes from the log, never from the set file.
//! let mut client = ThinClient::new(ClusterParams::mainnet(pin.shred_version));
//! client.trust_validator_set_bytes(epoch, set_file.set_bytes(), &pin.set_hash)?;
//! # assert!(client.validator_set(epoch).is_some());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # What a log is worth
//!
//! A verified log proves that `threshold` of the listed signers signed each
//! record. It does not prove the set is right: no source of a validator set
//! is a proof, and a signature only moves the question to the signer. See
//! `docs/SETS.md` for what a signer vouches for and what agreement between
//! sources does and does not show.

mod error;
mod keys;
mod log;
mod record;
#[cfg(feature = "rpc")]
pub mod rpc;
mod set_file;

pub use error::{Error, Result};
pub use keys::{signer_key_from_hex, SignerKey, SigningKey};
pub use log::{check_links, parse, to_text, verify, Pin, VerifiedLog};
pub use record::{
    Record, RecordSignature, SignedRecord, Source, KIND_RANK_MAP, KIND_SNAPSHOT, MAX_LABEL_LEN,
    MAX_NAME_LEN, MAX_SOURCES, RECORD_DOMAIN,
};
pub use set_file::{agree, SetFile, SET_FILE_FORMAT};

/// A SHA-256 digest: a record hash or a validator-set hash.
pub type Hash = [u8; 32];
