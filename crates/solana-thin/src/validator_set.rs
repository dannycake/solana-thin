//! Who is allowed to sign, and with how much weight.
//!
//! A certificate names its signers by *rank*: position in the epoch's
//! validator list, sorted by stake (largest first) and then by BLS key bytes.
//! This module holds that list, reproduces the ordering Agave uses, and
//! checks an aggregate signature against it.
//!
//! ## Where the list comes from
//!
//! This is the weakest joint in any Solana light client, and it is worth being
//! blunt about. Nothing in a block commits to the validator list in a way a
//! small proof can open. So a [`ValidatorSet`] is identified by its
//! [`hash`](ValidatorSet::hash), and the client only uses a set whose hash the
//! caller pinned. How the caller comes to trust that hash (shipped with the
//! app, read from their own node, agreed by several independent sources) is
//! the trust root of the whole system. See `docs/DESIGN.md`.

use crate::certificate::{decode_bitmap, Aggregate};
use crate::error::{Error, Result};
use crate::merkle::{sha256, Hash};
use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::BLST_ERROR;
use std::collections::HashMap;

/// Domain separation tag for vote signatures, the IETF BLS proof-of-possession
/// ciphersuite. Same value as `solana-bls-signatures::HASH_TO_POINT_DST`.
const SIGNATURE_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Domain separation tag for proofs of possession.
const POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const SET_HASH_DOMAIN: &[u8] = b"solana-thin/validator-set/v1";

/// The most validators a set may hold: the most vote accounts a cluster
/// admits for an epoch.
///
/// `MAX_ALPENGLOW_VOTE_ACCOUNTS` in Agave (`runtime/src/bank.rs:262`), applied
/// when the epoch's stakes are filtered (`get_top_epoch_stakes`, same file,
/// line 6886, through `clone_and_filter_for_vat` in
/// `vote/src/vote_account.rs:212`). No rank map is larger, so no real set is
/// refused, and a hostile one costs at most this many key checks.
pub const MAX_VALIDATORS: usize = 2_000;

/// Bytes one validator takes in an encoded set: its key and its stake.
const ENCODED_VALIDATOR_SIZE: usize = 48 + 8;
/// Bytes in the encoding of the largest set.
pub(crate) const MAX_ENCODED_SIZE: usize = 4 + MAX_VALIDATORS * ENCODED_VALIDATOR_SIZE;

/// One validator: its compressed BLS public key and its stake in lamports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validator {
    /// Compressed G1 point, as stored in the validator's vote account.
    pub bls_pubkey: [u8; 48],
    /// Active stake delegated to the validator for the epoch.
    pub stake: u64,
}

/// What an RPC node knows about a vote account, before filtering and ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteAccount {
    /// Address of the vote account.
    pub vote_pubkey: [u8; 32],
    /// The validator identity the vote account names.
    pub node_pubkey: [u8; 32],
    /// The BLS key registered in the vote account, if any.
    pub bls_pubkey: Option<[u8; 48]>,
    /// Stake active for the epoch.
    pub stake: u64,
}

/// The ranked validator list of one epoch.
#[derive(Clone)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    keys: Vec<PublicKey>,
    total_stake: u64,
    hash: Hash,
}

impl core::fmt::Debug for ValidatorSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatorSet")
            .field("validators", &self.validators.len())
            .field("total_stake", &self.total_stake)
            .finish()
    }
}

impl ValidatorSet {
    /// Builds a set from validators already in rank order.
    ///
    /// Fails unless the list is exactly what Agave would produce: stake
    /// strictly positive, ordered by stake descending then key ascending, no
    /// key twice, every key a valid point in the right subgroup.
    pub fn from_ranked(validators: Vec<Validator>) -> Result<Self> {
        if validators.is_empty() {
            return Err(Error::EmptyValidatorSet);
        }
        if validators.len() > MAX_VALIDATORS {
            return Err(Error::LimitExceeded("validator count"));
        }
        let mut total_stake: u64 = 0;
        let mut keys = Vec::with_capacity(validators.len());
        for (i, v) in validators.iter().enumerate() {
            if v.stake == 0 {
                return Err(Error::ZeroStake);
            }
            if i > 0 {
                let prev = &validators[i - 1];
                if prev.bls_pubkey == v.bls_pubkey {
                    return Err(Error::DuplicateValidator);
                }
                let in_order = prev.stake > v.stake
                    || (prev.stake == v.stake && prev.bls_pubkey < v.bls_pubkey);
                if !in_order {
                    return Err(Error::UnsortedValidatorSet);
                }
            }
            total_stake = total_stake
                .checked_add(v.stake)
                .ok_or(Error::StakeOverflow)?;
            keys.push(parse_public_key(&v.bls_pubkey)?);
        }
        // Equal keys with different stakes are not adjacent after sorting.
        let mut seen = std::collections::HashSet::with_capacity(validators.len());
        if !validators.iter().all(|v| seen.insert(v.bls_pubkey)) {
            return Err(Error::DuplicateValidator);
        }
        let hash = set_hash(&validators);
        Ok(Self {
            validators,
            keys,
            total_stake,
            hash,
        })
    }

    /// Sorts validators into rank order and builds the set.
    pub fn from_unordered(mut validators: Vec<Validator>) -> Result<Self> {
        validators.sort_by(|a, b| {
            b.stake
                .cmp(&a.stake)
                .then_with(|| a.bls_pubkey.cmp(&b.bls_pubkey))
        });
        Self::from_ranked(validators)
    }

    /// Builds the set from raw vote accounts, applying the filters Agave's
    /// `BLSPubkeyToRankMap` applies: drop accounts with no stake or no usable
    /// BLS key, and drop *every* account that shares a BLS key or a node
    /// identity with another.
    pub fn from_vote_accounts(accounts: &[VoteAccount]) -> Result<Self> {
        let mut key_count: HashMap<[u8; 48], u32> = HashMap::new();
        let mut node_count: HashMap<[u8; 32], u32> = HashMap::new();
        let mut candidates = Vec::new();
        for account in accounts {
            if account.stake == 0 {
                continue;
            }
            let Some(bls_pubkey) = account.bls_pubkey else {
                continue;
            };
            if parse_public_key(&bls_pubkey).is_err() {
                continue;
            }
            *key_count.entry(bls_pubkey).or_default() += 1;
            *node_count.entry(account.node_pubkey).or_default() += 1;
            candidates.push((account.node_pubkey, bls_pubkey, account.stake));
        }
        let validators = candidates
            .into_iter()
            .filter(|(node, key, _)| key_count[key] == 1 && node_count[node] == 1)
            .map(|(_, bls_pubkey, stake)| Validator { bls_pubkey, stake })
            .collect();
        Self::from_unordered(validators)
    }

    /// The validators, in rank order.
    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Whether the set is empty. Always false for a constructed set.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Sum of all stake in the set.
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// A commitment to the exact ranked list.
    ///
    /// `sha256("solana-thin/validator-set/v1" ‖ count:u32 ‖ (key:48 ‖ stake:u64)*)`.
    /// Two sets have the same hash only if every rank holds the same key with
    /// the same stake.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// Serializes the ranked list: a `u32` count, then key and stake per rank.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.validators.len() * ENCODED_VALIDATOR_SIZE);
        out.extend_from_slice(&(self.validators.len() as u32).to_le_bytes());
        for v in &self.validators {
            out.extend_from_slice(&v.bls_pubkey);
            out.extend_from_slice(&v.stake.to_le_bytes());
        }
        out
    }

    /// Parses the output of [`to_bytes`](Self::to_bytes), re-checking every rule.
    ///
    /// Every key is decompressed and subgroup-checked, which is the expensive
    /// part of loading a set. For bytes from an untrusted source use
    /// [`ThinClient::trust_validator_set_bytes`](crate::ThinClient::trust_validator_set_bytes),
    /// which compares them with the pinned hash before doing any of it.
    ///
    /// The encoding is canonical: bytes this accepts are exactly what
    /// `to_bytes` writes for the set it returns.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = crate::wire::Reader::new(bytes);
        let count = r.u32()? as usize;
        if count > MAX_VALIDATORS {
            return Err(Error::LimitExceeded("validator count"));
        }
        let count = r.bounded_count(count, ENCODED_VALIDATOR_SIZE)?;
        let mut validators = Vec::with_capacity(count);
        for _ in 0..count {
            validators.push(Validator {
                bls_pubkey: r.array()?,
                stake: r.u64()?,
            });
        }
        r.finish()?;
        Self::from_ranked(validators)
    }

    /// Verifies `aggregate` over `message` and returns the stake of its signers.
    pub(crate) fn signed_stake(&self, aggregate: &Aggregate, message: &[u8]) -> Result<u64> {
        let ranks = decode_bitmap(&aggregate.bitmap, self.validators.len())?;
        if ranks.is_empty() {
            return Err(Error::NoSigners);
        }
        let keys: Vec<&PublicKey> = ranks.iter().map(|rank| &self.keys[*rank]).collect();
        verify_aggregate(&keys, message, &aggregate.signature)?;
        // Cannot overflow: the ranks are distinct and the whole set fits.
        Ok(ranks.iter().map(|rank| self.validators[*rank].stake).sum())
    }
}

/// A validator's own evidence that it holds the secret for its BLS key.
///
/// The vote program checks this when a key is registered, and it can be read
/// back from that transaction. It is a BLS signature over
/// `"ALPENGLOW" ‖ vote account address ‖ compressed public key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofOfPossession {
    /// The vote account the key was registered for.
    pub vote_pubkey: [u8; 32],
    /// Compressed G2 point.
    pub signature: [u8; 96],
}

impl ProofOfPossession {
    /// Whether this proves possession of `bls_pubkey`.
    pub fn verify(&self, bls_pubkey: &[u8; 48]) -> bool {
        let Ok(key) = parse_public_key(bls_pubkey) else {
            return false;
        };
        let Ok(signature) = parse_signature(&self.signature) else {
            return false;
        };
        let mut message = Vec::with_capacity(9 + 32 + 48);
        message.extend_from_slice(b"ALPENGLOW");
        message.extend_from_slice(&self.vote_pubkey);
        message.extend_from_slice(bls_pubkey);
        signature.verify(false, &message, POP_DST, &[], &key, false) == BLST_ERROR::BLST_SUCCESS
    }
}

/// The hash of the set that `bytes` encode, without decoding them.
///
/// The set hash covers the validator count and then each key and stake, which
/// is byte for byte the encoding. So for every `bytes` that
/// [`ValidatorSet::from_bytes`] accepts this equals the decoded set's
/// [`hash`](ValidatorSet::hash), and it costs one SHA-256 where decoding costs
/// a subgroup check per key.
pub(crate) fn encoding_hash(bytes: &[u8]) -> Hash {
    sha256(&[SET_HASH_DOMAIN, bytes])
}

fn set_hash(validators: &[Validator]) -> Hash {
    let mut body = Vec::with_capacity(validators.len() * ENCODED_VALIDATOR_SIZE);
    for v in validators {
        body.extend_from_slice(&v.bls_pubkey);
        body.extend_from_slice(&v.stake.to_le_bytes());
    }
    sha256(&[
        SET_HASH_DOMAIN,
        &(validators.len() as u32).to_le_bytes(),
        &body,
    ])
}

/// Decompresses a public key and checks it is a usable one: on the curve, in
/// the prime-order subgroup, and not the identity.
fn parse_public_key(bytes: &[u8; 48]) -> Result<PublicKey> {
    let key = PublicKey::uncompress(bytes).map_err(|_| Error::InvalidPublicKey)?;
    key.validate().map_err(|_| Error::InvalidPublicKey)?;
    Ok(key)
}

fn parse_signature(bytes: &[u8; 96]) -> Result<Signature> {
    let signature = Signature::uncompress(bytes).map_err(|_| Error::InvalidSignature)?;
    signature
        .validate(true)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(signature)
}

/// Checks that every key in `keys` signed `message`, given their aggregate
/// signature. Keys must be distinct and individually validated.
fn verify_aggregate(keys: &[&PublicKey], message: &[u8], signature: &[u8; 96]) -> Result<()> {
    let signature = parse_signature(signature)?;
    let aggregate =
        AggregatePublicKey::aggregate(keys, false).map_err(|_| Error::SignatureMismatch)?;
    let key = aggregate.to_public_key();
    match signature.verify(false, message, SIGNATURE_DST, &[], &key, true) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(Error::SignatureMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::encode_bitmap;
    use crate::testkit::TestValidators;

    #[test]
    fn ranking_follows_stake_then_key() {
        let tv = TestValidators::new(6, |i| [50, 10, 50, 30, 10, 99][i]);
        let set = tv.set();
        let stakes: Vec<u64> = set.validators().iter().map(|v| v.stake).collect();
        assert_eq!(stakes, [99, 50, 50, 30, 10, 10]);
        assert_eq!(set.len(), 6);
        assert!(!set.is_empty());
        assert_eq!(
            format!("{set:?}"),
            "ValidatorSet { validators: 6, total_stake: 249 }"
        );
        let v = set.validators();
        assert!(v[1].bls_pubkey < v[2].bls_pubkey);
        assert!(v[4].bls_pubkey < v[5].bls_pubkey);
        assert_eq!(set.total_stake(), 249);
    }

    #[test]
    fn from_ranked_rejects_anything_but_the_canonical_list() {
        let tv = TestValidators::new(4, |i| 10 + i as u64);
        let good = tv.set().validators().to_vec();

        let mut swapped = good.clone();
        swapped.swap(0, 1);
        assert_eq!(
            ValidatorSet::from_ranked(swapped).unwrap_err(),
            Error::UnsortedValidatorSet
        );

        // Equal stake is ordered by key, and only stake decides between
        // unequal ones: ascending stake is out of order whatever the keys.
        let (low, high) = {
            let (a, b) = (good[0].bls_pubkey, good[1].bls_pubkey);
            (a.min(b), a.max(b))
        };
        let pair = |first: ([u8; 48], u64), second: ([u8; 48], u64)| {
            ValidatorSet::from_ranked(vec![
                Validator {
                    bls_pubkey: first.0,
                    stake: first.1,
                },
                Validator {
                    bls_pubkey: second.0,
                    stake: second.1,
                },
            ])
            .map(|set| set.len())
        };
        assert_eq!(pair((low, 7), (high, 7)), Ok(2));
        assert_eq!(pair((high, 7), (low, 7)), Err(Error::UnsortedValidatorSet));
        assert_eq!(pair((low, 7), (high, 8)), Err(Error::UnsortedValidatorSet));
        assert_eq!(pair((high, 7), (low, 8)), Err(Error::UnsortedValidatorSet));
        assert_eq!(pair((high, 8), (low, 7)), Ok(2));

        let mut zero = good.clone();
        zero[3].stake = 0;
        assert_eq!(
            ValidatorSet::from_ranked(zero).unwrap_err(),
            Error::ZeroStake
        );

        let mut dup = good.clone();
        dup[1].bls_pubkey = dup[0].bls_pubkey;
        assert_eq!(
            ValidatorSet::from_ranked(dup).unwrap_err(),
            Error::DuplicateValidator
        );

        let mut bad_key = good.clone();
        bad_key[2].bls_pubkey = [0xff; 48];
        assert_eq!(
            ValidatorSet::from_ranked(bad_key).unwrap_err(),
            Error::InvalidPublicKey
        );

        assert_eq!(
            ValidatorSet::from_ranked(vec![]).unwrap_err(),
            Error::EmptyValidatorSet
        );
    }

    #[test]
    fn identity_key_is_rejected() {
        // The compressed point at infinity: valid encoding, useless key.
        let mut infinity = [0u8; 48];
        infinity[0] = 0xc0;
        let set = ValidatorSet::from_ranked(vec![Validator {
            bls_pubkey: infinity,
            stake: 1,
        }]);
        assert_eq!(set.unwrap_err(), Error::InvalidPublicKey);
    }

    #[test]
    fn hash_commits_to_keys_stakes_and_order() {
        let tv = TestValidators::new(5, |i| 100 - i as u64);
        let set = tv.set();
        let mut changed = set.validators().to_vec();
        changed[4].stake -= 1;
        assert_ne!(
            ValidatorSet::from_ranked(changed).unwrap().hash(),
            set.hash()
        );
        let fewer = set.validators()[..4].to_vec();
        assert_ne!(ValidatorSet::from_ranked(fewer).unwrap().hash(), set.hash());
        let round_trip = ValidatorSet::from_bytes(&set.to_bytes()).unwrap();
        assert_eq!(round_trip.hash(), set.hash());
    }

    /// Pinning from bytes compares a hash over the encoding before decoding
    /// it. That hash is the set's own only if no set has two encodings.
    #[test]
    fn an_accepted_encoding_is_the_only_one_for_its_set() {
        let tv = TestValidators::new(4, |i| 10 + i as u64);
        let set = tv.set();
        let bytes = set.to_bytes();
        assert_eq!(encoding_hash(&bytes), set.hash());

        // Every single-bit change is refused, or is a different set that
        // encodes back to exactly the changed bytes.
        let mut accepted = 0;
        for bit in 0..bytes.len() * 8 {
            let mut mutant = bytes.clone();
            mutant[bit / 8] ^= 1 << (bit % 8);
            if let Ok(other) = ValidatorSet::from_bytes(&mutant) {
                accepted += 1;
                assert_eq!(other.to_bytes(), mutant, "bit {bit}");
                assert_eq!(other.hash(), encoding_hash(&mutant), "bit {bit}");
                assert_ne!(other.hash(), set.hash(), "bit {bit}");
            }
        }
        // Some stake changes keep the order; nothing else survives.
        assert!(accepted > 0 && accepted < 4 * 64, "{accepted} accepted");

        // Bytes after the last validator, and counts that disagree with what
        // follows them.
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            ValidatorSet::from_bytes(&long).unwrap_err(),
            Error::TrailingBytes
        );
        let mut fewer = bytes.clone();
        fewer[0] -= 1;
        assert_eq!(
            ValidatorSet::from_bytes(&fewer).unwrap_err(),
            Error::TrailingBytes
        );
        let mut more = bytes.clone();
        more[0] += 1;
        assert_eq!(
            ValidatorSet::from_bytes(&more).unwrap_err(),
            Error::Truncated
        );
        assert_eq!(
            ValidatorSet::from_bytes(&bytes[..bytes.len() - 1]).unwrap_err(),
            Error::Truncated
        );
    }

    /// The duplicate check and the set hash both compare key bytes, so a
    /// point must have one encoding. A compressed key is its x coordinate
    /// and three flag bits; the ways to write the same point differently are
    /// an x that is not reduced, and flags that do not say "compressed".
    #[test]
    fn a_public_key_has_exactly_one_encoding() {
        // The field modulus p, big-endian.
        const P: [u8; 48] = [
            0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b,
            0xac, 0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0,
            0xf6, 0xb0, 0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe,
            0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
        ];
        let tv = TestValidators::new(40, |_| 1);
        let mut unreduced = 0;
        for rank in 0..tv.len() {
            let key = tv.pubkey(rank);
            assert!(parse_public_key(&key).is_ok());

            // x + p names the same point if it still fits in 381 bits.
            let flags = key[0] & 0xe0;
            let mut sum = key;
            sum[0] &= 0x1f;
            let mut carry = 0u16;
            for i in (0..48).rev() {
                let digit = u16::from(sum[i]) + u16::from(P[i]) + carry;
                sum[i] = digit as u8;
                carry = digit >> 8;
            }
            if carry == 0 && sum[0] & 0xe0 == 0 {
                sum[0] |= flags;
                assert_eq!(parse_public_key(&sum), Err(Error::InvalidPublicKey));
                unreduced += 1;
            }

            // Without the compression flag these 48 bytes are not a key.
            let mut uncompressed = key;
            uncompressed[0] &= 0x7f;
            assert_eq!(
                parse_public_key(&uncompressed),
                Err(Error::InvalidPublicKey)
            );
            // The infinity flag on a point that is not at infinity.
            let mut infinite = key;
            infinite[0] |= 0x40;
            assert_eq!(parse_public_key(&infinite), Err(Error::InvalidPublicKey));
        }
        assert!(
            unreduced > 0,
            "no test key had an x small enough to add p to"
        );
    }

    #[test]
    fn a_set_holds_no_more_validators_than_a_cluster_admits() {
        assert_eq!(MAX_VALIDATORS, 2_000);
        // Not keys at all: whatever looks at one refuses it.
        let junk = |count: usize| -> Vec<Validator> {
            (0..count)
                .map(|i| Validator {
                    bls_pubkey: [0xff; 48],
                    stake: (count - i) as u64,
                })
                .collect()
        };
        let encode = |validators: &[Validator]| {
            let mut bytes = (validators.len() as u32).to_le_bytes().to_vec();
            for v in validators {
                bytes.extend_from_slice(&v.bls_pubkey);
                bytes.extend_from_slice(&v.stake.to_le_bytes());
            }
            bytes
        };
        // One over the limit is refused for its size, before any key is
        // decompressed. At the limit the keys are what fails.
        for (count, error) in [
            (MAX_VALIDATORS + 1, Error::LimitExceeded("validator count")),
            (u16::MAX as usize, Error::LimitExceeded("validator count")),
            (MAX_VALIDATORS, Error::InvalidPublicKey),
        ] {
            let validators = junk(count);
            assert_eq!(
                ValidatorSet::from_bytes(&encode(&validators)).unwrap_err(),
                error
            );
            assert_eq!(ValidatorSet::from_ranked(validators).unwrap_err(), error);
        }
    }

    #[test]
    fn vote_account_filters_match_agave() {
        let tv = TestValidators::new(5, |_| 10);
        let key = |i: usize| tv.set().validators()[i].bls_pubkey;
        let account = |n: u8, bls: Option<[u8; 48]>, stake| VoteAccount {
            vote_pubkey: [n; 32],
            node_pubkey: [n; 32],
            bls_pubkey: bls,
            stake,
        };
        let mut accounts = vec![
            account(1, Some(key(0)), 5),
            account(2, None, 100),       // no BLS key
            account(3, Some(key(1)), 0), // no stake
            account(4, Some(key(2)), 7),
            account(5, Some(key(2)), 9), // shares a BLS key with 4: both go
            account(6, Some(key(3)), 3),
            account(7, Some(key(4)), 4),
            account(8, Some([0xff; 48]), 50), // not a key at all
        ];
        accounts[6].node_pubkey = [6; 32]; // shares a node with 6: both go
        let set = ValidatorSet::from_vote_accounts(&accounts).unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set.validators()[0].bls_pubkey, key(0));
    }

    #[test]
    fn aggregate_must_come_from_exactly_the_named_signers() {
        let tv = TestValidators::new(8, |_| 10);
        let set = tv.set();
        let msg = b"vote";
        let agg = tv.aggregate(&[0, 1, 2, 5], msg);
        assert_eq!(set.signed_stake(&agg, msg).unwrap(), 40);

        // Same signature, one signer added to or removed from the bitmap.
        let mut more = agg.clone();
        more.bitmap = encode_bitmap(&[0, 1, 2, 5, 6]);
        assert_eq!(set.signed_stake(&more, msg), Err(Error::SignatureMismatch));
        let mut fewer = agg.clone();
        fewer.bitmap = encode_bitmap(&[0, 1, 2]);
        assert_eq!(set.signed_stake(&fewer, msg), Err(Error::SignatureMismatch));

        // Same signers, different message.
        assert_eq!(
            set.signed_stake(&agg, b"other"),
            Err(Error::SignatureMismatch)
        );

        // No signers at all.
        let mut none = agg.clone();
        none.bitmap = encode_bitmap(&[]);
        assert_eq!(set.signed_stake(&none, msg), Err(Error::NoSigners));
    }

    #[test]
    fn signature_must_be_a_real_group_element() {
        let tv = TestValidators::new(3, |_| 10);
        let set = tv.set();
        let mut agg = tv.aggregate(&[0, 1, 2], b"m");
        // The identity is a valid encoding and verifies against nothing useful.
        agg.signature = [0; 96];
        agg.signature[0] = 0xc0;
        assert_eq!(set.signed_stake(&agg, b"m"), Err(Error::InvalidSignature));
        agg.signature = [0xff; 96];
        assert_eq!(set.signed_stake(&agg, b"m"), Err(Error::InvalidSignature));
    }

    #[test]
    fn proof_of_possession_binds_key_and_vote_account() {
        let tv = TestValidators::new(2, |_| 1);
        let pop = tv.proof_of_possession(0, [7; 32]);
        let key0 = tv.pubkey(0);
        let key1 = tv.pubkey(1);
        assert!(pop.verify(&key0));
        assert!(!pop.verify(&key1));
        let mut other_account = pop;
        other_account.vote_pubkey = [8; 32];
        assert!(!other_account.verify(&key0));
        // A vote signature is not a proof of possession: different domain.
        let vote = tv.aggregate(&[0], &{
            let mut m = b"ALPENGLOW".to_vec();
            m.extend_from_slice(&[7; 32]);
            m.extend_from_slice(&key0);
            m
        });
        let cross = ProofOfPossession {
            vote_pubkey: [7; 32],
            signature: vote.signature,
        };
        assert!(!cross.verify(&key0));
    }
}
