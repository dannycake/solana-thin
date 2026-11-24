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

/// The most validators a set may hold. Ranks travel as `u16`.
pub const MAX_VALIDATORS: usize = u16::MAX as usize;

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
        let mut out = Vec::with_capacity(4 + self.validators.len() * 56);
        out.extend_from_slice(&(self.validators.len() as u32).to_le_bytes());
        for v in &self.validators {
            out.extend_from_slice(&v.bls_pubkey);
            out.extend_from_slice(&v.stake.to_le_bytes());
        }
        out
    }

    /// Parses the output of [`to_bytes`](Self::to_bytes), re-checking every rule.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = crate::wire::Reader::new(bytes);
        let count = r.u32()? as usize;
        let count = r.bounded_count(count, 56)?;
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

    #[cfg(feature = "unsound-stale-set")]
    fn stake_by_key(&self) -> HashMap<[u8; 48], u64> {
        self.validators
            .iter()
            .map(|v| (v.bls_pubkey, v.stake))
            .collect()
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

/// One rank of an unverified validator list for an epoch the client has no
/// pinned set for.
#[cfg(feature = "unsound-stale-set")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The BLS key claimed to hold this rank.
    pub bls_pubkey: [u8; 48],
    /// Needed only if the key is not in the client's trusted set.
    pub proof_of_possession: Option<ProofOfPossession>,
}

/// An *untrusted* key list for a later epoch, used only to turn bitmap ranks
/// back into keys. See [`crate::StalePolicy`].
///
/// Nothing in it is taken on faith:
///
/// * Its order is checked by the signature itself. Put the keys in the wrong
///   order and the aggregate no longer verifies.
/// * It carries no stake. Weight comes only from the trusted set.
/// * A key the trusted set has never seen must prove possession. Without that
///   an attacker could add a key built to cancel honest keys out of the
///   aggregate (a rogue-key attack) and forge any certificate.
/// * No key may appear twice. A doubled key would let one real signature be
///   counted as two.
#[cfg(feature = "unsound-stale-set")]
#[derive(Clone)]
pub struct CandidateSet {
    keys: Vec<[u8; 48]>,
    parsed: Vec<PublicKey>,
    proven: Vec<bool>,
}

#[cfg(feature = "unsound-stale-set")]
impl core::fmt::Debug for CandidateSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CandidateSet")
            .field("keys", &self.keys.len())
            .finish()
    }
}

#[cfg(feature = "unsound-stale-set")]
impl CandidateSet {
    /// Checks and stores a candidate list. Proofs of possession are verified
    /// here, once, so that certificate checks stay cheap.
    pub fn new(candidates: Vec<Candidate>) -> Result<Self> {
        if candidates.is_empty() {
            return Err(Error::EmptyValidatorSet);
        }
        if candidates.len() > MAX_VALIDATORS {
            return Err(Error::LimitExceeded("validator count"));
        }
        let mut seen = std::collections::HashSet::with_capacity(candidates.len());
        let mut keys = Vec::with_capacity(candidates.len());
        let mut parsed = Vec::with_capacity(candidates.len());
        let mut proven = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if !seen.insert(candidate.bls_pubkey) {
                return Err(Error::DuplicateValidator);
            }
            parsed.push(parse_public_key(&candidate.bls_pubkey)?);
            proven.push(
                candidate
                    .proof_of_possession
                    .is_some_and(|pop| pop.verify(&candidate.bls_pubkey)),
            );
            keys.push(candidate.bls_pubkey);
        }
        Ok(Self {
            keys,
            parsed,
            proven,
        })
    }

    /// Number of ranks.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the list is empty. Always false for a constructed list.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verifies `aggregate` over `message` using this list for ranks, and
    /// returns how much stake *of the trusted set* the signers hold.
    pub(crate) fn signed_trusted_stake(
        &self,
        trusted: &ValidatorSet,
        aggregate: &Aggregate,
        message: &[u8],
    ) -> Result<u64> {
        let ranks = decode_bitmap(&aggregate.bitmap, self.keys.len())?;
        if ranks.is_empty() {
            return Err(Error::NoSigners);
        }
        let stake_by_key = trusted.stake_by_key();
        let mut signed: u64 = 0;
        let mut keys = Vec::with_capacity(ranks.len());
        for rank in &ranks {
            match stake_by_key.get(&self.keys[*rank]) {
                Some(stake) => signed += stake,
                None if self.proven[*rank] => {}
                None => return Err(Error::MissingProofOfPossession),
            }
            keys.push(&self.parsed[*rank]);
        }
        verify_aggregate(&keys, message, &aggregate.signature)?;
        Ok(signed)
    }
}

fn set_hash(validators: &[Validator]) -> Hash {
    let mut body = Vec::with_capacity(validators.len() * 56);
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
