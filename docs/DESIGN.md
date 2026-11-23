# Design

This document says what solana-thin checks, why each check exists, and where
its guarantees stop. Every format below was read from Agave's source and then
confirmed against vectors that Agave v4.4.1 generated
(`tools/agave-fixtures`). File references are to the Agave repository.

## Trust model

The client trusts two things it cannot verify:

1. **The shred version** of the cluster (a `u16`, 50093 on mainnet when
   Alpenglow went live). It is inside every signed vote and every shred.
2. **The hash of the validator set** for each epoch it verifies in.

Everything else arrives as untrusted bytes. The security claim is:

> If fewer than 20% of the pinned stake is Byzantine, a transaction the client
> accepts is in a block that the network finalized, at the position the client
> reports, in a part of the block that was executed.

20% is Alpenglow's own fault bound. The claim is about inclusion, not about
execution outcome, and it is subject to the inherited limit in
[Merkle truncation](#merkle-truncation).

## Finality certificates

`votor-messages/src/wire.rs`, `bls-cert-verify/src/cert_verify.rs`,
`runtime/src/validated_block_finalization.rs`.

A validator signs one of:

```
notarize:  0x01 | slot:u64 | block_id:32 | shred_version:u16     (43 bytes)
finalize:  0x02 | slot:u64 |               shred_version:u16     (11 bytes)
```

with BLS12-381, public keys in G1, the IETF proof-of-possession ciphersuite
(`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`). A certificate is an aggregate
signature and a bitmap of signer ranks (`solana-signer-store`, base-2 form:
`0x00 | bit_count:u16 | bits, LSB first`).

A block is final when either holds, measured against the stake of the epoch
the block's slot is in:

- **fast:** signers of a notarize aggregate for the block hold ≥ 80%;
- **slow:** signers of a notarize aggregate for the block hold ≥ 60% *and*
  signers of a finalize aggregate for its slot hold ≥ 60%.

Two things a verifier must not get wrong:

- A fast certificate is byte-for-byte a notarization certificate with more
  signers. The threshold is the only difference.
- A finalize vote names no block. It is only meaningful next to a 60%
  notarization of the exact block.

`FinalityCert` mirrors the `BlockFinalizationCert` that leaders embed in block
footers, so a prover can copy one off the ledger.

## Validator sets

`runtime/src/epoch_stakes.rs` (`BLSPubkeyToRankMap`).

Rank order is stake descending, then compressed BLS key bytes ascending.
Vote accounts with zero stake or no BLS key are dropped, and so is *every*
account that shares a BLS key or a node identity with another.
`ValidatorSet::from_vote_accounts` reproduces this; `from_ranked` accepts only
the canonical list.

The set hash is
`sha256("solana-thin/validator-set/v1" ‖ count:u32 ‖ (key:48 ‖ stake:u64)*)`.

**Which epoch's stake.** Certificates for slots in epoch `E` are checked
against the stake snapshot taken at the start of epoch `E − 1`. That is the
stake `getVoteAccounts` reports as active during epoch `E − 1`. So the set for
the next epoch can be fetched at any time during the current one.

**Why the hash must be pinned.** BLS aggregation is safe only if every key in
the set has proven possession of its secret. The vote program checks that at
registration. A set from an untrusted source may contain a key computed to
cancel the honest ones (`rogue = x·G − Σ honest`), after which one signature
by `x` verifies as a certificate from everyone. The test
`a_rogue_key_forges_everything_if_an_unpinned_set_is_trusted` does exactly
this.

### Stale-set mode

Off by default. With a `StalePolicy`, a certificate for epoch `E + j` can be
checked against the set pinned for epoch `E`:

- The caller supplies a `CandidateSet`: the claimed key order for `E + j`. It
  is untrusted. Its order is checked by the signature itself, since the wrong
  order yields the wrong aggregate key.
- A signer counts for its stake *in the pinned set*. A key not in the pinned
  set must carry a valid proof of possession (a BLS signature over
  `"ALPENGLOW" ‖ vote_account ‖ key` under the PoP domain, which is public
  on-chain data) and counts for zero.
- No key may be listed twice.
- Each threshold is raised by `drift_bps_per_epoch × j`.

Reasoning: let `d` be the total variation distance between the old and new
normalized stake vectors, treating validators that left as weight zero. A
signer set holding `τ + d` of old stake holds at least `τ` of new stake. If
`d ≤ drift × j`, the certificate meets the real threshold.

The weak point is the "if". Stake activation and deactivation are each capped
at 9% of total stake per epoch, which motivates 900 basis points. Validators
can also leave the set by other routes (losing their BLS key registration,
key collisions) that this cap does not cover. Stale mode is a grace window of
an epoch or two, not a way to follow the chain indefinitely. It cannot be
chained: a set accepted this way never becomes a base for another step,
because the client never learns the new stakes.

## Block ids

`ledger/src/blockstore.rs` (`build_double_merkle_tree`),
`ledger/src/shred/merkle_tree.rs`.

A block is cut into data shreds of 1,203 bytes, grouped into FEC sets of 32
data and 32 coding shreds. Each FEC set has a Merkle tree over its 64 shreds:

```
leaf  = sha256("\x00SOLANA_MERKLE_SHREDS_LEAF" ‖ shred[64 .. proof_offset])
node  = sha256("\x01SOLANA_MERKLE_SHREDS_NODE" ‖ left[..20] ‖ right[..20])
```

The block id is the root of a second tree with the same node rule:

```
leaves: FEC root 0, FEC root 1, ..., FEC root n−1,
        sha256(parent_slot:u64 ‖ parent_id:32 ‖ n:u32)
```

A level with an odd number of nodes pairs the last with itself. In a tree of
three leaves, leaf 2 therefore also verifies at index 3. The verifier closes
this by fixing the path length from the leaf count, requiring the parent leaf
at index `n` exactly (and `n` is inside that leaf's preimage), and requiring
FEC set indexes below `n`.

The hashed region of a shred contains its slot, index, shred version and FEC
set index. The verifier does not take these from the proof: it rebuilds the
leaf from the certified slot, the position the proof claims, and its own shred
version. A shred therefore verifies only where it really is.

## From bytes to "a transaction of this block"

`entry/src/block_component.rs`, `runtime/src/block_component_processor.rs`,
`ledger/src/shredder.rs` (`deshred`).

The data shreds of a slot hold *components*: runs of shreds ending at one
flagged `DATA_COMPLETE`. A component is an entry batch or a marker. A valid
block is: header marker, entry batches, footer marker, final tick.

Transactions are not length-prefixed. The only way to know that bytes are a
transaction is to parse from the start of the batch. So the verifier requires:

1. **Shred 0, holding a header whose parent equals the parent in the block's
   tree.** With fast leader handover a leader may emit an `UpdateParent`
   marker part way through; validators then discard everything before it
   without executing it. The tree commits to the *final* parent and the
   header to the *first*. Agave rejects an `UpdateParent` that names the same
   parent as the header (`UpdateParentMatchesBlockHeader`), so equality means
   no switch happened and the whole block ran.
2. **The shred before the component, flagged `DATA_COMPLETE`.** Without it a
   proof could start parsing in the middle of a batch, inside bytes an
   attacker chose. The flag is inside the hashed leaf.
3. **Every shred from the component's start to the transaction's last byte.**
   The walk stops at the first `DATA_COMPLETE`, as the validator's does.

Then the batch is walked (`count`, then per entry `num_hashes`, `hash`,
`tx_count`, transactions) to the claimed position. The transaction parser
handles legacy, v0 and v1 encodings and has one job: consume exactly the bytes
a validator would for every valid transaction.

## Proof format

`TxProof::to_bytes`, version 1, little-endian:

```
"STP" 0x01
certificate: kind:u8, slot, id, aggregate(s)
ancestry:    count:u16, then per hop: parent slot, parent id, fec_set_count, path
block:       parent link; set count:u16; per FEC set:
               set:u32, first:u8, shred count:u8, chained root:32,
               per shred: variant, parent_offset, flags, size, body_len:u16, body,
               siblings, coding subtree root:20, path
position:    component_start:u32, entry:u32, transaction:u32
footer:      0, or 1 and start:u32
```

Decoding rejects unknown versions, trailing bytes, lengths the input cannot
back, and shred bodies with trailing zeros (so each shred has one encoding).

## Merkle truncation

Tree nodes are truncated to 20 bytes. Second-preimage resistance (160 bits)
protects against anyone who did not produce the block. Collision resistance
is about 80 bits, and the party who can use a collision is the block's leader:
it could prepare two different shreds with the same truncated leaf hash, give
validators one, and later show a light client the other. Validators have the
same exposure, where it surfaces as a duplicate block. This crate cannot do
better than the tree it verifies.

## What is out of scope in v0.1

- Proving execution success, logs, or account state. Not possible today.
- Blocks with an `UpdateParent` marker. Detected and refused.
- Fetching anything. The crate has no network code.
- Verifying a transaction's Ed25519 signatures. A block containing a badly
  signed transaction is invalid and would not be finalized.

## What Solana could add

Three small changes would remove the largest limits. None is proposed
upstream yet.

1. **A validator-set commitment.** Put the hash of epoch `E + 1`'s ranked
   `(BLS key, stake)` list in a block footer during epoch `E`. Footers are
   already covered by the block id, so a light client could follow epochs with
   one small proof each and the pinned hash would be needed only once.
2. **A receipts root.** A per-block Merkle root over transaction status, as
   SIMD-0064 described, committed in the footer. Inclusion proofs would then
   say whether a transaction succeeded.
3. **An RPC method for proofs.** `getBlock` could return the footer, and a
   `getTransactionProof` could return what `solana_thin::prover` builds. Until
   then a prover needs shred access.

## Open questions

- How large are entry batches on mainnet in practice? Proof size follows from
  it and it has not been measured here.
- Is fast leader handover active on mainnet, and how often do blocks switch
  parent? That decides whether supporting those blocks is worth the extra
  rules.
- Stale mode's drift assumption deserves a proper analysis against the ways a
  validator can leave the set.
