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

"Executed" is a statement about that part of the block, not about the
transaction. Validators processed every transaction in it, and each one
either committed or would have made the block invalid. But "committed" has
three shapes: the instructions ran (successfully or not, fee paid); the
accounts could not be loaded (fee paid, nothing ran); or, where
`relax_fee_payer_constraint` (SIMD-0290) is active, the fee payer could not
pay and the transaction was recorded as a no-op (no fee, nothing ran).
Honest leaders drop the last kind, but a block containing one is valid, so a
proof of inclusion cannot rule it out.

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

`runtime/src/epoch_stakes.rs` (`BLSPubkeyToRankMap`), `runtime/src/bank.rs`
(`get_top_epoch_stakes`), `vote/src/vote_account.rs`
(`clone_and_filter_for_vat`).

Membership is decided in two steps.

**Admission** (SIMD-0357). At the first block of an epoch the cluster keeps
vote accounts that have stake, a BLS key, and a lamport balance of at least
the rent-exempt minimum plus one epoch's Validator Admission Ticket (0.8 SOL
on mainnet in November 2026; it scales with slot time). If more than 2,000
qualify, the lowest-staked are cut. Each admitted account is debited the
ticket, and the debit appears in that block's rewards as `VATDebit`.

This step cannot be reproduced from `getVoteAccounts`, which lists every
staked account whatever its balance, and balances read later do not say what
they were at that block. The debits do: `tools/fetch_vote_accounts.py` reads
them and keeps only accounts that paid. On mainnet in epoch 1095 that was 664
of 684 staked accounts with a key. The 20 left out held 0.02% of stake, and
one wrong member is enough to shift every rank below it and fail every
certificate.

**Ranking.** Of the admitted accounts, *every* account that shares a BLS key
or a node identity with another is dropped. The rest are ordered by stake
descending, then compressed BLS key bytes ascending.
`ValidatorSet::from_vote_accounts` does this step; `from_ranked` accepts only
the canonical list.

The set hash is
`sha256("solana-thin/validator-set/v1" ‖ count:u32 ‖ (key:48 ‖ stake:u64)*)`.

**Which epoch's stake.** Certificates for slots in epoch `E` are checked
against the stake snapshot taken at the start of epoch `E − 1`. That is the
stake `getVoteAccounts` reports as active during epoch `E − 1`. So the set for
the next epoch can be fetched during the current one.

This was checked on a cluster of four running validators whose stake moved
every epoch: pinning the set fetched one epoch earlier verified 705 of 705
certificates across 14 epochs; pinning the set from the same epoch, or from
two epochs earlier, rejected 19 each (see `docs/LOCAL-VALIDATOR.md`).

Fetch early in the epoch. The snapshot froze each account's BLS key and node
identity at the epoch's first block, and RPC reports them as they are now. An
account that changes either mid-epoch yields a wrong set from a late fetch.

**Why the hash must be pinned.** BLS aggregation is safe only if every key in
the set has proven possession of its secret. The vote program checks that at
registration. A set from an untrusted source may contain a key computed to
cancel the honest ones (`rogue = x·G − Σ honest`), after which one signature
by `x` verifies as a certificate from everyone. The test
`a_rogue_key_forges_everything_if_an_unpinned_set_is_trusted` does exactly
this.

### Stale-set mode

Not compiled by default: it sits behind the Cargo feature
`unsound-stale-set`, named for what it is. With a `StalePolicy`, a
certificate for epoch `E + j` can be checked against the set pinned for epoch
`E`:

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

The weak point is the "if", and it is weaker than a rate limit suggests.
Stake activation and deactivation are each capped at 9% of total stake per
epoch, which motivates 900 basis points. That cap does not bound `d`:

- **Stake can enter the set without activating.** Stake that is already
  active but outside the ranked set joins at full weight in one epoch when
  its validator registers a BLS key, tops up its admission balance, or stops
  sharing a key or node identity with another account. If a share `x` of the
  new total arrives this way, signers holding 89% of pinned stake hold
  `0.89 × (1 − x)` of real stake, which is under 80% once `x` exceeds 10.1%.
  The client would report fast finality for a block that only 72% notarized
  when `x` is 19%.
- **The margin has no slack.** 9% deactivating among the signers and 9%
  activating elsewhere lands exactly on the threshold.
- Validators can also leave by the same routes.

So stale mode is not a proof under any assumption the protocol enforces. It
is a grace window for an application that would otherwise have no answer, to
be used for an epoch at most and never for value. It cannot be chained: a set
accepted this way never becomes a base for another step, because the client
never learns the new stakes.

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

   The header must be read from **shred 0 alone**, not from the first
   component. Agave's blockstore records the header's parent only when the
   header parses from shred 0's own bytes (`ParentInfo::maybe_parse_block_header`).
   A leader can let a 54-byte header run on into shred 1. The blockstore then
   sees no header, has nothing to compare an `UpdateParent` against, and
   accepts one that names the *same* parent. Header and tree agree, and the
   prefix was still thrown away. v0.1 first read the header from the whole
   component and accepted a transaction from such a prefix; a review found
   it. The test is `a_header_split_across_shreds_does_not_hide_an_abandoned_prefix`.

   The blockstore has a second way to see no header: a header whose parent
   id is all zeros reads to it as an unset one (`ParentInfo::from_slot_meta`),
   so again an `UpdateParent` to the same parent is not compared with it. A
   block has such a parent only when it is built directly on a cluster's
   first block. The verifier proves nothing in those (`ZeroParentId`).

   **If parent switches are ever supported**, the rule would be: with `H`
   the header from shred 0 alone and `P` the tree's parent, accept when
   `H == P` and `P`'s id is not zero; or when the proof opens shreds `u - 1`
   and `u = 32k`, shred `u - 1` is flagged `DATA_COMPLETE`, shred `u`'s own
   data parses as an `UpdateParent` naming `P`, the slot is the first of its
   leader window, and the claim's component starts at or after `u`. That is
   how the blockstore recognises the marker (`maybe_parse_update_parent`),
   and it allows only one. It is not implemented: the feature is inactive on
   mainnet, and Agave and Firedancer disagree about blocks with no header.
2. **The shred before the component, flagged `DATA_COMPLETE`.** Without it a
   proof could start parsing in the middle of a batch, inside bytes an
   attacker chose. The flag is inside the hashed leaf.
3. **Every shred from the component's start to the transaction's last byte.**
   The walk stops at the first `DATA_COMPLETE`, as the validator's does.
4. **Shreds a validator would have kept.** Before a shred is hashed it must
   pass what the fetch filter and `sanitize` require of it: a size inside
   the body, no "last in slot" without "data complete", "data complete"
   only on the last data shred of a FEC set, and a parent offset that is
   non-zero and does not reach past slot 0. After the header check, every
   opened shred must also name the parent slot the tree commits to. A
   validator drops or dies on each of these, so a block that shows one was
   never completed. Components therefore start only at the first shred of a
   FEC set.

Then the batch is walked (`count`, then per entry `num_hashes`, `hash`,
`tx_count`, transactions) to the claimed position. The transaction parser
handles legacy, v0 and v1 encodings and has one job: consume exactly the bytes
a validator would for every valid transaction.

Replay parses transactions with `agave-transaction-view`
(`entry/src/block_component_parser.rs`), which is stricter than this parser:
at most 12 signatures, single-byte key and lookup-table counts, compact
integers of at most two bytes. Everything it accepts, this parser reads to the
same length. What this parser accepts beyond that can only occur in bytes a
validator never executed, which is what the two rules above exist to exclude.

Agave discards a data shred flagged `DATA_COMPLETE` unless it is the last of
its FEC set (`ledger/src/shred/filter.rs`), before and after erasure
recovery, so components align to FEC sets. The verifier requires the same.

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

- Entry batches on mainnet were at most 61 KB in the four blocks measured,
  12 to 15 per block, which puts the median proof at 19 KB. Is that a cap
  leaders will keep? A proof could be much smaller if transactions were
  length-prefixed or batches were Merkle trees.
- Is fast leader handover active on mainnet, and how often do blocks switch
  parent? None of the four blocks measured did. That decides whether
  supporting those blocks is worth the extra rules.
- Is there any other place where the verifier reads a block differently from
  a validator? The split header was one. Each such difference is a way to
  show a client bytes that never ran.
- Stale mode has no sound bound today. Is there one worth having, or should
  it go?
