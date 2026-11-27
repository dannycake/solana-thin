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

The bound is about validators while they have stake to lose. A set's keys
go on working after their owners have unstaked, and enough of them, sold or
stolen later, could sign a conflicting block for an old slot. Every
proof-of-stake light client has this long-range exposure. Here it is exactly
the epochs a caller leaves pinned: a certificate is only ever checked against
the set pinned for its own epoch. Pin the epochs you need proofs from, drop
the ones you no longer do (`ThinClient::forget_epochs_before`), and do not
pin an old epoch's hash on the word of a source you would not trust for the
current one.

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
against the stake snapshot taken at the first block of epoch `E − 1`. So the
set for the next epoch is fixed, and can be fetched, during the current one.

This was checked on a cluster of four running validators whose stake moved
every epoch: pinning the set fetched one epoch earlier verified 705 of 705
certificates across 14 epochs; pinning the set from the same epoch, or from
two epochs earlier, rejected 19 each (see `docs/LOCAL-VALIDATOR.md`).

**What `getVoteAccounts` reports is not quite that snapshot.** Three things
differ.

- *Stake.* The snapshot is taken before the staking rewards for the epoch
  that just ended are paid; they go out over the blocks that follow
  (`runtime/src/bank.rs`, `process_new_epoch`: `update_epoch_stakes` runs
  before `begin_partitioned_rewards`). From the epoch's second block on,
  `getVoteAccounts` reports each validator's stake with its delegators'
  rewards added. For most validators that is 0.03% and changes no rank. It
  changes ranks where two validators are that close, and where a validator's
  delegators are leaving: stake being deactivated still earns, and RPC
  counts it. On mainnet in epoch 1095 two validators were reported at 77.4
  and 46.2 SOL whose snapshot stake was 2.1 and 3.4 SOL. Eight ranks out of
  664 were wrong, and every certificate of epoch 1096 failed against the
  fetched set (`tests/mainnet_snapshot.rs` keeps four of them). On testnet
  the same comparison found 50 of 481 ranks wrong.
- *Keys.* The snapshot froze each account's BLS key and node identity at
  that first block, and RPC reports them as they are now.
- *Totals.* Even with the order right, stake that is off by the rewards
  shifts a certificate's share of stake. On mainnet that shift was at most
  a quarter of a basis point, which matters only to a certificate that
  clears 60% or 80% by less.

So a set built from `getVoteAccounts` is a candidate, not the set.

**A certificate does not vouch for a set.** It is tempting to check a
candidate against a real certificate of its epoch and pin it if that
verifies. The check proves only that the right key sits at each rank the
certificate names. It says nothing about stake: on devnet the previous
epoch's set verified every certificate of the next, because only stake had
moved, and a set with one validator's stake multiplied passes too
(`a_certificate_does_not_vouch_for_the_stake_in_a_set`), after which that
validator's signature alone is a "fast" certificate. A certificate is a
check that a set is not wrong in order. The stake must come from a source
that is exact.

Order itself needs exact stake. In the mainnet set for epoch 1097 five pairs
of validators tie to the lamport and are ordered by key, and the smallest
gap that is not zero is 131,854 lamports.

**Where the exact snapshot can be read.** Three places, measured in November
2026. They share no code path and agree to the lamport.

- *A bank snapshot.* Every snapshot a node writes carries the epoch-stakes
  maps for the epochs from three back to one ahead, already filtered for
  admission. Nodes that serve snapshots over HTTP send the bank file near
  the front of the archive: a client can stop about 68 MB into an
  incremental snapshot. Three unrelated mainnet nodes, at three slots, gave
  identical maps. The sets built from them rank in the order of Agave's own
  rank map, and the one for epoch 1096 verifies that epoch's certificates.
  This works on Agave 4.4. The maps are not an input to the bank hash, so
  nothing in the archive vouches for them.
- *`getVatActiveSetRankMap`* (Agave 4.5: on testnet and devnet, not yet on
  mainnet). Given a slot it returns that epoch's total stake and, per rank,
  the vote key, node identity, BLS key and stake. The hash computed from the
  answer alone is this crate's set hash.
- *`getVoteAccounts` less the rewards.* Subtract from each vote account's
  stake every reward of type `Staking` paid to its delegators in the
  epoch's reward blocks. Rewards of type `DeactivatedStake` never entered
  the stake and must be left alone. This equals the rank map to the lamport
  on devnet (21 of 21 validators) and testnet (481 of 481), and the snapshot
  on mainnet (662 of 662 for epoch 1097). It is exact and heavy: about 520
  block fetches and a sweep of 1.3 million stake accounts on mainnet, half
  an hour from a public endpoint, and it has to be done in the same epoch.

None of the three is a proof. A set hash should rest on independent sources
that agree, until the set is on chain under the bank hash (SIMD-0676, open),
and a light client would then still need a way to open one account against
that hash, which nothing specifies today.

The first two are read by tools in this repository (`snapshot-stakes` and
`setlog from-rank-map`). `setlog` refuses on any difference between sources
and records what agreed in a signed, hash-chained log that a client verifies
before pinning. It also compares each source's members with the `VATDebit`
rewards of the block that admitted them: Agave charges exactly the accounts
of the epoch-stakes map, after the cut to 2,000 and before the ranking step
drops shared keys, so the debits must equal a snapshot's map and exceed a
rank map by only the accounts that share a key. [SETS.md](SETS.md) has the
format, the procedure, and what agreement between sources and the
admission check do and do not show.

**Why the hash must be pinned.** BLS aggregation is safe only if every key in
the set has proven possession of its secret. The vote program checks that at
registration. A set from an untrusted source may contain a key computed to
cancel the honest ones (`rogue = x·G − Σ honest`), after which one signature
by `x` verifies as a certificate from everyone. The test
`a_rogue_key_forges_everything_if_an_unpinned_set_is_trusted` does exactly
this.

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
   tree.** With fast leader handover a block may switch parent partway through
   with an `UpdateParent` marker: the tree commits to the *final* parent and
   the header to the *first*. The verifier mirrors Agave's rule that an
   `UpdateParent` must not name the same parent as the header
   (`UpdateParentMatchesBlockHeader`), so when the header's parent equals the
   tree's parent, no switch happened and the whole block is the one the tree
   commits to.

   The header is read from **shred 0 alone**, not from the first component,
   because that is where the rule above reads it
   (`ParentInfo::maybe_parse_block_header`). The verifier therefore requires
   the header wholly in shred 0, and refuses a block whose header is not
   there. v0.1 read it from the whole first component instead; a review caught
   that, and the test is
   `a_header_split_across_shreds_does_not_hide_an_abandoned_prefix`.

   A parent id of all zeros cannot be told from an unset one
   (`ParentInfo::from_slot_meta`), so the same-parent rule cannot stand on it.
   A block has such a parent only when it is built directly on a cluster's
   first block, and the verifier proves nothing in those (`ZeroParentId`).

   **Parent switches** (fast leader handover) are supported behind the
   default-off `fast-leader-handover` feature. With `H` the header from shred 0
   alone and `P` the tree's parent: when `H == P` and `P`'s id is not zero, the
   block did not switch and the whole of it ran (today's path). When `H != P`
   the leader switched part way, and a proof for a transaction in the executed
   *suffix* is accepted when the proof opens shreds `u - 1` and `u = 32k`, shred
   `u - 1` is flagged `DATA_COMPLETE`, shred `u`'s own data parses as an
   `UpdateParent` naming `P` (which must be a real block, `P`'s id not zero,
   `P.slot <= H.slot`), the slot is the first of its leader window
   (`slot % 4 == 0`), and the claim's component starts at or after `u`. A claim
   before `u`, in the abandoned prefix, is refused (`AbandonedPrefix`), as is a
   footer before `u`. That is how the blockstore recognizes the marker
   (`maybe_parse_update_parent`), and it allows only one; "at most one marker"
   and "first in window" are enforced by Agave before finality, so the
   certificate stands for them, as it does for the rules a verifier cannot see.

   One point confirmed against Agave while implementing, against an early guess:
   a switched block's shreds all keep **the header's** parent offset (`H`), not
   the switched-to parent's. The shred parent offset is a single slot-wide
   value, checked equal to the block header's parent and `>=` the marker's
   (`ParentInfo::validate_shred_parent`); the `UpdateParent` marker re-parents
   replay without touching the shred headers. So on the switch path every opened
   shred must name `H`, where on the ordinary path it names `P`.

   **Default builds refuse every switched block** (`UpdateParentBlock`), as they
   must until a cluster activates fast leader handover; the feature changes only
   what the verifier accepts, never the wire format or a default build's bytes.
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
   opened shred must also name the parent slot the tree commits to (or, on
   the fast-leader-handover switch path, the header's parent slot). A
   validator drops or dies on each of these, so a block that shows one was
   never completed. Components therefore start only at the first shred of a
   FEC set.

Then the batch is walked (`count`, then per entry `num_hashes`, `hash`,
`tx_count`, transactions) to the claimed position. The transaction parser
handles legacy, v0 and v1 encodings and has one job: consume exactly the bytes
a validator would for every valid transaction.

Replay parses transactions with `agave-transaction-view`
(`entry/src/block_component_parser.rs`), which is stricter than this parser:
in Agave 4.4 at most 12 signatures, single-byte key and lookup-table counts,
compact integers of at most two bytes. Everything it accepts, this parser
reads to the same length, and two fuzz targets hold it to that. What this
parser accepts beyond that can only occur in bytes a validator never
executed, which is what the two rules above exist to exclude.

Agave 4.5 keeps the wire format and moves the limits: its parser lets
through up to 127 signatures, and the caps on a v1 transaction are checked
by replay around the parser instead of inside it. Two more fuzz targets hold
this parser to that version, including transactions over replay's limits,
which a later release could raise without touching the format.

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
same exposure, where it surfaces as a duplicate block.

The same budget buys a second route. The last leaf of a block's tree names
its parent and its number of FEC sets, and nothing but its position tells it
from a FEC set root. A leader could look for a FEC set whose root collides,
in its first 20 bytes, with a made-up parent leaf, and offer a client an
ancestry step from its real block into one that never existed. Opening the
last shred on every step would close this route and leave the first open, so
it is not done. This crate cannot do better than the tree it verifies.

## What is out of scope in v0.1

- Proving execution success, logs, or account state. Not possible today.
- Blocks with an `UpdateParent` marker. Detected and refused.
- Fetching anything. The crate has no network code.
- Verifying a transaction's Ed25519 signatures. A block containing a badly
  signed transaction is invalid and would not be finalized.

## What Solana could add

Three small changes would remove the largest limits. As of November 2026:
SIMD-0676 (open) would put the next epoch's stake, keys and ranks in an
account under the bank hash, without a way to open one account against that
hash; two open Agave pull requests would serve footer certificates and block
markers over RPC; SIMD-0064's receipts are stagnant.

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

- Over 175,981 mainnet transactions the median proof was 21.6 KB, the 95th
  percentile 56.0 KB and the largest 65.7 KB, because a proof opens a whole
  entry batch. Is that batch size a cap leaders will keep? A proof could be
  much smaller if transactions were length-prefixed or batches were Merkle
  trees.
- How often will blocks switch parent once fast leader handover is active?
  It is active on no public cluster, and none of 805 blocks captured from
  mainnet, testnet and devnet did. That decides whether supporting those
  blocks is worth the extra rules.
- Is there any other place where the verifier reads a block differently from
  the rule it mirrors? The header-in-shred-0 rule was one such place. Each
  such difference is a way a careless verifier could accept bytes that were
  never executed.
