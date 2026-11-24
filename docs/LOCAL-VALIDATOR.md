# Testing against running validators

The conformance vectors compare this crate with Agave's libraries. These two
procedures compare it with validators that are actually running: blocks they
produced, certificates they signed, transactions they accepted over RPC.

Both were run on 2026-11-23 with Agave v4.4.1 on Linux x86-64.

## One validator

Release binaries, `solana-test-validator --alpenglow`. Shred version 56225,
400 ms slots.

| Check | Result |
|---|---|
| Block id recomputed from data shreds equals the id in the validator's blockstore | 447 of 447 blocks |
| Finality certificates taken from block footers verify against the set built from `getVoteAccounts` | 446 of 446 (all fast) |
| The same certificate checked with another shred version | rejected, `SignatureMismatch` |
| Memo transactions sent one at a time with the `solana` CLI: proven, encoded, decoded, verified | 12 of 12, 1,992 bytes each |
| The same, proven from a certificate three blocks later | 3 of 3, 2,287 bytes (about 100 bytes per hop) |
| 300 transfers with 300-byte memos sent in a burst: proven and verified | 300 of 300, 2.7 to 31.5 KB |

An empty block is 96 data shreds (three FEC sets). The footer of block `N + 1`
or `N + 2` carried the certificate for block `N` in every case.

One bug was found this way: the CLI writes `--with-memo` to Memo version 4
(`Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH`), which
`Transaction::memos` did not recognise. Fixed, with a test.

A test validator holds all the stake, so every certificate has one signature,
every block finalizes fast, and its 432,000-slot epoch never turns over. The
next run covers those.

## Four validators

`cluster-run` (in `tools/agave-fixtures`) starts Agave's own `LocalCluster`:
four full validators in one process, voting over loopback, with 40, 30, 20
and 10% of stake and 64-slot epochs. After three epochs it stops the 30%
validator. The remaining 70% is enough to finalize but not fast, and the
stopped validator's leader slots are skipped. It saves `getVoteAccounts` once
per epoch, because stake moves at every boundary: validators that vote earn
rewards and the stopped one does not.

| Check | Result |
|---|---|
| Block ids equal the validator's | 709 of 709 |
| Footer certificates verify, each against the set fetched one epoch before its slot | 705 of 705: 330 fast, 375 slow, over 14 epochs and 10 distinct sets |
| The same with the set fetched in the certificate's own epoch | 19 rejected |
| The same with the set fetched two epochs before | 19 rejected |
| Transactions proven and verified | 7 of 7: 4 under fast certificates, 3 under slow |
| The same from a certificate four certified blocks later | 7 of 7, up to 5 hops |
| Blocks whose parent is not the previous slot | 28, all indexed and chained through |

The rejected certificates in the two wrong-offset rows fail on stake, not on
the signature. With the same-epoch set, fast certificates signed by the 40, 30
and 10% validators come to 79.99%. With the set from two epochs before, slow
certificates signed by the 40 and 20% validators come to 59.98%. By the right
epoch's numbers both clear their threshold. That is the rule in
`docs/DESIGN.md` for which epoch's stake applies, observed rather than read.

```sh
cd tools/agave-fixtures
cargo run --release --bin cluster-run -- ../../cluster        # about 6 minutes
cargo run --release --bin ledger-dump -- ../../cluster/ledger 1 100000 ../../cluster/dump.jsonl
cd ../..
ALL=1 SLOTS_PER_EPOCH=64 cargo run --release --example verify_ledger -- \
  cluster/dump.jsonl cluster <shred version from cluster/cluster.json>
```

Given a directory, `verify_ledger` pins the set from
`vote-accounts-epoch-<E>.json` for epoch `E + 1`. `SET_OFFSET=0` or `2` shows
the other two rows.

## Attack blocks, injected into running validators

`cluster-inject` (in `tools/agave-fixtures`) runs the same four-validator
cluster, stops the 10% validator, and sends hand-built blocks for its leader
slots, signed with its key, to the other three over their shred ports. Each
block is built on the cluster's current head and its footer's bank hash is
settled against that live state first. Run on 2026-11-24, twice.

| Block | What the validators did | What the verifier says |
|---|---|---|
| Honest | Rooted, with the block id the crate computes. Its transfer executed. | A proof under the real certificate from a later footer verifies (1,742 bytes). |
| Header split over two shreds, then an UpdateParent naming the header's own parent | Rooted. Replay started at the marker: the transfer after it executed, the one before it did not. | Refuses the block: no header where a validator looks. |
| UpdateParent to an older ancestor | Shreds inserted, slot never completed, marked dead, in four attempts. Not root-caused; the single-process oracle votes for the same shape, where the root never advances. | Refuses the block. |
| Zero parent id | Not constructible: the parent would have to be slot 0, and injection starts after the cluster is up. | Refuses the block. |

The second row is the split-header attack on validators that voted for it:
a finalized block with a transaction in it that never ran, and header and
block id in agreement. Before the fix the verifier accepted that
transaction. An injected block that arrives a moment late is inserted and
replayable and still not finalized, because the slot was already skipped; the
tool retries at the next leader window.

```sh
cd tools/agave-fixtures
cargo run --release --bin cluster-inject -- ../../inject     # about 10 minutes
```

A block built directly on the cluster's first block has a parent id of all
zeros, and nothing in it can be proven (see `docs/DESIGN.md`). On a test
validator that is the first block or two. Send transactions after that.

## What neither run shows

- **A leader switching parent** (`UpdateParent`). Fast leader handover was
  not exercised.
- **Validator admission.** Every validator here could pay its admission
  ticket, so the filter in `docs/DESIGN.md` removed nobody.
- **Many validators.** Four signers, not hundreds.
- **Mainnet.** See the README.

## Reproducing the one-validator run

Needs the Agave v4.4.1 release (`solana-release-x86_64-unknown-linux-gnu.tar.bz2`
from the Agave releases page) on `PATH`, and the fixture tool built as
described in `tools/agave-fixtures/README.md`.

```sh
# 1. A validator with Alpenglow active from genesis.
solana-test-validator --alpenglow --reset --quiet --ledger test-ledger &

# 2. Some transactions. Keep the signatures.
solana-keygen new --no-bip39-passphrase -s -o payer.json
U="-u http://127.0.0.1:8899 -k payer.json"
solana $U airdrop 100
for i in 1 2 3; do
  solana $U transfer --allow-unfunded-recipient --with-memo "anchor-$i" \
    "$(solana-keygen pubkey payer.json)" 0.0001
done                                   # prints "Signature: ..."

# 3. The validator set and the shred version.
python3 tools/fetch_vote_accounts.py http://127.0.0.1:8899 vote-accounts.json
curl -s http://127.0.0.1:8899 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getClusterNodes"}'   # "shredVersion"

# 4. The shreds, read from the ledger while the validator runs.
(cd tools/agave-fixtures && cargo run --release --bin ledger-dump -- \
  ../../test-ledger 1 400 ../../dump.jsonl)

# 5. Prove and verify.
cargo run --release --example verify_ledger -- \
  dump.jsonl vote-accounts.json <shred version> <signature> ...
```

`HOPS=3` before the last command proves each transaction from a certificate
three certified blocks later, which exercises the ancestry chain.

The example exits non-zero if any block id differs, any certificate is
rejected, or any transaction fails to prove or verify.
