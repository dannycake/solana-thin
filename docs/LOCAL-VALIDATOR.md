# Testing against a running validator

The conformance vectors compare this crate with Agave's libraries. This
procedure compares it with a validator that is actually running: blocks it
produced, certificates it signed, transactions it accepted over RPC.

## What was run (2026-11-23)

Agave v4.4.1 release binaries, `solana-test-validator --alpenglow`, on Linux
x86-64. One validator, shred version 56225, 400 ms slots.

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

## What this does not show

- **More than one signer.** A test validator holds all the stake, so every
  certificate has one signature and the 80% and 60% thresholds are met
  trivially. Aggregation over many keys and the thresholds are covered by the
  Agave vectors (13 certificates), not by this run.
- **Slow finalization.** With one validator every block finalizes fast. No
  slow certificate was produced.
- **An epoch boundary.** The test validator's epoch is 432,000 slots, so the
  rule for which epoch's stake applies was not exercised.
- **A leader switching parent** (`UpdateParent`), and skipped slots.
- **Mainnet.** See the README.

## Reproducing it

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
