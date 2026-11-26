# shred-fixtures

Runs the shred-parse conformance fixtures that Firedancer publishes
(`firedancer-io/test-vectors`, asset `shred.tar.gz`) through solana-thin, and
compares the two things that are comparable: whether each shred parses, and
the Merkle root of each completed FEC set.

The fixtures were produced by a differential fuzzer and carry the verdicts of
Agave's own harness, so this checks the shred parser and the FEC root
computation against vectors that nobody on this project wrote.

```
cargo run --release -- --tag 54829b38
```

Options: `--cache DIR`, `--expected FILE`, `--offline` (never use the network),
`--list` (print every per-shred disagreement instead of one example a class).
It needs `curl` on the path; everything else is in the binary.

## The fixtures are downloaded, never committed

The test-vectors repository declares no license, so nothing from it may be
copied into this one. On first use the tool:

1. downloads `SHA256SUMS` and `shred.tar.gz` of the release with plain
   anonymous GETs (the only things sent are the URL and the client name
   `shred-fixtures`);
2. checks the archive's SHA-256 against `SHA256SUMS`, and, for a release
   listed in `PINNED` in `src/fetch.rs`, against the digest recorded there.
   `SHA256SUMS` comes from the same place as the archive, so alone it only
   shows the download is intact; the pin shows the release was not replaced.
   A mismatch stops the run before the archive is opened;
3. extracts into a fresh directory, writing only regular `*.fix` members under
   their bare file name. Paths stored in the archive are ignored, and a link,
   a device or an oddly named member fails the extraction.

The cache is `$XDG_CACHE_HOME/solana-thin/shred-fixtures/<tag>/` (or
`~/.cache/...`), outside the repository. A later run finds the extracted
directory and uses no network. The extracted files are then trusted as they
are: delete the directory to verify from scratch. The fixtures are only ever
read as bytes and decoded as protobuf.

To use a newer release, pass its tag. Until its digest is added to `PINNED`
the summary says the archive matched `SHA256SUMS` only.

## The schema

`org.solana.sealevel.v1.ShredParseFixture`, from the `protosol` crate (18.0.0,
Apache-2.0) on crates.io. The crate ships prost types generated ahead of time
(`protosol::protos`), so there is no `build.rs`, no `protoc` and no vendored
`.proto` here.

## What is compared

What the reference's outputs mean is read from Agave's harness,
`conformance/src/shred.rs` (`execute_shred_parse`).

1. **Per shred.** `shred_results[i]` is
   `Shred::new_from_serialized_shred(..)` succeeding and having a chained
   Merkle root: a parse plus `sanitize`, for data and coding shreds, any proof
   size, no signature check. It is not the fetch-stage filter. This is compared
   with `RawDataShred::parse`.

   The light client is meant to be stricter in two ways, and the summary
   reports those as their own classes rather than as failures: it reads data
   shreds only, and only variants `0x96` and `0xb6`, whose proof size of 6 is
   what a 32:32 FEC set has. Agave's own filter drops any other proof size once
   SIMD-317 enforcement is on (`ledger/src/shred/filter.rs`,
   `has_correct_proof_size`).

   The other direction, the light client accepting what the reference rejects,
   fails the run. `src/reference.rs` restates the reference's rules so that
   such a case is named by the rule involved; the summary also counts every
   shred where that restatement and the fixture differ, which should be zero.

2. **Per completed FEC set.** For each `fec_set_results` entry, the data shreds
   of the input in that slot and FEC set are collected and `fec_set_root()` of
   each is compared with `merkle_root`. The fuzzer replays and equivocates, so
   an index may hold several shreds; the root differs only if some index holds
   shreds and none of them gives the reference root. `chained_merkle_root`,
   `parent_offset`, `shred_version` and `payload_hash` (XXH64 of the 32 data
   regions) are compared too. A set with no data shred in the input, which the
   reference recovered from coding shreds, is reported as not comparable.

3. **Per slot, informational.** The data shreds of each slot go to
   `BlockData::from_shreds`, and the summary gives how many index and why the
   rest are refused. A refusal is not a failure: the reference has nothing to
   compare it with.

**Not compared:** `block_parse_result`. It follows a pre-Alpenglow
configuration (tick verification, transaction sanitizing) that this verifier
does not implement. Signatures are not compared either: the fuzzer re-proofs
FEC sets but does not sign them.

## Exit status

`0` when nothing fails, `1` when the light client accepts a shred the
reference rejects or a completed FEC set's root differs, `2` when the run
could not be carried out (download, checksum, arguments).

`expected-differences.toml` lists differences of the first two kinds that are
intended, one entry each with a reason. It is empty: release `54829b38` needs
none.

## Result for release 54829b38

1,008 fixtures, 146,337 shreds. Every shred verdict agrees (146,333 accepted
by both, 4 rejected by both), and all 4,557 completed FEC sets give the
reference's Merkle root, chained root, parent offset, shred version and
payload hash. 1,000 of the 1,008 slots index as blocks; the other 8 are
missing shreds.

What that does and does not show:

- Every accepted shred is variant `0x96`. Resigned shreds (`0xb6`) do not
  occur, and neither do coding shreds, so the two "stricter" classes above
  were never exercised and no FEC set needed recovery.
- Only two reference rules reject anything in this release: a data index of
  32,768 or more (once, on a `0xb2` shred the light client refuses for its
  variant before looking further) and a `size` beyond the body (three times).
- `RawDataShred::parse` does not make four checks that Agave's
  `shred_data::sanitize` does (`ledger/src/shred/shred_data.rs`,
  `shred/traits.rs`): index below 32,768, `LAST_SHRED_IN_SLOT` only together
  with `DATA_COMPLETE`, a parent offset that is non-zero and no larger than
  the slot, and index not below the FEC set index. No fixture separates the
  two parsers on these, so they pass here unseen. If a later release adds
  such a case it will show up as a failing "accepts-rejected" row.
