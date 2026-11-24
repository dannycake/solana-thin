//! Agave's verdicts, frozen, and the verifier held to them with no Agave in
//! the build.
//!
//! `tests/vectors/oracle/*.json` is written by `tools/agave-fixtures`
//! (`diff-fuzz --emit`), which links the real validator. Each file is one
//! block: its data shreds, and what Agave v4.4.1 did with them — the parent
//! and block id its blockstore computed, whether replay succeeded so that a
//! validator would vote, and the transactions it executed, by coordinates
//! and bytes.
//!
//! This test plays the dishonest prover those files allow. For every block
//! Agave voted for it signs a certificate over Agave's block id, then offers
//! the verifier every claim that can be built from the shreds: every shred
//! as a component start, every transaction the verifier's own walk reaches
//! from it, every footer-shaped component as the footer. The rule:
//!
//! > a claim the verifier accepts names a transaction Agave executed, at the
//! > coordinates Agave executed it, with the same bytes, in Agave's block,
//! > on Agave's parent, and a footer it reports is the one Agave processed.
//!
//! The verifier may refuse anything; refusing more than a validator is
//! always allowed. The files also carry a few encoded proofs as the oracle
//! built them, which pin the wire format; they are held to the same rule.
//!
//! # File format
//!
//! * `shreds`: the data shreds in index order, each a hex string: variant (1
//!   byte), parent offset (u16 LE), flags (1), size (u16 LE), then the body
//!   with trailing zeros removed. A run of equal shreds (the empty padding
//!   that fills out a FEC set) is written once, as `[hex, count]`.
//!   `testkit::BlockBuilder::push_shreds`
//!   rebuilds the exact payloads Agave judged (minus the leader's
//!   signature, which no check here reads) when started on
//!   `builder_parent`. `null` when the payloads cannot be rebuilt that way,
//!   or when Agave's blockstore kept only some of them.
//! * `parent`, `block_id`: from Agave's `SlotMeta` and double Merkle root.
//! * `voted`, `executed`, `footer`: replay's result.
//! * `claims`: what the oracle run offered, with `observed` (what the
//!   verifier did at the time) and `required` (`must-reject` unless Agave
//!   executed a transaction at those coordinates). `proof` is present for a
//!   few of them.
//! * `validators`: the test validators are `TestValidators::new(count,
//!   |_| stake)`; `validator_set` is that set's encoding, checked here.

use serde_json::Value;
use solana_thin::block::{self, Marker};
use solana_thin::shred::DataShred;
use solana_thin::testkit::{BlockBuilder, RawBlock, TestValidators};
use solana_thin::transaction::Transaction;
use solana_thin::*;
use std::collections::BTreeSet;
use std::path::Path;

/// Cases in which the verifier is known to accept a claim Agave did not
/// execute. They are frozen as found so the hole stays visible; the test
/// fails if one is missing from this list, and also if one listed here has
/// stopped failing, so the entry is removed with the fix.
///
/// Both are finding C2: Agave's `ParentInfo::from_slot_meta` treats a header
/// whose parent id is all zeros as no header, so a block on genesis can
/// carry an UpdateParent naming the same `(0, zeros)` parent. Agave replays
/// from the marker and never executes what is in front of it. The verifier
/// sees a header equal to the tree's parent, concludes no switch happened,
/// and accepts transactions (and a footer) from the abandoned prefix.
const KNOWN_OPEN: &[&str] = &[
    "known/c2-zero-parent-update-parent",
    "known/c2-zero-parent-decoy-footer",
];

struct Executed {
    component_start: u32,
    entry: u32,
    transaction: u32,
    wire: Vec<u8>,
}

struct Footer {
    component_start: u32,
    bank_hash: Hash,
    producer_time_nanos: u64,
}

struct Vector {
    name: String,
    shred_version: u16,
    slots_per_epoch: u64,
    slot: u64,
    builder_parent: BlockRef,
    shreds: Option<Vec<DataShred>>,
    parent: Option<BlockRef>,
    block_id: Option<Hash>,
    voted: bool,
    executed: Vec<Executed>,
    footer: Option<Footer>,
    validators: TestValidators,
    stored_claims: Vec<(String, String, Vec<u8>)>,
}

fn hash(value: &Value) -> Hash {
    hex::decode(value.as_str().expect("hex string"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

fn block_ref(value: &Value) -> BlockRef {
    BlockRef {
        slot: value["slot"].as_u64().expect("slot"),
        id: hash(&value["id"]),
    }
}

fn int(value: &Value) -> u32 {
    u32::try_from(value.as_u64().expect("integer")).expect("fits u32")
}

fn load(path: &Path) -> Vector {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let validators = TestValidators::new(
        doc["validators"]["count"].as_u64().unwrap() as usize,
        |_| doc["validators"]["stake"].as_u64().unwrap(),
    );
    assert_eq!(
        hex::encode(validators.set().to_bytes()),
        doc["validator_set"].as_str().unwrap(),
        "{}: the test validators are not the ones the file was signed for",
        path.display()
    );
    let shreds = doc["shreds"].as_array().map(|runs| {
        let mut shreds = Vec::new();
        for run in runs {
            // A string is one shred; `[string, count]` is that shred `count`
            // times over.
            let (text, count) = match run.as_array() {
                Some(pair) => (pair[0].as_str().unwrap(), pair[1].as_u64().unwrap()),
                None => (run.as_str().unwrap(), 1),
            };
            let bytes = hex::decode(text).unwrap();
            let shred = DataShred {
                variant: bytes[0],
                parent_offset: u16::from_le_bytes([bytes[1], bytes[2]]),
                flags: bytes[3],
                size: u16::from_le_bytes([bytes[4], bytes[5]]),
                body: bytes[6..].to_vec(),
            };
            shreds.extend((0..count).map(|_| shred.clone()));
        }
        shreds
    });
    Vector {
        name: doc["name"].as_str().unwrap().to_string(),
        shred_version: doc["shred_version"].as_u64().unwrap() as u16,
        slots_per_epoch: doc["slots_per_epoch"].as_u64().unwrap(),
        slot: doc["slot"].as_u64().unwrap(),
        builder_parent: block_ref(&doc["builder_parent"]),
        shreds,
        parent: (!doc["parent"].is_null()).then(|| block_ref(&doc["parent"])),
        block_id: (!doc["block_id"].is_null()).then(|| hash(&doc["block_id"])),
        voted: doc["voted"].as_bool().unwrap(),
        executed: doc["executed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tx| Executed {
                component_start: int(&tx["component_start"]),
                entry: int(&tx["entry"]),
                transaction: int(&tx["transaction"]),
                wire: hex::decode(tx["wire"].as_str().unwrap()).unwrap(),
            })
            .collect(),
        footer: (!doc["footer"].is_null()).then(|| Footer {
            component_start: int(&doc["footer"]["component_start"]),
            bank_hash: hash(&doc["footer"]["bank_hash"]),
            producer_time_nanos: doc["footer"]["producer_time_nanos"].as_u64().unwrap(),
        }),
        validators,
        stored_claims: doc["claims"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|claim| !claim["proof"].is_null())
            .map(|claim| {
                (
                    claim["observed"].as_str().unwrap().to_string(),
                    claim["required"].as_str().unwrap().to_string(),
                    hex::decode(claim["proof"].as_str().unwrap()).unwrap(),
                )
            })
            .collect(),
    }
}

fn vectors() -> Vec<Vector> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/oracle");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    paths.iter().map(|path| load(path)).collect()
}

impl Vector {
    fn client(&self) -> ThinClient {
        let params = ClusterParams {
            shred_version: self.shred_version,
            slots_per_epoch: self.slots_per_epoch,
            first_normal_slot: 0,
            first_normal_epoch: 0,
        };
        let mut client = ThinClient::new(params);
        let set = self.validators.set();
        let pinned = set.hash();
        client
            .trust_validator_set(params.epoch_of(self.slot).unwrap(), set, &pinned)
            .unwrap();
        client
    }

    /// The block as Agave judged it, rebuilt from the frozen shreds.
    fn raw(&self) -> Option<RawBlock> {
        let shreds = self.shreds.clone()?;
        let payloads = BlockBuilder::new(self.slot, self.builder_parent, self.shred_version)
            .push_shreds(shreds)
            .build();
        Some(RawBlock::from_shreds(&payloads).expect("frozen shreds form whole FEC sets"))
    }

    /// Holds one accepted claim to what Agave executed. Returns what is
    /// wrong with it, if anything.
    fn judge(&self, verified: &VerifiedTransaction) -> Option<String> {
        let (block_id, parent) = (self.block_id?, self.parent?);
        let at = format!(
            "(component_start {}, entry {}, transaction {})",
            verified.component_start, verified.position.entry, verified.position.transaction
        );
        let executed = self.executed.iter().find(|tx| {
            tx.component_start == verified.component_start
                && tx.entry == verified.position.entry
                && tx.transaction == verified.position.transaction
        });
        let Some(executed) = executed else {
            return Some(format!(
                "accepted a transaction at {at}; Agave executed nothing there"
            ));
        };
        if Transaction::parse(&executed.wire).ok().as_ref() != Some(&verified.transaction) {
            return Some(format!(
                "accepted a transaction at {at} that differs from the one Agave executed there"
            ));
        }
        if verified.block.id != block_id || verified.block.slot != self.slot {
            return Some(format!("accepted {at} in a block that is not Agave's"));
        }
        if verified.parent != parent {
            return Some(format!("accepted {at} on a parent that is not Agave's"));
        }
        if let Some(ours) = &verified.footer {
            let same = self.footer.as_ref().is_some_and(|agave| {
                ours.bank_hash == agave.bank_hash
                    && ours.producer_time_nanos == agave.producer_time_nanos
            });
            if !same {
                return Some(format!(
                    "accepted {at} with a footer (bank hash {}) Agave did not process",
                    hex::encode(ours.bank_hash)
                ));
            }
        }
        None
    }

    /// Every way this block breaks the rule.
    fn violations(&self) -> Vec<String> {
        let mut violations = Vec::new();
        let raw = self.raw();

        // Identity: under Agave's parent, the light client computes Agave's
        // block id.
        if let (Some(raw), Some(parent), Some(block_id)) = (&raw, &self.parent, &self.block_id) {
            if raw.block(parent).id != *block_id {
                violations.push("block id differs from Agave's".to_string());
                return violations;
            }
        }
        if !self.voted {
            // No validator signs for this block, so no certificate exists
            // and nothing can be claimed.
            return violations;
        }
        let (block_id, parent) = (self.block_id.unwrap(), self.parent.unwrap());
        let block = BlockRef {
            slot: self.slot,
            id: block_id,
        };
        let client = self.client();
        let certificate = self.validators.fast_cert(
            block,
            &self.validators.ranks_reaching(8_000),
            self.shred_version,
        );

        // The proofs the oracle run built.
        for (observed, required, proof) in &self.stored_claims {
            match client.verify_transaction_bytes(proof) {
                Ok(verified) => {
                    if required == "must-reject" {
                        violations.push(format!(
                            "a frozen proof that must be rejected is accepted (observed at \
                             freeze: {observed})"
                        ));
                    } else if let Some(wrong) = self.judge(&verified) {
                        violations.push(wrong);
                    }
                }
                Err(error) => {
                    if observed == "accept" {
                        println!(
                            "  note: {}: a frozen proof accepted at freeze is now refused: \
                             {error:?}",
                            self.name
                        );
                    }
                }
            }
        }

        // Every claim that can be built from the shreds, each offered twice:
        // opening the fewest shreds that show it, and opening every shred.
        // The verifier reads more of the block the more it is given, so the
        // second is the one a dishonest prover would send.
        let Some(raw) = raw else {
            return violations;
        };
        let everything: BTreeSet<u32> = (0..raw.shred_count()).collect();
        let mut accepted: Option<(u32, TxPosition, BTreeSet<u32>)> = None;
        for start in 0..raw.shred_count() {
            let (bytes, last) = raw.component(start);
            let reached = block::reachable(&bytes);
            if reached.is_empty() {
                continue;
            }
            let lens: Vec<usize> = (start..=last).map(|i| raw.shred_data(i).len()).collect();
            for (position, _, end) in reached {
                let mut seen = 0;
                let mut holder = last;
                for (i, len) in lens.iter().enumerate() {
                    seen += len;
                    if seen >= end {
                        holder = start + i as u32;
                        break;
                    }
                }
                let mut needed = BTreeSet::from([0]);
                if start > 0 {
                    needed.insert(start - 1);
                }
                needed.extend(start..=holder);
                for opened in [&needed, &everything] {
                    let proof = TxProof {
                        finality: certificate.clone(),
                        ancestry: vec![],
                        block: raw.open(&parent, opened),
                        component_start: start,
                        position,
                        footer_start: None,
                    };
                    if let Ok(verified) = client.verify_transaction_bytes(&proof.to_bytes()) {
                        violations.extend(self.judge(&verified));
                        accepted.get_or_insert((start, position, needed.clone()));
                    }
                }
            }
        }

        // Every footer-shaped component, offered as the footer of one
        // accepted claim.
        if let Some((component_start, position, base)) = accepted {
            for start in raw.component_starts() {
                let (bytes, last) = raw.component(start);
                let Ok(Marker::Footer(_)) = block::parse_marker(&bytes) else {
                    continue;
                };
                let mut needed = base.clone();
                if start > 0 {
                    needed.insert(start - 1);
                }
                needed.extend(start..=last);
                for opened in [&needed, &everything] {
                    let proof = TxProof {
                        finality: certificate.clone(),
                        ancestry: vec![],
                        block: raw.open(&parent, opened),
                        component_start,
                        position,
                        footer_start: Some(start),
                    };
                    if let Ok(verified) = client.verify_transaction_bytes(&proof.to_bytes()) {
                        let agave = self
                            .footer
                            .as_ref()
                            .is_some_and(|f| f.component_start == start);
                        if !agave {
                            violations.push(format!(
                                "accepted the component at shred {start} as the footer; \
                                 Agave's footer is at {:?}",
                                self.footer.as_ref().map(|f| f.component_start)
                            ));
                        }
                        violations.extend(self.judge(&verified));
                    }
                }
            }
        }
        violations
    }
}

#[test]
fn accepted_claims_are_what_agave_executed() {
    let vectors = vectors();
    assert!(
        vectors.len() >= 20,
        "the oracle corpus is missing: {} files",
        vectors.len()
    );
    for name in KNOWN_OPEN {
        assert!(
            vectors.iter().any(|v| v.name == *name),
            "KNOWN_OPEN names {name}, which is not in the corpus"
        );
    }
    let mut voted = 0;
    let mut failures = Vec::new();
    for vector in &vectors {
        voted += usize::from(vector.voted);
        // The same claim can be reached more than once (a frozen proof and
        // its rebuilt twin, a claim with and without a footer).
        let mut violations = vector.violations();
        violations.sort();
        violations.dedup();
        let known = KNOWN_OPEN.contains(&vector.name.as_str());
        match (known, violations.is_empty()) {
            (false, true) => {}
            (false, false) => failures.push(format!("{}: {violations:#?}", vector.name)),
            (true, false) => {
                println!(
                    "KNOWN OPEN SOUNDNESS HOLE, {}: {} claim(s) accepted against Agave:",
                    vector.name,
                    violations.len()
                );
                for violation in &violations {
                    println!("    {violation}");
                }
            }
            (true, true) => failures.push(format!(
                "{} no longer fails: remove it from KNOWN_OPEN",
                vector.name
            )),
        }
    }
    // The rule says nothing about a block nobody votes for. A corpus of
    // those would pass without testing anything.
    assert!(voted >= 10, "only {voted} frozen blocks have Agave's vote");
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn block_ids_are_agaves() {
    let mut checked = 0;
    for vector in vectors() {
        let (Some(raw), Some(parent), Some(block_id)) =
            (vector.raw(), vector.parent, vector.block_id)
        else {
            continue;
        };
        assert_eq!(
            hex::encode(raw.block(&parent).id),
            hex::encode(block_id),
            "{}",
            vector.name
        );
        // The id commits to the parent: under any other parent it differs.
        let other = BlockRef {
            slot: parent.slot,
            id: [0xee; 32],
        };
        assert_ne!(raw.block(&other).id, block_id, "{}", vector.name);
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} frozen blocks have an id");
}
