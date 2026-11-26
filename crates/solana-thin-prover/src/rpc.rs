//! What the prover asks an RPC node: who the validators are, and which slot
//! a transaction landed in.
//!
//! Neither answer is trusted. The node list decides whom to ask, and what
//! they send is checked. The slot is a hint, and a wrong one costs a fetch.

use crate::serve::SlotHints;
use serde_json::{json, Value};
use solana_thin_setlog::rpc::{host_label, Curl, Rpc};
use std::time::Duration;

/// Says what is asking and nothing about who runs it.
const USER_AGENT: &str = "solana-thin-prover";

/// An RPC endpoint.
#[derive(Debug, Clone)]
pub struct Node {
    url: String,
}

/// The cluster's epoch schedule, as a node reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportedSchedule {
    /// Slots in a full-length epoch.
    pub slots_per_epoch: u64,
    /// The first full-length epoch.
    pub first_normal_epoch: u64,
    /// Its first slot.
    pub first_normal_slot: u64,
}

impl Node {
    /// The endpoint at `url`, which must be `http://` or `https://`.
    pub fn new(url: &str) -> Result<Self, String> {
        host_label(url)?;
        Ok(Self {
            url: url.to_string(),
        })
    }

    /// The endpoint's host, for messages. Never the path or query, which
    /// are where API keys go.
    pub fn label(&self) -> String {
        host_label(&self.url).unwrap_or_default()
    }

    fn with<T>(&self, ask: impl FnOnce(&Rpc<'_>, &str) -> Result<T, String>) -> Result<T, String> {
        let curl = Curl::new(USER_AGENT);
        let rpc = Rpc {
            transport: &curl,
            pause: Duration::ZERO,
            backoff: Duration::from_secs(1),
            attempts: 3,
        };
        ask(&rpc, &self.url)
    }

    /// The result of `getClusterNodes`.
    pub fn cluster_nodes(&self) -> Result<Value, String> {
        self.with(|rpc, url| rpc.call(url, "getClusterNodes", json!([])))
    }

    /// The result of `getEpochSchedule`.
    pub fn epoch_schedule(&self) -> Result<ReportedSchedule, String> {
        self.with(epoch_schedule)
    }
}

impl SlotHints for Node {
    fn slot_of(&self, signature: &[u8; 64]) -> Result<Option<u64>, String> {
        self.with(|rpc, url| slot_of(rpc, url, signature))
    }
}

fn epoch_schedule(rpc: &Rpc<'_>, url: &str) -> Result<ReportedSchedule, String> {
    let answer = rpc.call(url, "getEpochSchedule", json!([]))?;
    let field = |name: &str| {
        answer[name]
            .as_u64()
            .ok_or_else(|| format!("getEpochSchedule: no {name}"))
    };
    Ok(ReportedSchedule {
        slots_per_epoch: field("slotsPerEpoch")?,
        first_normal_epoch: field("firstNormalEpoch")?,
        first_normal_slot: field("firstNormalSlot")?,
    })
}

/// The slot the node says `signature` landed in, or `None` if it does not
/// know the transaction.
///
/// `getSignatureStatuses` with history, not `getTransaction`: the slot is
/// all that is wanted, and it comes without the transaction around it.
fn slot_of(rpc: &Rpc<'_>, url: &str, signature: &[u8; 64]) -> Result<Option<u64>, String> {
    let text = bs58::encode(signature).into_string();
    let answer = rpc.call(
        url,
        "getSignatureStatuses",
        json!([[text], {"searchTransactionHistory": true}]),
    )?;
    let status = &answer["value"][0];
    if status.is_null() {
        return Ok(None);
    }
    status["slot"]
        .as_u64()
        .map(Some)
        .ok_or_else(|| "getSignatureStatuses: a status without a slot".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_thin_setlog::rpc::testing::Scripted;

    fn answer(result: Value) -> String {
        json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
    }

    #[test]
    fn a_slot_hint_is_read_from_the_signature_status() {
        let known = answer(json!({"context": {"slot": 9}, "value": [
            {"slot": 473_905_900u64, "confirmations": null, "err": null,
             "confirmationStatus": "finalized"}]}));
        let transport = Scripted::new(&[(200, &known)]);
        assert_eq!(
            slot_of(&transport.rpc(), "http://node", &[7; 64]),
            Ok(Some(473_905_900))
        );
        let asked = transport.asked.borrow();
        assert_eq!(asked[0].1["method"], "getSignatureStatuses");
        assert_eq!(
            asked[0].1["params"],
            json!([[bs58::encode([7u8; 64]).into_string()], {"searchTransactionHistory": true}])
        );
    }

    #[test]
    fn an_unknown_signature_is_no_hint_and_a_broken_answer_is_an_error() {
        let unknown = answer(json!({"context": {"slot": 9}, "value": [null]}));
        let transport = Scripted::new(&[(200, &unknown)]);
        assert_eq!(slot_of(&transport.rpc(), "u", &[7; 64]), Ok(None));

        let odd = answer(json!({"context": {"slot": 9}, "value": [{"err": null}]}));
        let transport = Scripted::new(&[(200, &odd)]);
        assert!(slot_of(&transport.rpc(), "u", &[7; 64]).is_err());

        let transport = Scripted::new(&[]);
        assert!(slot_of(&transport.rpc(), "u", &[7; 64]).is_err());
    }

    #[test]
    fn the_epoch_schedule_is_read_whole_or_not_at_all() {
        let schedule = answer(json!({"firstNormalEpoch": 14, "firstNormalSlot": 524_256,
            "slotsPerEpoch": 432_000, "leaderScheduleSlotOffset": 432_000, "warmup": true}));
        let transport = Scripted::new(&[(200, &schedule)]);
        assert_eq!(
            epoch_schedule(&transport.rpc(), "u"),
            Ok(ReportedSchedule {
                slots_per_epoch: 432_000,
                first_normal_epoch: 14,
                first_normal_slot: 524_256,
            })
        );
        let partial = answer(json!({"slotsPerEpoch": 432_000}));
        let transport = Scripted::new(&[(200, &partial)]);
        assert!(epoch_schedule(&transport.rpc(), "u").is_err());
    }

    #[test]
    fn only_http_urls_are_endpoints_and_a_label_never_shows_a_key() {
        assert!(Node::new("ftp://example.com").is_err());
        let node = Node::new("https://rpc.example.com/v1/SECRET").unwrap();
        assert_eq!(node.label(), "rpc.example.com");
    }
}
