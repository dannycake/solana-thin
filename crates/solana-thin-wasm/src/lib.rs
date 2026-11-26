//! The verifier as a bare WebAssembly module: no `wasm-bindgen`, no bundler,
//! and no imports, so that `WebAssembly.instantiate(bytes, {})` is all a host
//! needs. `solana-thin.mjs` beside this crate wraps what follows in a class.
//!
//! This is a check that the verifier builds and runs in a JavaScript engine,
//! and the smallest thing an app could start from. It is not a package.
//!
//! # The interface
//!
//! The host passes bytes by copying them into memory it got from
//! [`st_alloc`], and frees that memory with [`st_free`] when the call
//! returns. Every other function returns an answer: a pointer to a `u32`
//! length, little-endian, followed by that many bytes of JSON, which the
//! host reads and then frees with `st_free(pointer, 4 + length)`.
//!
//! An answer is `{"ok":true, ...}` or
//! `{"ok":false,"kind":...,"detail":...,"epoch":...}`, where `kind` is the
//! name of a [`solana_thin::ErrorKind`]. Numbers that may not fit a
//! JavaScript number are decimal strings, and bytes are hex.

use solana_thin::{ClusterParams, Error, ErrorKind, Finality, ThinClient, TxProof};
use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::fmt::Write;

/// A verifier, behind the handle [`st_verifier_new`] gives the host.
pub struct Verifier {
    client: ThinClient,
}

/// Why a call was refused: a kind for the host to branch on, the verifier's
/// sentence, and the epoch to pin where that is what is missing.
struct Refusal {
    kind: ErrorKind,
    detail: String,
    epoch: Option<u64>,
}

impl Refusal {
    /// An argument that is wrong before any checking begins.
    fn argument(detail: String) -> Self {
        Self {
            kind: ErrorKind::InvalidParameters,
            detail,
            epoch: None,
        }
    }
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        Self {
            kind: error.kind(),
            detail: error.to_string(),
            epoch: match error {
                Error::UnknownEpoch(epoch) => Some(epoch),
                _ => None,
            },
        }
    }
}

/// `text` as a JSON string.
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            c if u32::from(c) < 0x20 => write!(out, r"\u{:04x}", u32::from(c)).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}

/// A 64-bit number as JSON. JavaScript numbers are exact only up to 2^53,
/// and a block time in nanoseconds is past that.
fn decimal(number: u64) -> String {
    format!(r#""{number}""#)
}

/// The memory layout of `length` bytes from [`st_alloc`]. Never zero-sized:
/// the allocator does not hand those out.
fn layout(length: usize) -> Layout {
    Layout::array::<u8>(length.max(1)).expect("a length the host could allocate")
}

/// Hands the host an answer: the length of `json`, then `json`.
fn answer(result: Result<String, Refusal>) -> *mut u8 {
    let json = match result {
        Ok(fields) if fields.is_empty() => r#"{"ok":true}"#.to_owned(),
        Ok(fields) => format!(r#"{{"ok":true,{fields}}}"#),
        Err(refusal) => format!(
            r#"{{"ok":false,"kind":"{:?}","detail":{},"epoch":{}}}"#,
            refusal.kind,
            quoted(&refusal.detail),
            refusal.epoch.map_or("null".to_owned(), decimal),
        ),
    };
    let length = u32::try_from(json.len()).expect("an answer is far below 4 GiB");
    let pointer = st_alloc(4 + json.len());
    // SAFETY: `pointer` is a fresh allocation of `4 + json.len()` bytes.
    unsafe {
        pointer.copy_from_nonoverlapping(length.to_le_bytes().as_ptr(), 4);
        pointer
            .add(4)
            .copy_from_nonoverlapping(json.as_ptr(), json.len());
    }
    pointer
}

/// The host's bytes.
///
/// # Safety
/// `pointer` must be valid for reads of `length` bytes for as long as the
/// slice is used, unless `length` is zero.
unsafe fn bytes<'a>(pointer: *const u8, length: usize) -> &'a [u8] {
    if length == 0 {
        &[]
    } else {
        // SAFETY: the caller's contract.
        unsafe { std::slice::from_raw_parts(pointer, length) }
    }
}

/// Bytes from the host as the fixed-size array the verifier takes.
fn sized<const N: usize>(what: &str, bytes: &[u8]) -> Result<[u8; N], Refusal> {
    bytes
        .try_into()
        .map_err(|_| Refusal::argument(format!("the {what} is {} bytes, not {N}", bytes.len())))
}

/// Allocates `length` bytes for the host to copy an argument into.
#[no_mangle]
pub extern "C" fn st_alloc(length: usize) -> *mut u8 {
    let layout = layout(length);
    // SAFETY: the layout is not zero-sized.
    let pointer = unsafe { alloc(layout) };
    if pointer.is_null() {
        handle_alloc_error(layout);
    }
    pointer
}

/// Frees memory from [`st_alloc`], or an answer.
///
/// # Safety
/// `pointer` must come from [`st_alloc`] called with this `length`, or be an
/// answer whose JSON is `length - 4` bytes long, and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn st_free(pointer: *mut u8, length: usize) {
    // SAFETY: the caller's contract; both were allocated with this layout.
    unsafe { dealloc(pointer, layout(length)) }
}

/// Makes a verifier for a cluster: its shred version and its epoch schedule.
/// `warmup` is zero for a cluster whose epochs are `slots_per_epoch` long
/// from slot zero, as on mainnet, and non-zero for one that began with
/// warm-up epochs, as testnet and devnet did.
///
/// The answer's `verifier` is the handle to pass to the other functions.
#[no_mangle]
pub extern "C" fn st_verifier_new(
    shred_version: u32,
    slots_per_epoch: u64,
    warmup: u32,
) -> *mut u8 {
    let made = || {
        let shred_version = u16::try_from(shred_version).map_err(|_| {
            Refusal::argument(format!(
                "the shred version is {shred_version}, which does not fit 16 bits"
            ))
        })?;
        let params = if warmup == 0 {
            ClusterParams::without_warmup(shred_version, slots_per_epoch)?
        } else {
            ClusterParams::with_warmup(shred_version, slots_per_epoch)?
        };
        let verifier = Box::new(Verifier {
            client: ThinClient::new(params),
        });
        Ok(format!(
            r#""verifier":{}"#,
            Box::into_raw(verifier) as usize
        ))
    };
    answer(made())
}

/// Drops a verifier.
///
/// # Safety
/// `verifier` must be a handle from [`st_verifier_new`] that has not been
/// freed, and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn st_verifier_free(verifier: *mut Verifier) {
    // SAFETY: the caller's contract.
    drop(unsafe { Box::from_raw(verifier) });
}

/// Trusts the validator set in `set` for `epoch`, provided it hashes to the
/// 32 bytes at `hash`. The epoch is the host's word: nothing about it is
/// read from the set or from a proof.
///
/// # Safety
/// `verifier` must be a live handle from [`st_verifier_new`], and each
/// pointer must be valid for reads of its length.
#[no_mangle]
pub unsafe extern "C" fn st_pin(
    verifier: *mut Verifier,
    epoch: u64,
    set: *const u8,
    set_length: usize,
    hash: *const u8,
    hash_length: usize,
) -> *mut u8 {
    // SAFETY: the caller's contract.
    let (verifier, set, hash) = unsafe {
        (
            &mut *verifier,
            bytes(set, set_length),
            bytes(hash, hash_length),
        )
    };
    let mut pinned = || {
        let hash = sized::<32>("pinned hash", hash)?;
        verifier
            .client
            .trust_validator_set_bytes(epoch, set, &hash)?;
        Ok(String::new())
    };
    answer(pinned())
}

/// Checks a proof against the sets pinned so far. With a `signature` of 64
/// bytes, also checks that the proof is for the transaction with that id;
/// pass a length of zero to take whichever transaction the proof is for.
///
/// # Safety
/// `verifier` must be a live handle from [`st_verifier_new`], and each
/// pointer must be valid for reads of its length.
#[no_mangle]
pub unsafe extern "C" fn st_verify(
    verifier: *const Verifier,
    proof: *const u8,
    proof_length: usize,
    signature: *const u8,
    signature_length: usize,
) -> *mut u8 {
    // SAFETY: the caller's contract.
    let (client, proof, signature) = unsafe {
        (
            &(*verifier).client,
            bytes(proof, proof_length),
            bytes(signature, signature_length),
        )
    };
    let verified = || {
        let verified = if signature.is_empty() {
            client.verify_transaction_bytes(proof)?
        } else {
            let signature = sized::<64>("expected signature", signature)?;
            let proof = TxProof::from_bytes(proof, client.limits())?;
            client.verify_signature(&proof, &signature)?
        };
        let certified = verified.finalized_by;
        // Every transaction the verifier parses has a signature. If that
        // ever stopped being so, an empty id must not be the answer.
        let id = verified
            .transaction
            .signature()
            .ok_or(Error::UnsupportedTransaction)?;
        let memos: Vec<String> = verified
            .transaction
            .memos()
            .map(|memo| quoted(&hex(memo)))
            .collect();
        let finality = match certified.finality {
            Finality::Fast => "fast".to_owned(),
            Finality::Slow => "slow".to_owned(),
            // `Finality` may grow; a new way keeps the verifier's name for it.
            other => format!("{other:?}").to_lowercase(),
        };
        Ok(format!(
            concat!(
                r#""slot":{},"blockId":{},"epoch":{},"transactionId":{},"#,
                r#""blockTimeNanos":{},"finality":{},"memos":[{}]"#,
            ),
            decimal(verified.block.slot),
            quoted(&hex(&verified.block.id)),
            decimal(client.params().epoch_of(certified.block.slot)?),
            quoted(&hex(id)),
            verified
                .block_time_nanos()
                .map_or("null".to_owned(), decimal),
            quoted(&finality),
            memos.join(","),
        ))
    };
    answer(verified())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    struct Vector {
        shred_version: u32,
        epoch: u64,
        set: Vec<u8>,
        set_hash: Vec<u8>,
        signature: Vec<u8>,
        proof: Vec<u8>,
        block_id: String,
    }

    fn vector() -> Vector {
        let doc: Value = serde_json::from_str(include_str!(
            "../../solana-thin/tests/vectors/mainnet-block-473100911.json"
        ))
        .unwrap();
        let bytes = |name: &str| hex::decode(doc[name].as_str().unwrap()).unwrap();
        Vector {
            shred_version: doc["shred_version"].as_u64().unwrap() as u32,
            epoch: doc["epoch"].as_u64().unwrap(),
            set: bytes("validator_set"),
            set_hash: bytes("validator_set_hash"),
            signature: bytes("first_signature"),
            proof: bytes("proof_of_first_transaction"),
            block_id: doc["block_id"].as_str().unwrap().to_owned(),
        }
    }

    /// Copies `bytes` into memory from `st_alloc`, as the JavaScript side does.
    fn put(bytes: &[u8]) -> (*mut u8, usize) {
        let pointer = st_alloc(bytes.len());
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer, bytes.len()) };
        (pointer, bytes.len())
    }

    /// Reads an answer the way the JavaScript side does, and frees it.
    fn take(answer: *mut u8) -> Value {
        unsafe {
            let length = u32::from_le_bytes(*answer.cast::<[u8; 4]>()) as usize;
            let text = std::slice::from_raw_parts(answer.add(4), length).to_vec();
            st_free(answer, 4 + length);
            serde_json::from_slice(&text).unwrap()
        }
    }

    fn new_verifier(shred_version: u32, slots_per_epoch: u64, warmup: u32) -> Value {
        take(st_verifier_new(shred_version, slots_per_epoch, warmup))
    }

    fn handle(answer: &Value) -> *mut Verifier {
        assert_eq!(answer["ok"], true, "{answer}");
        answer["verifier"].as_u64().unwrap() as usize as *mut Verifier
    }

    fn pin(verifier: *mut Verifier, epoch: u64, set: &[u8], hash: &[u8]) -> Value {
        let (set, set_length) = put(set);
        let (hash, hash_length) = put(hash);
        let answer = unsafe { st_pin(verifier, epoch, set, set_length, hash, hash_length) };
        unsafe {
            st_free(set, set_length);
            st_free(hash, hash_length);
        }
        take(answer)
    }

    fn verify(verifier: *mut Verifier, proof: &[u8], signature: &[u8]) -> Value {
        let (proof, proof_length) = put(proof);
        let (signature, signature_length) = put(signature);
        let answer =
            unsafe { st_verify(verifier, proof, proof_length, signature, signature_length) };
        unsafe {
            st_free(proof, proof_length);
            st_free(signature, signature_length);
        }
        take(answer)
    }

    #[test]
    fn a_mainnet_proof_verifies_through_the_exported_functions() {
        let v = vector();
        let verifier = handle(&new_verifier(v.shred_version, 432_000, 0));

        let unpinned = verify(verifier, &v.proof, &[]);
        assert_eq!(
            unpinned,
            json!({
                "ok": false,
                "kind": "EpochNotPinned",
                "detail": "no trusted validator set for epoch 1095",
                "epoch": "1095",
            })
        );

        let wrong = pin(verifier, v.epoch, &v.set, &[0; 32]);
        assert_eq!(wrong["kind"], "InvalidValidatorSet", "{wrong}");
        let short = pin(verifier, v.epoch, &v.set, &v.set_hash[..31]);
        assert_eq!(
            short,
            json!({
                "ok": false,
                "kind": "InvalidParameters",
                "detail": "the pinned hash is 31 bytes, not 32",
                "epoch": null,
            })
        );
        assert_eq!(
            pin(verifier, v.epoch, &v.set, &v.set_hash),
            json!({ "ok": true })
        );

        let verified = verify(verifier, &v.proof, &[]);
        let time = verified["blockTimeNanos"].as_str().unwrap().to_owned();
        assert!(time.parse::<u64>().unwrap() > 1_793_500_000_000_000_000);
        assert_eq!(
            verified,
            json!({
                "ok": true,
                "slot": "473100911",
                "blockId": v.block_id,
                "epoch": "1095",
                "transactionId": hex::encode(&v.signature),
                "blockTimeNanos": time,
                "finality": "fast",
                "memos": [],
            })
        );
        assert_eq!(verify(verifier, &v.proof, &v.signature), verified);

        let mut other = v.signature.clone();
        other[0] ^= 1;
        assert_eq!(
            verify(verifier, &v.proof, &other)["kind"],
            "WrongTransaction"
        );
        assert_eq!(
            verify(verifier, &v.proof, &v.signature[..63])["detail"],
            "the expected signature is 63 bytes, not 64"
        );
        let cut = verify(verifier, &v.proof[..v.proof.len() - 1], &[]);
        assert_eq!(cut["kind"], "Malformed", "{cut}");

        unsafe { st_verifier_free(verifier) };
    }

    #[test]
    fn a_verifier_is_made_for_a_cluster_or_not_at_all() {
        let v = vector();
        for warmup in [0, 1] {
            let refused = new_verifier(v.shred_version, 31, warmup);
            assert_eq!(refused["kind"], "InvalidParameters", "{refused}");
        }
        let too_wide = new_verifier(0x1_0000, 432_000, 0);
        assert_eq!(
            too_wide["detail"],
            "the shred version is 65536, which does not fit 16 bits"
        );

        // With warm-up epochs the same slot is in another epoch.
        let warm = handle(&new_verifier(v.shred_version, 432_000, 1));
        assert_eq!(
            pin(warm, v.epoch, &v.set, &v.set_hash),
            json!({ "ok": true })
        );
        assert_eq!(verify(warm, &v.proof, &[])["epoch"], "1107");
        unsafe { st_verifier_free(warm) };
    }

    #[test]
    fn text_in_an_answer_is_escaped() {
        assert_eq!(quoted("plain"), r#""plain""#);
        assert_eq!(quoted("a \"b\" \\ c\n\u{1}"), r#""a \"b\" \\ c\n\u0001""#);
        let parsed: Value = serde_json::from_str(&quoted("it's \"x\"\t\u{7f}é")).unwrap();
        assert_eq!(parsed, "it's \"x\"\t\u{7f}é");
    }
}
