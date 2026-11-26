#![no_main]

//! `transaction_view`, against the parser of the next release: `agave-transaction-view` 10.1.0,
//! which Agave 4.5 replays with (v4.5.0-beta.0, `entry/src/block_component_parser.rs:110`). The
//! bytes of a transaction are what they were in 4.4.1. What moved is where the limits are:
//!
//! * Parsing lets more through: up to 127 signatures in front of a legacy or v0 message, where
//!   4.4.1 stopped at 12.
//! * `sanitize` takes no configuration and checks less. The limits 4.4.1 passed in, its cap of
//!   12 signatures and the size of a v1 transaction are now replay's own to check, around its
//!   call to `sanitize` (see `within_replay_limits`).
//!
//! The property is the one `transaction_view` holds, over the wider set:
//!
//! * **Parsed and sanitized**: ours must accept it, consume the same number of bytes and agree
//!   on everything the view exposes. Counted as `agreed` when replay's limits pass too, so that
//!   a finalized block can hold it, and as `agreed_over_limits` when they do not (13 signatures
//!   on a v1 transaction, 65 instructions). Ours is held to both: those limits are policy that
//!   a later release can raise without touching the parser.
//! * **Parsed, but sanitize refuses it**: ours may refuse too, counted as
//!   `theirs_unsanitized_only`. If it accepts, the length and the contents must still agree.
//!
//! Ours accepting what the view refuses is allowed and counted as `ours_only`, as there.
//!
//! To see an example of a counted case: `FUZZ_FAIL_ON=agreed_over_limits cargo +nightly fuzz
//! run -O -a transaction_view_45`.

use agave_transaction_view_45::{
    transaction_version::TransactionVersion, transaction_view::UnsanitizedTransactionView,
};
use solana_thin::transaction::MessageVersion;
use solana_thin_fuzz::{
    assert_same_instructions, assert_same_parts, parse_prefix, tally_at_exit, Counter,
};

/// What replay checks on a sanitized view before running it (Agave 4.5): the size, in
/// `Bank::verify_transaction` (`runtime/src/bank.rs:5734-5745`), and the limits of
/// `runtime-transaction/src/transaction_limits.rs:53-104`, applied when the view becomes a
/// `RuntimeTransaction` (`runtime-transaction/src/runtime_transaction/transaction_view.rs:82-88`).
/// The numbers are `PACKET_DATA_SIZE` and `v1::MAX_TRANSACTION_SIZE`, `MAX_V1_SIGNATURES` and
/// `MAX_V1_ACCOUNTS`, `MAX_INSTRUCTION_TRACE_LENGTH`, `MAX_ACCOUNTS_PER_INSTRUCTION`, and a
/// requested heap between `MIN_HEAP_FRAME_BYTES` and `MAX_HEAP_FRAME_BYTES`.
fn within_replay_limits(view: &UnsanitizedTransactionView<&[u8]>) -> bool {
    let v1 = matches!(view.version(), TransactionVersion::V1);
    let max_size = if v1 { 4096 } else { 1232 };
    let heap = view
        .transaction_config()
        .and_then(|config| config.requested_heap_size());
    view.data().len() <= max_size
        && (!v1 || (view.num_signatures() <= 12 && view.num_static_account_keys() <= 96))
        && view.num_instructions() <= 64
        && view.instructions_iter().all(|ix| ix.accounts.len() <= 255)
        && heap.is_none_or(|heap| (32 * 1024..=256 * 1024).contains(&heap) && heap % 1024 == 0)
}

static AGREED: Counter = Counter::new("agreed");
static AGREED_OVER_LIMITS: Counter = Counter::new("agreed_over_limits");
static BOTH_UNSANITIZED: Counter = Counter::new("both_unsanitized");
static THEIRS_UNSANITIZED_ONLY: Counter = Counter::new("theirs_unsanitized_only");
static OURS_ONLY: Counter = Counter::new("ours_only");
static NEITHER: Counter = Counter::new("neither");
static COUNTERS: [&Counter; 6] = [
    &AGREED,
    &AGREED_OVER_LIMITS,
    &BOTH_UNSANITIZED,
    &THEIRS_UNSANITIZED_ONLY,
    &OURS_ONLY,
    &NEITHER,
];

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    tally_at_exit("transaction_view_45", &COUNTERS);
    let ours = parse_prefix(data);
    let Ok((view, consumed)) = UnsanitizedTransactionView::try_new_unsanitized_from_prefix(data)
    else {
        match ours {
            Some(_) => OURS_ONLY.bump(),
            None => NEITHER.bump(),
        }
        return;
    };
    let sanitized = view.clone().sanitize().is_ok();
    let Some((tx, len)) = ours else {
        assert!(
            !sanitized,
            "the validator accepts a transaction of {consumed} bytes that the light client refuses"
        );
        THEIRS_UNSANITIZED_ONLY.bump();
        return;
    };
    assert_eq!(
        len, consumed,
        "the two parsers end the transaction in different places"
    );
    match (sanitized, within_replay_limits(&view)) {
        (true, true) => AGREED.bump(),
        (true, false) => AGREED_OVER_LIMITS.bump(),
        (false, _) => BOTH_UNSANITIZED.bump(),
    }

    // Both read the same bytes to the same end: everything they expose must match.
    assert_same_parts(
        &tx,
        view.signatures(),
        view.static_account_keys(),
        view.recent_blockhash().as_ref(),
        view.message_data(),
    );
    let version = match view.version() {
        TransactionVersion::Legacy => MessageVersion::Legacy,
        TransactionVersion::V0 => MessageVersion::V0,
        TransactionVersion::V1 => MessageVersion::V1,
    };
    assert_eq!(tx.version, version);
    assert_same_instructions(
        &tx,
        view.instructions_iter()
            .map(|ix| (ix.program_id_index, ix.accounts, ix.data)),
    );
});
