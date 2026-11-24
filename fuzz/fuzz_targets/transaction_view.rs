#![no_main]

//! Transactions, against the parser replay uses. A validator replaying a block reads each
//! transaction with `UnsanitizedTransactionView::try_new_unsanitized_from_prefix`
//! (Agave 4.4.1, `entry/src/block_component_parser.rs:108`): the transaction ends where that
//! parser says it does, and the next one starts there. The light client walks the same bytes
//! with its own parser and has to land in the same places.
//!
//! The view is in two steps, and so is the property:
//!
//! * **Parsed and sanitized** (`sanitize` with the limits replay passes, see `REPLAY`): this is
//!   a transaction a finalized block can hold. Ours must accept it, consume the same number of
//!   bytes, and agree on the signatures, the static account keys, the blockhash, the message
//!   bytes and every instruction.
//! * **Parsed, but sanitize refuses it**: a block holding it is dead, so no proof ever walks
//!   over it. Ours folds some of those checks into parsing (no signatures, a signature count
//!   that does not match the header, no account keys) and may refuse. Counted as
//!   `theirs_unsanitized_only`; `findings/transaction_view/unsanitized-v1-no-signers` is one.
//!   If ours does accept, it must still agree on the length and the contents.
//!
//! The other direction, ours accepting what the view refuses, is allowed and counted as
//! `ours_only`: the view applies limits that follow from the packet size while it parses (at
//! most 12 signatures, 38 keys, lengths of two compact-u16 bytes, room for one index per
//! address table lookup, offsets that fit a `u16`) and ours has none of them.
//! `findings/transaction_view/ours-only-v0-empty-lookups` is one. Those bytes never reach a
//! finalized block either.
//!
//! To see an example of a counted case: `FUZZ_FAIL_ON=ours_only cargo +nightly fuzz run -O -a
//! transaction_view`, or give it one of the files in `findings/transaction_view/`.

use agave_transaction_view::{
    sanitize::SanitizeConfig, transaction_version::TransactionVersion,
    transaction_view::UnsanitizedTransactionView,
};
use solana_thin::transaction::MessageVersion;
use solana_thin_fuzz::{parse_prefix, tally_at_exit, Counter};

/// What Agave 4.4.1 passes (`runtime-transaction/src/sanitize_config.rs`): heap between
/// `MIN_HEAP_FRAME_BYTES` and `MAX_HEAP_FRAME_BYTES`, `MAX_INSTRUCTION_TRACE_LENGTH`,
/// `MAX_ACCOUNTS_PER_INSTRUCTION`.
const REPLAY: SanitizeConfig = SanitizeConfig {
    min_requested_heap_size: 32 * 1024,
    max_requested_heap_size: 256 * 1024,
    max_instructions: 64,
    max_accounts_per_instruction: 255,
};

static AGREED: Counter = Counter::new("agreed");
static BOTH_UNSANITIZED: Counter = Counter::new("both_unsanitized");
static THEIRS_UNSANITIZED_ONLY: Counter = Counter::new("theirs_unsanitized_only");
static OURS_ONLY: Counter = Counter::new("ours_only");
static NEITHER: Counter = Counter::new("neither");
static COUNTERS: [&Counter; 5] = [
    &AGREED,
    &BOTH_UNSANITIZED,
    &THEIRS_UNSANITIZED_ONLY,
    &OURS_ONLY,
    &NEITHER,
];

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    tally_at_exit("transaction_view", &COUNTERS);
    let ours = parse_prefix(data);
    let Ok((view, consumed)) = UnsanitizedTransactionView::try_new_unsanitized_from_prefix(data)
    else {
        match ours {
            Some(_) => OURS_ONLY.bump(),
            None => NEITHER.bump(),
        }
        return;
    };
    let sanitized = view.clone().sanitize(&REPLAY).is_ok();
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
    if sanitized {
        AGREED.bump();
    } else {
        BOTH_UNSANITIZED.bump();
    }

    // Both read the same bytes to the same end: everything they expose must match.
    assert_eq!(tx.signatures.len(), usize::from(view.num_signatures()));
    for (ours, theirs) in tx.signatures.iter().zip(view.signatures()) {
        assert_eq!(&ours[..], theirs.as_ref());
    }
    assert_eq!(
        tx.account_keys.len(),
        usize::from(view.num_static_account_keys())
    );
    for (ours, theirs) in tx.account_keys.iter().zip(view.static_account_keys()) {
        assert_eq!(&ours[..], theirs.as_ref());
    }
    assert_eq!(&tx.recent_blockhash[..], view.recent_blockhash().as_ref());
    assert_eq!(tx.message, view.message_data());
    let version = match view.version() {
        TransactionVersion::Legacy => MessageVersion::Legacy,
        TransactionVersion::V0 => MessageVersion::V0,
        TransactionVersion::V1 => MessageVersion::V1,
    };
    assert_eq!(tx.version, version);
    assert_eq!(tx.instructions.len(), usize::from(view.num_instructions()));
    for (ours, theirs) in tx.instructions.iter().zip(view.instructions_iter()) {
        assert_eq!(ours.program_id_index, theirs.program_id_index);
        assert_eq!(ours.accounts, theirs.accounts);
        assert_eq!(ours.data, theirs.data);
    }
});
