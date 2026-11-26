#![no_main]

//! Transactions, against the other parser a validator ships: `solana-transaction`'s
//! `VersionedTransaction` read with `wincode`, the path ledger tools and RPC use (and how
//! `tools/agave-fixtures` writes its vectors).
//!
//! * wincode reads the whole input as a transaction and `sanitize` passes: ours must accept
//!   the same bytes, with the same signatures and the same message bytes.
//! * wincode reads it but `sanitize` refuses it: ours may refuse too (it checks the signature
//!   count against the header while parsing). Counted as `theirs_unsanitized_only`;
//!   `findings/transaction_wincode/unsanitized-legacy-no-signatures` is one. If ours accepts,
//!   the signatures and message must still agree.
//! * ours accepts what wincode refuses: allowed, counted as `ours_only`.

use solana_thin::transaction::Transaction;
use solana_thin_fuzz::{assert_same_parts, tally_at_exit, Counter};
use solana_transaction::versioned::VersionedTransaction;

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
    tally_at_exit("transaction_wincode", &COUNTERS);
    let ours = Transaction::parse(data);
    let Ok(theirs) = wincode::deserialize_exact::<VersionedTransaction>(data) else {
        match ours {
            Ok(_) => OURS_ONLY.bump(),
            Err(_) => NEITHER.bump(),
        }
        return;
    };
    let sanitized = theirs.sanitize().is_ok();
    let tx = match ours {
        Ok(tx) => tx,
        Err(error) => {
            assert!(
                !sanitized,
                "wincode reads a sanitary transaction that the light client refuses: {error}"
            );
            THEIRS_UNSANITIZED_ONLY.bump();
            return;
        }
    };
    if sanitized {
        AGREED.bump();
    } else {
        BOTH_UNSANITIZED.bump();
    }
    assert_same_parts(
        &tx,
        &theirs.signatures,
        theirs.message.static_account_keys(),
        theirs.message.recent_blockhash().as_ref(),
        &theirs.message.serialize(),
    );
});
