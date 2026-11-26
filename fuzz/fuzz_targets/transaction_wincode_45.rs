#![no_main]

//! `transaction_wincode`, against the next release: `solana-transaction` and `solana-message`
//! 6.0.0, which Agave 4.5 ships. `sanitize` there no longer caps a v1 message at 12 signatures,
//! 64 account keys and 64 instructions, nor checks its heap size or that its keys differ: a v1
//! message sanitizes with as many of each as its one-byte counts can say, and ours must accept
//! all of them. The property and the counters are those of `transaction_wincode`.

use solana_thin::transaction::Transaction;
use solana_thin_fuzz::{assert_same_parts, tally_at_exit, Counter};
use solana_transaction_45::versioned::VersionedTransaction;

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
    tally_at_exit("transaction_wincode_45", &COUNTERS);
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
