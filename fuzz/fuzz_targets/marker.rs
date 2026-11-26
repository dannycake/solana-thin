#![no_main]

//! Block components: the bytes inside shreds, as a proof hands them over. The input is an
//! entry index and a transaction index (one byte each), then the component.
//!
//! Nothing here may panic, hang or allocate more than the input can back. And the two walks
//! over an entry batch must agree: every transaction `transactions` lists is what
//! `transaction_at` returns for that position.

use solana_thin::block::{self, TxPosition};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((position, component)) = data.split_first_chunk::<2>() else {
        return;
    };
    let position = TxPosition {
        entry: u32::from(position[0]),
        transaction: u32::from(position[1]),
    };
    let marker = block::parse_marker(component);
    let at = block::transaction_at(component, position);
    let all = block::transactions(component);
    if block::is_entry_batch(component) {
        assert!(marker.is_err(), "an entry batch parsed as a marker");
    } else {
        assert!(
            at.is_err() && all.is_err(),
            "a marker parsed as an entry batch"
        );
    }
    let Ok(all) = all else { return };
    for (position, tx) in &all {
        assert_eq!(block::transaction_at(component, *position).as_ref(), Ok(tx));
    }
    // The whole batch parsed, so the position asked for is found exactly when it is listed.
    let listed = all.iter().find(|(p, _)| *p == position).map(|(_, tx)| tx);
    assert_eq!(at.as_ref().ok(), listed);
});
