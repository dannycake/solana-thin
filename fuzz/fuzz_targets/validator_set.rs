#![no_main]

//! An encoded validator set, fetched from anywhere before its hash is compared with the pinned
//! one. Decoding must not panic or allocate more than the input can back, and a set that
//! decodes re-encodes to the same bytes and so to the same hash.

use solana_thin::ValidatorSet;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(set) = ValidatorSet::from_bytes(data) else {
        return;
    };
    assert_eq!(set.to_bytes(), data);
    let again = ValidatorSet::from_bytes(&set.to_bytes()).expect("a decoded set re-encodes");
    assert_eq!(again.hash(), set.hash());
    assert_eq!(again.validators(), set.validators());
});
