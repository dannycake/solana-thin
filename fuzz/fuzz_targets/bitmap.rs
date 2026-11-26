#![no_main]

//! Signer bitmaps, against `solana-signer-store`, the crate Agave decodes them with. The input
//! is a validator count (`u16`) and then the bitmap.
//!
//! For a finalization certificate a validator calls `decode` and then insists on the
//! single-vector form (`verify_base2` in Agave 4.4.1's `bls-cert-verify/src/cert_verify.rs`
//! returns `WrongEncoding` for `Decoded::Base3`). So:
//!
//! * theirs decodes a single vector: ours must accept and name exactly the same ranks;
//! * theirs decodes the two-vector form: ours must refuse. This is the one intended
//!   difference from the decoder itself, and it matches what the validator does with the
//!   result;
//! * theirs refuses: ours must refuse.
//!
//! And whatever ranks come out, `encode_bitmap` writes them back in a form their decoder
//! reads to the same ranks.

use solana_signer_store::{decode, Decoded};
use solana_thin::certificate::{decode_bitmap, encode_bitmap};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((count, bitmap)) = data.split_first_chunk::<2>() else {
        return;
    };
    let validators = usize::from(u16::from_le_bytes(*count));
    let ours = decode_bitmap(bitmap, validators);
    match decode(bitmap, validators) {
        Ok(Decoded::Base2(bits)) => {
            let theirs: Vec<usize> = bits.iter_ones().collect();
            assert_eq!(ours.as_ref(), Ok(&theirs));
            let encoded = encode_bitmap(&theirs);
            match decode(&encoded, validators) {
                Ok(Decoded::Base2(bits)) => {
                    assert_eq!(bits.iter_ones().collect::<Vec<_>>(), theirs)
                }
                other => panic!("their decoder does not read our encoding: {other:?}"),
            }
            assert_eq!(decode_bitmap(&encoded, validators), Ok(theirs));
        }
        Ok(Decoded::Base3(..)) => assert!(ours.is_err(), "ours accepts a two-vector bitmap"),
        Err(error) => assert!(ours.is_err(), "theirs refuses with {error:?}, ours accepts"),
    }
});
