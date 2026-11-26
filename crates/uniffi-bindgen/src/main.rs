//! UniFFI's binding generator, built from the same `uniffi` release as
//! `solana-thin-ffi`. Generated code and library have to agree on that
//! version, and a generator installed from elsewhere might not.
//!
//! ```text
//! cargo run -p uniffi-bindgen -- generate --library <libsolana_thin_ffi> \
//!     --language kotlin --out-dir <dir>
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
