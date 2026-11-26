//! A client's side of a validator-set log: check the log against the signer
//! keys the client ships with, then pin the set it names.
//!
//! ```text
//! cargo run -p solana-thin-setlog --example pin_from_log -- \
//!     <log.jsonl> <set file> <threshold> <signer key, hex> [<signer key> ...]
//! ```
//!
//! The log and the set file can come from anywhere. The signer keys and the
//! threshold cannot: they are what the client trusts.

use solana_thin::{ClusterParams, ThinClient};
use solana_thin_setlog::{parse, signer_key_from_hex, verify, SetFile};
use std::error::Error;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [log_path, set_path, threshold, signers @ ..] = &args[..] else {
        return Err(
            "usage: pin_from_log <log.jsonl> <set file> <threshold> <signer key> ...".into(),
        );
    };
    let signer_keys = signers
        .iter()
        .map(|key| signer_key_from_hex(key))
        .collect::<Result<Vec<_>, _>>()?;

    // Every signature and every link, or nothing.
    let log = verify(
        &parse(&fs::read_to_string(log_path)?)?,
        &signer_keys,
        threshold.parse()?,
    )?;

    // The set file says which epoch its bytes are for. The hash to hold
    // them to comes from the log.
    let set_file = SetFile::from_json(&fs::read_to_string(set_path)?)?;
    if set_file.cluster() != log.cluster() {
        return Err("the set file is for another cluster".into());
    }
    let epoch = set_file.epoch();
    let pin = log
        .pin(epoch)
        .ok_or("the log has no record for the set file's epoch")?;

    // Mainnet's epochs are full length from slot zero; testnet and devnet
    // began with warm-up epochs.
    let params = match log.cluster() {
        "mainnet-beta" => ClusterParams::mainnet(pin.shred_version),
        _ => ClusterParams::with_warmup(pin.shred_version, 432_000)?,
    };
    let mut client = ThinClient::new(params);
    client.trust_validator_set_bytes(epoch, set_file.set_bytes(), &pin.set_hash)?;

    let set = client.validator_set(epoch).expect("just pinned");
    println!(
        "pinned epoch {epoch} of {}: {} validators, total stake {}, set hash {}",
        log.cluster(),
        set.len(),
        set.total_stake(),
        hex::encode(set.hash())
    );
    Ok(())
}
