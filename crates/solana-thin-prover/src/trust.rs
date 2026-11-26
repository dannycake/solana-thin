//! What the prover verifies with: a client holding the pinned sets.
//!
//! The prover checks every certificate before it builds on it and every
//! proof before it hands it out, with the same verifier a client runs. So
//! it needs what a client needs: the cluster's shred version, its epoch
//! schedule, and each epoch's validator set under a pinned hash.
//!
//! The hash comes from a verified set log if one is given, and from the set
//! file itself otherwise. In the second case the operator is trusting the
//! file. Either way a wrong set makes the prover refuse what it should
//! serve, or serve what clients with the right set refuse; it cannot make a
//! client accept anything.

use solana_thin::{ClusterParams, Limits, ThinClient};
use solana_thin_setlog::{SetFile, VerifiedLog};
use std::collections::BTreeMap;

/// Where the cluster's epochs begin and end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schedule {
    /// By the cluster's name: `mainnet-beta`, `testnet` or `devnet`.
    Known,
    /// Epochs of this many slots from slot zero, as on a test validator.
    Flat(u64),
    /// Warm-up epochs, then epochs of this many slots.
    Warmup(u64),
}

/// The client, and the set files it was built from.
#[derive(Debug, Clone)]
pub struct Trust {
    client: ThinClient,
    cluster: String,
    sets: BTreeMap<u64, SetFile>,
}

impl Trust {
    /// Pins every set in `files`, to the hash `log` gives for its epoch or,
    /// without a log, to the file's own.
    ///
    /// The files must be for one cluster under one shred version, one per
    /// epoch. With a log, each must be the set the log names for its epoch.
    pub fn new(
        files: Vec<SetFile>,
        log: Option<&VerifiedLog>,
        schedule: Schedule,
    ) -> Result<Self, String> {
        let first = files.first().ok_or("no set file was given")?;
        let (cluster, shred_version) = (first.cluster().to_string(), first.shred_version());
        let params = match (schedule, cluster.as_str()) {
            (Schedule::Known, "mainnet-beta") => Ok(ClusterParams::mainnet(shred_version)),
            (Schedule::Known, "testnet" | "devnet") => {
                ClusterParams::with_warmup(shred_version, 432_000)
            }
            (Schedule::Known, other) => {
                return Err(format!(
                    "the epoch schedule of cluster {other:?} is not known; give its epoch length"
                ))
            }
            (Schedule::Flat(slots), _) => ClusterParams::without_warmup(shred_version, slots),
            (Schedule::Warmup(slots), _) => ClusterParams::with_warmup(shred_version, slots),
        }
        .map_err(|e| format!("the epoch schedule: {e}"))?;
        if let Some(log) = log {
            if log.cluster() != cluster {
                return Err(format!(
                    "the log is for {} and the set files are for {cluster}",
                    log.cluster()
                ));
            }
        }
        let mut client = ThinClient::new(params);
        let mut sets = BTreeMap::new();
        for file in files {
            let epoch = file.epoch();
            if file.cluster() != cluster {
                return Err(format!(
                    "the set for epoch {epoch} is for {}, not {cluster}",
                    file.cluster()
                ));
            }
            if file.shred_version() != shred_version {
                return Err(format!(
                    "the set for epoch {epoch} is under shred version {}, not {shred_version}",
                    file.shred_version()
                ));
            }
            let hash = match log {
                None => file.set_hash(),
                Some(log) => {
                    let pin = log
                        .pin(epoch)
                        .ok_or_else(|| format!("the log has no record for epoch {epoch}"))?;
                    if pin.shred_version != shred_version {
                        return Err(format!(
                            "the log puts epoch {epoch} under shred version {}, not \
                             {shred_version}",
                            pin.shred_version
                        ));
                    }
                    pin.set_hash
                }
            };
            client
                .trust_validator_set_bytes(epoch, file.set_bytes(), &hash)
                .map_err(|e| format!("the set for epoch {epoch}: {e}"))?;
            sets.insert(epoch, file);
        }
        Ok(Self {
            client,
            cluster,
            sets,
        })
    }

    /// Holds every proof to `limits`, so that none leaves that a client
    /// with the same limits would refuse for its size.
    pub fn set_limits(&mut self, limits: Limits) {
        self.client.set_limits(limits);
    }

    /// The verifier, with every set pinned.
    pub fn client(&self) -> &ThinClient {
        &self.client
    }

    /// The cluster's name, as the set files give it.
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// The cluster's shred version, as the set files give it.
    pub fn shred_version(&self) -> u16 {
        self.client.params().shred_version
    }

    /// The epochs a set is pinned for.
    pub fn epochs(&self) -> Vec<u64> {
        self.sets.keys().copied().collect()
    }

    /// The set file pinned for `epoch`.
    pub fn set_file(&self, epoch: u64) -> Option<&SetFile> {
        self.sets.get(&epoch)
    }
}
