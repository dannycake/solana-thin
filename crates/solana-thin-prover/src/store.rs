//! What the prover keeps on disk: a directory, bounded.
//!
//! ```text
//! <dir>/blocks/<slot>.block       a certified block: its anchor and shreds
//! <dir>/proofs/<signature>.proof  a proof that was built and verified
//! <dir>/certs/<slot>.cert         a verified certificate, by certified slot
//! ```
//!
//! A block's shreds are kept so that the next proof from the same block
//! costs no fetch. They are also the first thing to go: when the directory
//! passes its cap the oldest blocks are deleted, and the proofs built from
//! them stay. Proofs and certificates may take half the cap; past that the
//! oldest of them go too.
//!
//! Nothing read back is trusted. A proof is verified again before it is
//! served, and a block is hashed again when it is indexed, so a damaged or
//! planted file costs a fetch and nothing else.

use crate::anchor::{decode_certificate, encode_certificate, Anchor};
use solana_thin::shred::DATA_SHRED_SIZE;
use solana_thin::{BlockRef, FinalityCert};
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const BLOCK_MAGIC: &[u8; 5] = b"STPB\x01";
const BLOCKS: &str = "blocks";
const PROOFS: &str = "proofs";
const CERTS: &str = "certs";

/// A block read back from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlock {
    /// The block the file says it holds.
    pub block: BlockRef,
    /// Why it is final.
    pub anchor: Anchor,
    /// Its data shreds, in order.
    pub shreds: Vec<Vec<u8>>,
}

/// How full the store is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Blocks whose shreds are held.
    pub blocks: usize,
    /// Bytes they take.
    pub block_bytes: u64,
    /// Proofs and certificates held.
    pub kept: usize,
    /// Bytes they take.
    pub kept_bytes: u64,
    /// The cap on the whole directory.
    pub cap: u64,
}

#[derive(Default)]
struct Index {
    /// Files in the order they were written, oldest first, with their size.
    blocks: VecDeque<(PathBuf, u64)>,
    kept: VecDeque<(PathBuf, u64)>,
    block_bytes: u64,
    kept_bytes: u64,
}

/// The directory.
pub struct Store {
    dir: PathBuf,
    cap: u64,
    index: Mutex<Index>,
}

impl Store {
    /// Opens `dir`, creating it if need be, and holds it to `cap` bytes
    /// from now on. What is already there is kept, oldest first by the time
    /// it was written, as far as the cap allows.
    pub fn open(dir: &Path, cap: u64) -> io::Result<Self> {
        let mut found = Vec::new();
        for (name, is_block) in [(BLOCKS, true), (PROOFS, false), (CERTS, false)] {
            let folder = dir.join(name);
            fs::create_dir_all(&folder)?;
            for entry in fs::read_dir(&folder)? {
                let entry = entry?;
                let path = entry.path();
                let meta = entry.metadata()?;
                // A write that never finished.
                if path.extension().is_some_and(|ext| ext == "tmp") {
                    let _ = fs::remove_file(&path);
                    continue;
                }
                if meta.is_file() {
                    let written = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                    found.push((written, path, meta.len(), is_block));
                }
            }
        }
        found.sort();
        let mut index = Index::default();
        for (_, path, size, is_block) in found {
            if is_block {
                index.block_bytes += size;
                index.blocks.push_back((path, size));
            } else {
                index.kept_bytes += size;
                index.kept.push_back((path, size));
            }
        }
        let store = Self {
            dir: dir.to_path_buf(),
            cap,
            index: Mutex::new(index),
        };
        store.evict(&mut store.index.lock().unwrap());
        Ok(store)
    }

    /// How full the store is.
    pub fn usage(&self) -> Usage {
        let index = self.index.lock().unwrap();
        Usage {
            blocks: index.blocks.len(),
            block_bytes: index.block_bytes,
            kept: index.kept.len(),
            kept_bytes: index.kept_bytes,
            cap: self.cap,
        }
    }

    /// Deletes the oldest files until the directory fits its cap: proofs
    /// and certificates down to half of it, then blocks.
    fn evict(&self, index: &mut Index) {
        while index.kept_bytes > self.cap / 2 {
            let Some((path, size)) = index.kept.pop_front() else {
                break;
            };
            let _ = fs::remove_file(path);
            index.kept_bytes -= size;
        }
        while index.kept_bytes + index.block_bytes > self.cap {
            let Some((path, size)) = index.blocks.pop_front() else {
                break;
            };
            let _ = fs::remove_file(path);
            index.block_bytes -= size;
        }
    }

    /// Writes `bytes` to `path` so that a reader sees the old file or the
    /// new one and never part of either, then makes room for it.
    fn write(&self, path: PathBuf, bytes: &[u8], is_block: bool) -> io::Result<()> {
        let mut index = self.index.lock().unwrap();
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, bytes)?;
        fs::rename(&temporary, &path)?;
        let index = &mut *index;
        let (list, total) = if is_block {
            (&mut index.blocks, &mut index.block_bytes)
        } else {
            (&mut index.kept, &mut index.kept_bytes)
        };
        // Written again: it is the newest now.
        if let Some(at) = list.iter().position(|(held, _)| *held == path) {
            *total -= list.remove(at).map_or(0, |(_, size)| size);
        }
        list.push_back((path, bytes.len() as u64));
        *total += bytes.len() as u64;
        self.evict(index);
        Ok(())
    }

    fn block_path(&self, slot: u64) -> PathBuf {
        self.dir.join(BLOCKS).join(format!("{slot}.block"))
    }

    fn proof_path(&self, signature: &[u8; 64]) -> PathBuf {
        let name = bs58::encode(signature).into_string();
        self.dir.join(PROOFS).join(format!("{name}.proof"))
    }

    fn certificate_path(&self, slot: u64) -> PathBuf {
        self.dir.join(CERTS).join(format!("{slot}.cert"))
    }

    /// Keeps a certified block's shreds and its anchor.
    pub fn put_block(
        &self,
        block: &BlockRef,
        anchor: &Anchor,
        shreds: &[Vec<u8>],
    ) -> io::Result<()> {
        let invalid = |what| io::Error::new(io::ErrorKind::InvalidInput, what);
        let anchor = anchor
            .to_bytes()
            .ok_or_else(|| invalid("an anchor that cannot be written"))?;
        let mut bytes = Vec::with_capacity(64 + anchor.len() + shreds.len() * DATA_SHRED_SIZE);
        bytes.extend_from_slice(BLOCK_MAGIC);
        bytes.extend_from_slice(&block.slot.to_le_bytes());
        bytes.extend_from_slice(&block.id);
        bytes.extend_from_slice(&(anchor.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&anchor);
        bytes.extend_from_slice(&(shreds.len() as u32).to_le_bytes());
        for shred in shreds {
            if shred.len() != DATA_SHRED_SIZE {
                return Err(invalid("a shred of the wrong size"));
            }
            bytes.extend_from_slice(shred);
        }
        self.write(self.block_path(block.slot), &bytes, true)
    }

    /// The block held for `slot`, if its file is there and well formed.
    /// Whether the shreds are that block is for the caller to check.
    pub fn block(&self, slot: u64) -> Option<StoredBlock> {
        let bytes = fs::read(self.block_path(slot)).ok()?;
        let rest = bytes.strip_prefix(BLOCK_MAGIC)?;
        let (slot_bytes, rest) = rest.split_first_chunk::<8>()?;
        let (id, rest) = rest.split_first_chunk::<32>()?;
        let (anchor_len, rest) = rest.split_first_chunk::<4>()?;
        let anchor_len = u32::from_le_bytes(*anchor_len) as usize;
        if rest.len() < anchor_len {
            return None;
        }
        let (anchor, rest) = rest.split_at(anchor_len);
        let (count, rest) = rest.split_first_chunk::<4>()?;
        let count = u32::from_le_bytes(*count) as usize;
        if rest.len() != count.checked_mul(DATA_SHRED_SIZE)? {
            return None;
        }
        let block = BlockRef {
            slot: u64::from_le_bytes(*slot_bytes),
            id: *id,
        };
        (block.slot == slot).then_some(())?;
        Some(StoredBlock {
            block,
            anchor: Anchor::from_bytes(anchor)?,
            shreds: rest
                .chunks_exact(DATA_SHRED_SIZE)
                .map(<[u8]>::to_vec)
                .collect(),
        })
    }

    /// Deletes the block held for `slot`: its file turned out to be wrong.
    pub fn drop_block(&self, slot: u64) {
        let path = self.block_path(slot);
        let mut index = self.index.lock().unwrap();
        if let Some(at) = index.blocks.iter().position(|(held, _)| *held == path) {
            let size = index.blocks.remove(at).map_or(0, |(_, size)| size);
            index.block_bytes -= size;
        }
        let _ = fs::remove_file(path);
    }

    /// Keeps a proof under the signature it proves.
    pub fn put_proof(&self, signature: &[u8; 64], proof: &[u8]) -> io::Result<()> {
        self.write(self.proof_path(signature), proof, false)
    }

    /// The proof kept for `signature`. Unverified until the caller verifies
    /// it.
    pub fn proof(&self, signature: &[u8; 64]) -> Option<Vec<u8>> {
        fs::read(self.proof_path(signature)).ok()
    }

    /// Keeps a certificate under the slot of the block it certifies.
    pub fn put_certificate(&self, certificate: &FinalityCert) -> io::Result<()> {
        let bytes = encode_certificate(certificate).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a certificate that cannot be written",
            )
        })?;
        self.write(
            self.certificate_path(certificate.block().slot),
            &bytes,
            false,
        )
    }

    /// The certificate kept for the block of `slot`. Unverified until the
    /// caller verifies it.
    pub fn certificate(&self, slot: u64) -> Option<FinalityCert> {
        let certificate = decode_certificate(&fs::read(self.certificate_path(slot)).ok()?)?;
        (certificate.block().slot == slot).then_some(certificate)
    }
}
