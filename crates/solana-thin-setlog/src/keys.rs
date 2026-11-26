//! Ed25519 keys and signatures, as plain byte arrays at the crate's edge.

use crate::error::{Error, Result};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

/// A signer's public key: 32 bytes of Ed25519.
pub type SignerKey = [u8; 32];

/// A key that signs records.
///
/// Built from a 32-byte seed. The seed is the secret; this type never prints
/// it and has no way to give it back.
pub struct SigningKey(KeyPair);

impl SigningKey {
    /// The key for `seed`. The all-zero seed is refused: it is what an unset
    /// buffer looks like.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        KeyPair::try_from_seed(Seed::new(seed))
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// The key for a seed written as 64 hex digits.
    pub fn from_hex(seed: &str) -> Result<Self> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(seed.trim(), &mut bytes).map_err(|_| Error::InvalidKey)?;
        let key = Self::from_seed(bytes);
        bytes.fill(0);
        key
    }

    /// The public half, which a client lists as a signer key.
    pub fn public_key(&self) -> SignerKey {
        *self.0.pk
    }

    /// Signs `message`. The signature depends only on the key and the
    /// message, so signing twice gives the same bytes.
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        *self.0.sk.sign(message, None)
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningKey({})", hex::encode(self.public_key()))
    }
}

/// Whether `signature` is `signer`'s signature over `message`.
///
/// Strict: a signature whose scalar is not reduced is refused, so a valid
/// signature has one encoding.
pub(crate) fn verify(signer: &SignerKey, message: &[u8], signature: &[u8; 64]) -> bool {
    PublicKey::new(*signer)
        .verify(message, &Signature::new(*signature))
        .is_ok()
}

/// Parses a signer key written as 64 hex digits.
pub fn signer_key_from_hex(text: &str) -> Result<SignerKey> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut key).map_err(|_| Error::InvalidKey)?;
    Ok(key)
}
