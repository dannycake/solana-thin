//! What makes a block final in a proof: a certificate, and the parent links
//! from the block it certifies down to this one.

use solana_thin::merkle::Node;
use solana_thin::{BlockRef, FinalityCert, ParentLink};

/// A finality certificate and the chain of parents below it.
///
/// With no links the certificate is for the block itself. Otherwise each
/// link is the parent leaf of the block above it, newest first, and the last
/// one names the block this anchors. It is what the front of a proof holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// Certificate for the block, or for a descendant of it.
    pub certificate: FinalityCert,
    /// Parent links from the certified block down to the block.
    pub links: Vec<ParentLink>,
}

impl Anchor {
    /// The block this makes final: the certified one, or the last parent.
    pub fn block(&self) -> BlockRef {
        self.links
            .last()
            .map_or(self.certificate.block(), |link| link.parent)
    }

    /// The anchor's bytes, as the store keeps them: the certificate's length
    /// as a `u32` and its bytes ([`FinalityCert::to_bytes`]), a `u16` count,
    /// the links. `None` only for a list longer than its count can say.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let certificate = encode_certificate(&self.certificate)?;
        let mut out = u32::try_from(certificate.len())
            .ok()?
            .to_le_bytes()
            .to_vec();
        out.extend_from_slice(&certificate);
        out.extend_from_slice(&u16::try_from(self.links.len()).ok()?.to_le_bytes());
        for link in &self.links {
            out.extend_from_slice(&link.parent.slot.to_le_bytes());
            out.extend_from_slice(&link.parent.id);
            out.extend_from_slice(&link.fec_set_count.to_le_bytes());
            out.push(u8::try_from(link.path.len()).ok()?);
            for node in &link.path {
                out.extend_from_slice(node);
            }
        }
        Some(out)
    }

    /// Reads [`to_bytes`](Self::to_bytes) back. `None` unless the bytes are
    /// exactly one anchor.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader(bytes);
        let len = u32::from_le_bytes(reader.array()?);
        let certificate = decode_certificate(&reader.bytes(usize::try_from(len).ok()?)?)?;
        let count = u16::from_le_bytes(reader.array()?);
        let mut links = Vec::new();
        for _ in 0..count {
            let parent = read_block(&mut reader)?;
            let fec_set_count = u32::from_le_bytes(reader.array()?);
            let path_len = reader.array::<1>()?[0];
            let path = (0..path_len)
                .map(|_| reader.array::<20>())
                .collect::<Option<Vec<Node>>>()?;
            links.push(ParentLink {
                parent,
                fec_set_count,
                path,
            });
        }
        reader.0.is_empty().then_some(Self { certificate, links })
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    fn bytes(&mut self, len: usize) -> Option<Vec<u8>> {
        if self.0.len() < len {
            return None;
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(head.to_vec())
    }
}

fn read_block(reader: &mut Reader<'_>) -> Option<BlockRef> {
    Some(BlockRef {
        slot: u64::from_le_bytes(reader.array()?),
        id: reader.array()?,
    })
}

/// A certificate's bytes: [`FinalityCert::to_bytes`], the layout it has at
/// the front of a proof. A client decodes them with
/// [`FinalityCert::from_bytes`] and needs nothing from this crate.
pub fn encode_certificate(certificate: &FinalityCert) -> Option<Vec<u8>> {
    certificate.to_bytes().ok()
}

/// Reads [`encode_certificate`]'s bytes back. `None` unless they are exactly
/// one certificate. The result is unverified, like any certificate.
pub fn decode_certificate(bytes: &[u8]) -> Option<FinalityCert> {
    FinalityCert::from_bytes(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_thin::Aggregate;

    fn aggregate(n: u8, bitmap: usize) -> Aggregate {
        Aggregate {
            signature: [n; 96],
            bitmap: vec![n; bitmap],
        }
    }

    fn block(n: u8) -> BlockRef {
        BlockRef {
            slot: 1_000 + u64::from(n),
            id: [n; 32],
        }
    }

    fn certificates() -> Vec<FinalityCert> {
        vec![
            FinalityCert::Fast {
                block: block(1),
                notar: aggregate(2, 86),
            },
            FinalityCert::Slow {
                block: block(3),
                finalize: aggregate(4, 0),
                notar: aggregate(5, 300),
            },
        ]
    }

    #[test]
    fn a_certificate_survives_its_bytes_and_nothing_else_reads_as_one() {
        for certificate in certificates() {
            let bytes = encode_certificate(&certificate).unwrap();
            assert_eq!(decode_certificate(&bytes), Some(certificate));
            assert_eq!(decode_certificate(&bytes[..bytes.len() - 1]), None);
            let mut longer = bytes.clone();
            longer.push(0);
            assert_eq!(decode_certificate(&longer), None);
            let mut other_kind = bytes;
            other_kind[0] = 2;
            assert_eq!(decode_certificate(&other_kind), None);
        }
        assert_eq!(decode_certificate(&[]), None);
    }

    #[test]
    fn a_certificate_is_laid_out_as_in_a_proof() {
        let bytes = encode_certificate(&certificates()[0]).unwrap();
        assert_eq!(bytes.len(), 1 + 8 + 32 + 96 + 2 + 86);
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1..9], 1_001u64.to_le_bytes());
        assert_eq!(bytes[9..41], [1; 32]);
        assert_eq!(bytes[41..137], [2; 96]);
        assert_eq!(bytes[137..139], 86u16.to_le_bytes());
    }

    #[test]
    fn an_anchor_survives_its_bytes_and_names_the_last_parent() {
        for certificate in certificates() {
            let own = Anchor {
                certificate: certificate.clone(),
                links: vec![],
            };
            assert_eq!(own.block(), certificate.block());
            let below = Anchor {
                certificate,
                links: vec![
                    ParentLink {
                        parent: block(8),
                        fec_set_count: 23,
                        path: vec![[1; 20]; 5],
                    },
                    ParentLink {
                        parent: block(7),
                        fec_set_count: 1,
                        path: vec![[2; 20]],
                    },
                ],
            };
            assert_eq!(below.block(), block(7));
            for anchor in [own, below] {
                let bytes = anchor.to_bytes().unwrap();
                assert_eq!(Anchor::from_bytes(&bytes), Some(anchor));
                assert_eq!(Anchor::from_bytes(&bytes[..bytes.len() - 1]), None);
                let mut longer = bytes;
                longer.push(0);
                assert_eq!(Anchor::from_bytes(&longer), None);
            }
        }
    }
}
