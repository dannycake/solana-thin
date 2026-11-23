//! Bounds-checked byte reading and writing.
//!
//! Every length that comes off the wire is checked against the bytes that are
//! actually left before anything is allocated, so a hostile proof cannot make
//! the verifier reserve memory it will never fill.

use crate::error::{Error, Result};

/// A cursor over untrusted bytes. Every read is bounds checked.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// The bytes read since `start`, a position taken earlier.
    pub(crate) fn span(&self, start: usize) -> &'a [u8] {
        &self.buf[start..self.pos]
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Solana's "short vec" length: 1 to 3 bytes, 7 bits each, low bits first.
    ///
    /// Only the canonical encoding is accepted, exactly as validators do: no
    /// padding with zero continuation bytes, and nothing above `u16::MAX`.
    pub(crate) fn short_u16(&mut self) -> Result<u16> {
        let mut value: u32 = 0;
        for i in 0..3 {
            let byte = self.u8()?;
            let low = u32::from(byte & 0x7f);
            value |= low << (7 * i);
            if byte & 0x80 == 0 {
                if i > 0 && byte == 0 {
                    return Err(Error::Malformed("short vec length"));
                }
                return u16::try_from(value).map_err(|_| Error::Malformed("short vec length"));
            }
        }
        Err(Error::Malformed("short vec length"))
    }

    /// Reads a count that says how many items of at least `min_item_size`
    /// bytes follow, refusing counts the remaining input cannot hold.
    pub(crate) fn bounded_count(&mut self, count: usize, min_item_size: usize) -> Result<usize> {
        let need = count.checked_mul(min_item_size).ok_or(Error::Truncated)?;
        if need > self.remaining() {
            return Err(Error::Truncated);
        }
        Ok(count)
    }
}

/// Appends little-endian fields to a byte vector.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    pub(crate) buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub(crate) fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
}

/// Writes a short vec length. Used by the test builders.
#[cfg(any(test, feature = "testkit"))]
pub(crate) fn write_short_u16(out: &mut Vec<u8>, mut value: u16) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_u16_round_trips_and_rejects_padding() {
        for v in [0u16, 1, 127, 128, 255, 16383, 16384, u16::MAX] {
            let mut buf = Vec::new();
            write_short_u16(&mut buf, v);
            let mut r = Reader::new(&buf);
            assert_eq!(r.short_u16().unwrap(), v);
            r.finish().unwrap();
        }
        // 0x80 0x00 is a padded zero; validators reject it and so do we.
        assert!(Reader::new(&[0x80, 0x00]).short_u16().is_err());
        // Three continuation bytes never terminate.
        assert!(Reader::new(&[0x80, 0x80, 0x80]).short_u16().is_err());
        // 0xff 0xff 0x04 is 65536 + 65535: above u16.
        assert!(Reader::new(&[0xff, 0xff, 0x04]).short_u16().is_err());
        assert!(Reader::new(&[0x80]).short_u16().is_err());
    }

    #[test]
    fn reads_are_bounds_checked() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert_eq!(r.u32(), Err(Error::Truncated));
        assert_eq!(r.bounded_count(2, 1), Err(Error::Truncated));
        assert_eq!(r.finish(), Err(Error::TrailingBytes));
    }
}
