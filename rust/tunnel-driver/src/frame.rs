//! A bounded view into a contiguous packet buffer.
//!
//! Encapsulation drivers build headers by calling [`Frame::prepend`] and
//! writing into the returned slice.  Decapsulation drivers parse the outer
//! packet and call [`Frame::advance`] to expose the inner Ethernet frame.

use crate::driver::DriverError;

/// A mutable window inside a packet buffer.
///
/// `off` is the byte offset of the first header byte and `len` is the number
/// of bytes from that offset to the end of the packet.  Bytes before `off`
/// are reserved headroom.
pub struct Frame<'a> {
    buf: &'a mut [u8],
    off: usize,
    len: usize,
}

impl<'a> Frame<'a> {
    /// Create a frame view over `buf[off..off + len]`.
    pub fn new(buf: &'a mut [u8], off: usize, len: usize) -> Result<Self, DriverError> {
        let end = off.checked_add(len).ok_or(DriverError::FrameBounds)?;
        if end > buf.len() {
            return Err(DriverError::FrameBounds);
        }
        Ok(Self { buf, off, len })
    }

    /// Wrap the entire buffer.
    pub fn whole(buf: &'a mut [u8]) -> Self {
        let len = buf.len();
        Self { buf, off: 0, len }
    }

    #[inline]
    pub fn offset(&self) -> usize {
        self.off
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// The current packet bytes.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf[self.off..self.off + self.len]
    }

    /// The current packet bytes, mutably.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.off..self.off + self.len]
    }

    /// Reserve `n` bytes in front of the current packet and return them.
    ///
    /// The returned slice is intentionally not cleared; drivers overwrite
    /// every header byte they use.
    pub fn prepend(&mut self, n: usize) -> Result<&mut [u8], DriverError> {
        if n > self.off {
            return Err(DriverError::BufferTooSmall);
        }
        let start = self.off - n;
        let end = self.off;
        self.off = start;
        self.len += n;
        Ok(&mut self.buf[start..end])
    }

    /// Remove `n` bytes from the front of the packet (outer header parsing).
    pub fn advance(&mut self, n: usize) -> Result<(), DriverError> {
        if n > self.len {
            return Err(DriverError::FrameBounds);
        }
        self.off += n;
        self.len -= n;
        Ok(())
    }

    /// Remove `n` bytes from the end.
    pub fn trim_end(&mut self, n: usize) -> Result<(), DriverError> {
        if n > self.len {
            return Err(DriverError::FrameBounds);
        }
        self.len -= n;
        Ok(())
    }

    /// Write bytes at an absolute packet offset.
    pub fn write_at(&mut self, at: usize, bytes: &[u8]) -> Result<(), DriverError> {
        let end = at
            .checked_add(bytes.len())
            .ok_or(DriverError::FrameBounds)?;
        if end > self.len {
            return Err(DriverError::FrameBounds);
        }
        self.data_mut()[at..end].copy_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepend_and_advance() {
        let mut buf = [0u8; 32];
        let mut f = Frame::new(&mut buf, 16, 4).unwrap();
        f.data_mut().copy_from_slice(&[1, 2, 3, 4]);
        let hdr = f.prepend(4).unwrap();
        hdr.copy_from_slice(&[9, 8, 7, 6]);
        assert_eq!(f.offset(), 12);
        assert_eq!(f.len(), 8);
        assert_eq!(f.data(), &[9, 8, 7, 6, 1, 2, 3, 4]);
        f.advance(4).unwrap();
        assert_eq!(f.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn bounds_are_checked() {
        let mut buf = [0u8; 8];
        assert!(Frame::new(&mut buf, 4, 5).is_err());
        let mut f = Frame::new(&mut buf, 0, 8).unwrap();
        assert!(f.prepend(1).is_err());
        assert!(f.advance(9).is_err());
    }
}
