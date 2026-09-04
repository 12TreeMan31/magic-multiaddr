#![no_std]

use core::convert::From;
use core::iter::Iterator;
use core::marker::PhantomData;
use unsigned_varint::decode as varint_decode;

pub enum Error {
    /// Protocol could not find expected value
    MissingValue,
    /// Not enough input bytes
    Insufficient,
    /// Input bytes exceed maximum
    Overflow,
    /// Encoding is not minimal
    NotMinimal,
}

const fn varint_length(n: u64) -> usize {
    // Edge case where an overflow happens
    if n == 0 {
        return 1;
    }

    // Gets the number of goups of 7 we need counting from 0
    // Since it starts counting at 0 we need to add 1
    ((63 - n.leading_zeros()) / 7 + 1) as usize
}

/// Take u64 and encodes it into out, returns bytes written
fn varint_encode(mut n: u64, out: &mut [u8]) -> Result<usize, Error> {
    let length = varint_length(n);
    if length > out.len() {
        return Err(Error::Insufficient);
    }

    let mut i = 0;
    loop {
        // Extracts the first 7 bits
        let b = (n & 0x7f) as u8;
        n >>= 7;

        if n == 0 {
            out[i] = b;
            break;
        } else {
            // Marks the 8th bit
            out[i] = b | 0x80;
            i += 1;
        }
    }

    Ok(length)
}

impl From<varint_decode::Error> for Error {
    fn from(value: varint_decode::Error) -> Self {
        match value {
            varint_decode::Error::Insufficient => Error::Insufficient,
            varint_decode::Error::NotMinimal => Error::NotMinimal,
            varint_decode::Error::Overflow => Error::Overflow,
            _ => unreachable!(),
        }
    }
}

pub trait Codec {
    /// A `Codec` takes the current protocol `code` and the raw `input` of bytes from a multiaddr.
    /// After decoding, returns the built protocal and the remaning `input` bytes.
    fn decode<'a>(code: u64, input: &'a [u8]) -> Result<(Protocol<'a>, &'a [u8]), Error>;
}

pub struct Protocol<'a> {
    pub code: u64,
    pub length_prefix: bool,
    pub value: &'a [u8],
}

impl<'a> Protocol<'a> {
    pub fn new(code: u64, length_prefix: bool, value: &'a [u8]) -> Self {
        Self {
            code,
            length_prefix,
            value,
        }
    }

    /// Returns the number of bytes needed to encode the protocol
    pub fn encode_len(&self) -> usize {
        let mut length: usize = varint_length(self.code) + self.value.len();

        // Length is encoded as varint. See the spec
        if self.length_prefix {
            length += varint_length(self.value.len() as u64);
        }

        length
    }
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let length = self.encode_len();
        if length > out.len() {
            return Err(Error::Insufficient);
        }

        let mut offset = varint_encode(self.code, out)?;
        if self.length_prefix {
            offset += varint_encode(self.value.len() as u64, &mut out[offset..])?;
        }

        for (x, y) in self.value.iter().zip(out[offset..].iter_mut()) {
            *y = *x;
        }

        Ok(length)
    }
}

pub struct ProtocolIter<'a, C> {
    buf: &'a [u8],
    codec: PhantomData<C>,
}

impl<'a, C: Codec> ProtocolIter<'a, C> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            codec: PhantomData,
        }
    }
}

impl<'a, C: Codec> Iterator for ProtocolIter<'a, C> {
    type Item = Result<Protocol<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }

        let (code, remaining) = match varint_decode::u64(self.buf) {
            Ok((c, r)) => (c, r),
            Err(e) => {
                // Clears the buffer to stop the iterator on next call
                self.buf = &[];
                return Some(Err(e.into()));
            }
        };

        match C::decode(code, remaining) {
            Ok((p, buf)) => {
                self.buf = buf;
                Some(Ok(p))
            }
            Err(e) => {
                // Note for later we might want to keep the remainder value
                self.buf = &[];
                Some(Err(e))
            }
        }
    }
}
