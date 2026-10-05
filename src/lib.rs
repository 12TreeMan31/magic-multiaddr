#![no_std]

use core::convert::From;
use core::iter::{FusedIterator, Iterator};
use core::marker::PhantomData;
use unsigned_varint::decode as varint_decode;

pub mod text;
pub mod v2;

#[derive(Debug)]
pub enum Error {
    /// Protocol could not find expected value
    MissingValue,
    /// Not enough input bytes
    Insufficient,
    /// Input bytes exceed maximum
    Overflow,
    /// Encoding is not minimal
    NotMinimal,
    /// Catch all error
    Invalid,
}

/// Gets length in bytes `n` would be after encoding
const fn varint_length(n: u64) -> usize {
    // Edge case where an overflow happens
    if n == 0 {
        return 1;
    }

    // Gets the number of goups of 7 we need counting from 0
    // Since it starts counting at 0 we need to add 1
    ((63 - n.leading_zeros()) / 7 + 1) as usize
}

/// Encodes `n` as a uvarint and writes the result to `out`. Fails if length
/// of `out` < `varint_length(n)`; nothing will be written to `out`.
///
/// On success returns number of bytes written
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
            _ => Error::Invalid,
        }
    }
}

/// Trait that the user must implment in order to work with parsing logic
pub trait Codec {
    /// A `Codec` takes the current protocol `code` and the raw `input` of bytes from a multiaddr.
    /// After decoding, returns the built protocal and the remaning `input` bytes.
    fn decode<'a>(code: u64, input: &'a [u8]) -> Result<(Protocol<'a>, &'a [u8]), Error>;
}

/// One protocol in a multiaddr (ex. /ip4/1.1.1.1 or /udp/1234).
///
/// See https://multiformats.io/multiaddr/ for more info
pub struct Protocol<'a> {
    code: u64,
    /// False mean we know the length of the data, true means there is a size prefix on the data.
    length_prefix: bool,
    value: &'a [u8],
}

impl<'a> Protocol<'a> {
    pub fn new(code: u64, length_prefix: bool, value: &'a [u8]) -> Self {
        Self {
            code,
            length_prefix,
            value,
        }
    }

    pub fn code(&self) -> u64 {
        self.code
    }

    pub fn value(&self) -> &[u8] {
        self.value
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

    /// Converts self into a byte stream that can be sent over the network.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let length = self.encode_len();
        if length > out.len() {
            return Err(Error::Insufficient);
        }

        let mut offset = varint_encode(self.code, out)?;
        if self.length_prefix {
            offset += varint_encode(self.value.len() as u64, &mut out[offset..])?;
        }

        out[offset..offset + self.value.len()].copy_from_slice(self.value);

        Ok(length)
    }
}

/// Iterator over protocols in a multiaddr according to a codec.
pub struct ProtocolIter<'a, C> {
    buf: &'a [u8],
    codec: PhantomData<fn() -> C>,
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
                // Note for later we might want to keep the remainder value for error recovory
                self.buf = &[];
                Some(Err(e))
            }
        }
    }
}

impl<'a, C: Codec> FusedIterator for ProtocolIter<'a, C> {}
