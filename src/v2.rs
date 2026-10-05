use crate::varint_decode;
use core::convert::From;
use core::iter::{FusedIterator, Iterator};
use core::marker::PhantomData;
use core::{error, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Frame value not present
    MissingValue,
    /// Not enough input bytes
    Insufficient,
    /// Input bytes exceed maximum
    Overflow,
    /// Encoding is not minimal
    NotMinimal,
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
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingValue => f.write_str("frame value not present"),
            Error::Insufficient => f.write_str("not enough input bytes"),
            Error::Overflow => f.write_str("input bytes exceed maximum"),
            Error::NotMinimal => f.write_str("encoding is not minimal"),
        }
    }
}

impl error::Error for Error {}

pub enum FrameValue {
    Empty,
    Fixed(u64),
    LengthPrefixed,
}

pub trait Codec {
    type Error: From<Error>;

    fn code_to_name(code: u64) -> Result<&'static str, Self::Error>;
    fn name_to_code(name: &str) -> Result<u64, Self::Error>;
    fn frame(code: u64) -> Result<FrameValue, Self::Error>;

    fn value_to_bytes(code: u64, input: &str, out: &mut [u8]) -> Result<usize, Self::Error>;
    fn bytes_to_value(code: u64, input: &[u8], out: &mut [u8]) -> Result<usize, self::Error>;
}

pub struct Multiaddr<'a> {
    buf: &'a [u8],
}

impl<'a> Multiaddr<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Multiaddr { buf }
    }

    pub fn iter<C: Codec>(&self) -> ProtocolIter<'a, C> {
        ProtocolIter::new(self.buf)
    }

    pub fn encode_text<C: Codec>(&self, out: &mut [u8]) -> Result<usize, C::Error> {
        let mut written = 0;
        for proto in self.iter::<C>() {
            let proto = proto?;

            let name = C::code_to_name(proto.code())?;

            let buffered = written + 2 + name.len();
            if buffered >= out.len() {
                return Err(Error::Insufficient.into());
            }

            out[written] = b'/';
            written += 1;
            out[written..written + name.len()].copy_from_slice(name.as_bytes());
            written += name.len();
            out[written] = b'/';
            written += 1;

            match C::frame(proto.code())? {
                FrameValue::Empty => {}
                _ => {
                    if written >= out.len() {
                        return Err(Error::Insufficient.into());
                    }
                    out[written] = b'/';
                    written += 1;
                    written += C::bytes_to_value(proto.code(), proto.value(), &mut out[written..])?;
                }
            };
        }

        Ok(written)
    }
}

pub struct Protocol<'a> {
    code: u64,
    value: &'a [u8],
}

impl<'a> Protocol<'a> {
    pub(crate) const fn new(code: u64, value: &'a [u8]) -> Self {
        Self { code, value }
    }

    pub const fn code(&self) -> u64 {
        self.code
    }

    pub const fn value(&self) -> &[u8] {
        self.value
    }
}

pub struct ProtocolIter<'a, C> {
    buf: &'a [u8],
    codec: PhantomData<fn() -> C>,
}

impl<'a, C: Codec> ProtocolIter<'a, C> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            codec: PhantomData,
        }
    }
}

impl<'a, C: Codec> Iterator for ProtocolIter<'a, C> {
    type Item = Result<Protocol<'a>, C::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }

        let (code, mut remaining) = match varint_decode::u64(self.buf) {
            Ok((c, r)) => (c, r),
            Err(e) => {
                self.buf = &[];
                let e: Error = e.into();
                return Some(Err(e.into()));
            }
        };

        let frame = match C::frame(code) {
            Ok(f) => f,
            Err(e) => return Some(Err(e)),
        };

        let length: usize = match frame {
            FrameValue::Empty => 0,
            FrameValue::Fixed(n) => n as usize,
            FrameValue::LengthPrefixed => {
                let (n, r) = match varint_decode::u64(remaining) {
                    Ok((n, r)) => (n, r),
                    Err(e) => {
                        self.buf = &[];
                        let e: Error = e.into();
                        return Some(Err(e.into()));
                    }
                };
                remaining = r;
                n as usize
            }
        };

        match remaining.get(..length) {
            Some(v) => {
                self.buf = &remaining[length..];
                Some(Ok(Protocol::new(code, v)))
            }
            None => {
                self.buf = &[];
                Some(Err(Error::MissingValue.into()))
            }
        }
    }
}

impl<'a, C: Codec> FusedIterator for ProtocolIter<'a, C> {}
