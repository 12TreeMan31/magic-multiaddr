use core::convert::From;
use core::iter::{FusedIterator, Iterator};
use core::marker::PhantomData;
use core::{error, fmt};

pub mod text;
mod varint;

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

/// Tells the parser if a given code has an associated value
#[derive(Debug, Clone, PartialEq)]
pub enum FrameValue {
    Empty,
    Fixed(u64),
    LengthPrefixed,
}

/// Trait that the user must implment in order to work with parsing logic
pub trait Codec {
    type Error: From<Error>;

    /// Converts a protocol code into a string
    fn code_to_name(code: u64) -> Result<&'static str, Self::Error>;
    /// Converts a protocol string into a code
    fn name_to_code(name: &str) -> Result<u64, Self::Error>;
    /// Returns the associated `FrameValue` for a given code
    fn frame(code: u64) -> Result<FrameValue, Self::Error>;

    /// Converts a human readable value `input` into a binary version `out`.
    fn encode_value(code: u64, input: &str, out: &mut [u8]) -> Result<usize, Self::Error>;
    /// Converts a binary value into a human readable string
    fn decode_value(code: u64, input: &[u8], out: &mut [u8]) -> Result<usize, Self::Error>;
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

            let buffered = written + 1 + name.len();
            if buffered >= out.len() {
                return Err(Error::Insufficient.into());
            }

            // Writes for example /ip4
            out[written] = b'/';
            written += 1;
            out[written..written + name.len()].copy_from_slice(name.as_bytes());
            written += name.len();

            if C::frame(proto.code())? != FrameValue::Empty {
                if written >= out.len() {
                    return Err(Error::Insufficient.into());
                }
                // This would then write /1.1.1.1
                out[written] = b'/';
                written += 1;
                written += C::decode_value(proto.code(), proto.value(), &mut out[written..])?;
            }
        }

        Ok(written)
    }
}

/// One frame in a multiaddr (ex. /ip4/1.1.1.1 or /udp/1234).
///
/// See https://multiformats.io/multiaddr/ for more info
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

/// Iterator over protocols in a multiaddr according to a codec.
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

        let (code, mut remaining) = match varint::varint_decode(self.buf) {
            Ok((c, r)) => (c, r),
            Err(e) => {
                // Clears the buffer to stop the iterator on next call
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
                let (n, r) = match varint::varint_decode(remaining) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::String;

    const IP4: u64 = 0x04;
    const UDP: u64 = 0x0111;
    const DNS: u64 = 0x35;
    const TLS: u64 = 0x01c0;

    const LOOKUP: &[(u64, FrameValue, &str)] = &[
        (IP4, FrameValue::Fixed(4), "ip4"),
        (UDP, FrameValue::Fixed(2), "udp"),
        (DNS, FrameValue::LengthPrefixed, "dns"),
        (TLS, FrameValue::Empty, "tls"),
    ];

    struct TestCodec;

    impl Codec for TestCodec {
        type Error = Error;

        fn code_to_name(code: u64) -> Result<&'static str, Self::Error> {
            LOOKUP
                .iter()
                .find(|(c, _, _)| *c == code)
                .map(|(_, _, n)| *n)
                .ok_or(Error::MissingValue)
        }

        fn name_to_code(name: &str) -> Result<u64, Self::Error> {
            LOOKUP
                .iter()
                .find(|(_, _, n)| *n == name)
                .map(|(c, _, _)| *c)
                .ok_or(Error::MissingValue)
        }

        fn frame(code: u64) -> Result<FrameValue, Self::Error> {
            LOOKUP
                .iter()
                .find(|(c, _, _)| *c == code)
                .map(|(_, f, _)| f.clone())
                .ok_or(Error::MissingValue)
        }

        fn encode_value(code: u64, input: &str, out: &mut [u8]) -> Result<usize, Self::Error> {
            match code {
                IP4 => {
                    let mut buf = [0u8; 4];
                    let mut parts = input.split('.');
                    for slot in &mut buf {
                        *slot = parts
                            .next()
                            .ok_or(Error::MissingValue)?
                            .parse()
                            .map_err(|_| Error::MissingValue)?;
                    }
                    if parts.next().is_some() {
                        return Err(Error::MissingValue);
                    }
                    if out.len() < 4 {
                        return Err(Error::Insufficient);
                    }
                    out[..4].copy_from_slice(&buf);
                    Ok(4)
                }
                UDP => {
                    let n: u16 = input.parse().map_err(|_| Error::MissingValue)?;
                    if out.len() < 2 {
                        return Err(Error::Insufficient);
                    }
                    out[..2].copy_from_slice(&n.to_be_bytes());
                    Ok(2)
                }
                DNS => {
                    let b = input.as_bytes();
                    if out.len() < b.len() {
                        return Err(Error::Insufficient);
                    }
                    out[..b.len()].copy_from_slice(b);
                    Ok(b.len())
                }
                TLS => Ok(0),
                _ => Err(Error::MissingValue),
            }
        }

        fn decode_value(code: u64, input: &[u8], out: &mut [u8]) -> Result<usize, Self::Error> {
            // Render binary value to text using format!, then copy.
            let s: String = match code {
                IP4 => {
                    if input.len() != 4 {
                        return Err(Error::MissingValue);
                    }
                    format!("{}.{}.{}.{}", input[0], input[1], input[2], input[3])
                }
                UDP => {
                    if input.len() != 2 {
                        return Err(Error::MissingValue);
                    }
                    format!("{}", u16::from_be_bytes([input[0], input[1]]))
                }
                DNS => std::str::from_utf8(input)
                    .map_err(|_| Error::MissingValue)?
                    .to_string(),
                TLS => String::new(),
                _ => return Err(Error::MissingValue),
            };
            if out.len() < s.len() {
                return Err(Error::Insufficient);
            }
            out[..s.len()].copy_from_slice(s.as_bytes());
            Ok(s.len())
        }
    }
}
