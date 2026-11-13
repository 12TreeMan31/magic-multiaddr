use crate::*;
use core::iter::{FusedIterator, Iterator};
use core::marker::PhantomData;

/// Containter for the binary data that makes up a multiaddr.
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

    /// Uses `Codec` to parse the given multiaddr into the `out` buffer. The buffer will then contain a human readable version
    /// of the multiaddr. Returns the number of bytes written on success.
    pub fn encode_text<C: Codec>(&self, out: &mut [u8]) -> Result<usize, C::Error> {
        let mut written = 0;
        for proto in self.iter::<C>() {
            let proto = proto?;

            let name = C::code_to_name(proto.code())?;

            let buffered = written + 1 + name.len();
            if buffered > out.len() {
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
            Err(e) => {
                self.buf = &[];
                return Some(Err(e));
            }
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
