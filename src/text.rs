use crate::varint;
use crate::{Codec, Error, FrameValue};
use core::iter::{FusedIterator, Iterator};
use core::marker::PhantomData;
use core::str;

pub struct TextMultiaddr<'a> {
    buf: &'a str,
}

impl<'a> TextMultiaddr<'a> {
    pub const fn new(buf: &'a str) -> Self {
        TextMultiaddr { buf }
    }

    pub fn iter<C: Codec>(&self) -> TextIter<'a, C> {
        TextIter::new(self.buf)
    }

    pub fn decode_text<C: Codec>(&self, out: &mut [u8]) -> Result<usize, C::Error> {
        let mut written = 0;
        for proto in self.iter::<C>() {
            let proto = proto?;

            let length = varint::varint_length(proto.code());
            varint::varint_encode(proto.code(), &mut out[written..])?;
            written += length;

            let Some(value) = proto.value() else {
                continue;
            };

            let bytes = C::encode_value(proto.code(), value, &mut out[written..])?;
            let frame = C::frame(proto.code())?;

            if frame == FrameValue::LengthPrefixed {
                let length = varint::varint_length(bytes as u64);
                out.copy_within(written..written + bytes, written + length);
                varint::varint_encode(bytes as u64, &mut out[written..written + length])?;
                written += length;
            }

            written += bytes;
        }

        Ok(written)
    }
}

pub struct TextProtocol<'a> {
    code: u64,
    value: Option<&'a str>,
}

impl<'a> TextProtocol<'a> {
    pub(crate) const fn new(code: u64, value: Option<&'a str>) -> Self {
        Self { code, value }
    }

    pub fn code(&self) -> u64 {
        self.code
    }

    pub fn value(&self) -> Option<&str> {
        self.value
    }
}

/// Iterator that converts a string into `TextProtocol`s
pub struct TextIter<'a, C> {
    tokens: str::Split<'a, char>,
    done: bool,
    codec: PhantomData<fn() -> C>,
}

impl<'a, C: Codec> TextIter<'a, C> {
    pub fn new(multiaddr: &'a str) -> Self {
        let mut tokens = multiaddr.split('/');
        // Gets ride of the first / in a multiaddr
        if multiaddr.starts_with('/') {
            tokens.next();
        }

        Self {
            tokens,
            done: false,
            codec: PhantomData,
        }
    }
}

impl<'a, C: Codec> Iterator for TextIter<'a, C> {
    type Item = Result<TextProtocol<'a>, C::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // Look into replacing this call with fuse
        let name = match self.tokens.next()? {
            "" => return Some(Err(Error::NotMinimal.into())),
            n => n,
        };

        let Ok(code) = C::name_to_code(name) else {
            self.done = true;
            return Some(Err(Error::MissingValue.into()));
        };

        let frame = match C::frame(code) {
            Ok(f) => f,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };

        let has_value = frame != FrameValue::Empty;

        let value = match has_value {
            true => Some(self.tokens.next()?),
            false => None,
        };

        Some(Ok(TextProtocol::new(code, value)))
    }
}

impl<'a, C: Codec> FusedIterator for TextIter<'a, C> {}
