use crate::Error;
use core::iter::{FusedIterator, Iterator};
use core::marker::PhantomData;
use core::str;

pub trait TextCodec {
    /// Takes in a string protocol id and returns the equivalent integer code and
    /// whether or not it requires a value field. Any error is assumed to invalite
    /// the whole multiaddr.
    fn token_info(input: &str) -> Result<(u64, bool), ()>;
}

pub struct TextProtocol<'a> {
    code: u64,
    value: Option<&'a str>,
}

impl<'a> TextProtocol<'a> {
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

impl<'a, C: TextCodec> TextIter<'a, C> {
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

impl<'a, C: TextCodec> Iterator for TextIter<'a, C> {
    type Item = Result<TextProtocol<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // Look into replacing this call with fuse
        let name = match self.tokens.next()? {
            "" => return Some(Err(Error::NotMinimal)),
            n => n,
        };

        let Ok((code, has_value)) = C::token_info(name) else {
            self.done = true;
            return Some(Err(Error::Invalid));
        };

        let value = match has_value {
            true => Some(self.tokens.next()?),
            false => None,
        };

        Some(Ok(TextProtocol { code, value }))
    }
}

impl<'a, C: TextCodec> FusedIterator for TextIter<'a, C> {}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &[(u64, bool, &str)] = &[
        (0x04, true, "ip4"),
        (0x0111, true, "udp"),
        (0x01c0, false, "tls"),
    ];
    struct BasicCodec;
    impl TextCodec for BasicCodec {
        fn token_info(input: &str) -> Result<(u64, bool), ()> {
            SPEC.iter()
                .find(|(_, _, s)| *s == input)
                .map(|(x, y, _)| (*x, *y))
                .ok_or(())
        }
    }

    #[test]
    fn basic() {
        let addr = "/ip4/1.1.1.1/udp/1234/tls";
        let mut iter: TextIter<'_, BasicCodec> = TextIter::new(addr);

        let proto = iter.next().unwrap().unwrap();
        assert_eq!(proto.code, 0x04);
        assert_eq!(proto.value, Some("1.1.1.1"));

        let proto = iter.next().unwrap().unwrap();
        assert_eq!(proto.code, 0x0111);
        assert_eq!(proto.value, Some("1234"));

        let proto = iter.next().unwrap().unwrap();
        assert_eq!(proto.code, 0x01c0);
        assert_eq!(proto.value, None);
    }
}
