use crate::Error;
use core::iter::{FusedIterator, Iterator};
use core::marker::PhantomData;
use core::str;

pub trait TextCodec {
    fn code_from_str(input: &str) -> Result<u64, Error>;
    fn has_value(code: u64) -> Result<bool, Error>;
}

pub struct TextProtocol<'a> {
    pub code: u64,
    pub value: Option<&'a str>,
}

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

        let code = match C::code_from_str(name) {
            Ok(x) => x,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };
        let value = if C::has_value(code).unwrap() {
            // You need proper error handling here
            Some(self.tokens.next()?)
        } else {
            None
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
        (0x29, true, "ip6"),
        (0x06, true, "tcp"),
        (0x0111, true, "udp"),
        (0x01c0, false, "tls"),
    ];
    struct BasicCodec;
    impl TextCodec for BasicCodec {
        fn code_from_str(input: &str) -> Result<u64, Error> {
            SPEC.iter()
                .find(|(_, _, s)| *s == input)
                .map(|(x, _, _)| *x)
                .ok_or(Error::Insufficient)
        }
        fn has_value(code: u64) -> Result<bool, Error> {
            SPEC.iter()
                .find(|(c, _, _)| *c == code)
                .map(|(_, f, _)| *f)
                .ok_or(Error::Insufficient)
        }
    }

    #[test]
    fn basic() {
        let addr = "/ip4/1.1.1.1";
        let mut iter: TextIter<'_, BasicCodec> = TextIter::new(addr);

        let proto = iter.next().unwrap().unwrap();

        assert_eq!(proto.code, 0x04);
        assert_eq!(proto.value, Some("1.1.1.1"));
    }

    #[test]
    fn code_str() {
        assert_eq!(
            BasicCodec::code_from_str("ip6").expect("Not a valid code!"),
            0x29
        );
    }

    #[test]
    fn is_value() {
        assert_eq!(BasicCodec::has_value(0x04).unwrap(), true);
    }
}
