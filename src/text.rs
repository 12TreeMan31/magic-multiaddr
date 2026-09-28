use crate::Error;
use core::iter::{FusedIterator, Iterator};
use core::marker::PhantomData;
use core::str;

pub trait TextCodec {
    fn code_from_str(input: &str) -> Result<u64, Error>;
    fn has_value(code: u64) -> bool;
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
        let value = if C::has_value(code) {
            // You need proper error handling here
            Some(self.tokens.next()?)
        } else {
            None
        };

        Some(Ok(TextProtocol { code, value }))
    }
}

impl<'a, C: TextCodec> FusedIterator for TextIter<'a, C> {}
