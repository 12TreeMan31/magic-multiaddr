use core::convert::From;
use core::{error, fmt};

pub mod binary;
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::*;
    use crate::text::*;

    use std::assert_matches;
    use std::sync::LazyLock;

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

    static SAMPLE_ADDR: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let addr = TextMultiaddr::new("/ip4/192.168.1.1/udp/8080/dns/example.com/tls");

        let mut buf = vec![0u8; 1024];

        let bytes = addr
            .decode_text::<TestCodec>(&mut buf)
            .expect("Unable to create sample data!");

        buf.truncate(bytes);
        buf
    });

    #[test]
    fn iterate_multiple_protocols() {
        let mut iter = Multiaddr::new(&SAMPLE_ADDR).iter::<TestCodec>();

        let ip4 = iter.next().unwrap().unwrap();
        assert_eq!(ip4.code(), IP4);
        assert_eq!(ip4.value(), &[192, 168, 1, 1]);

        let udp = iter.next().unwrap().unwrap();
        assert_eq!(udp.code(), UDP);
        assert_eq!(udp.value(), &[0x1F, 0x90]);

        let dns = iter.next().unwrap().unwrap();
        assert_eq!(dns.code(), DNS);
        assert_eq!(dns.value(), b"example.com");

        let tls = iter.next().unwrap().unwrap();
        assert_eq!(tls.code(), TLS);
        assert_eq!(tls.value(), &[]);

        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn missing_fixed_value() {
        let buf = [IP4 as u8, 192, 168, 1];

        let mut iter = Multiaddr::new(&buf).iter::<TestCodec>();

        assert_matches!(iter.next(), Some(Err(Error::MissingValue)));
        assert!(iter.next().is_none());
    }

    #[test]
    fn missing_length_prefix() {
        let buf = [DNS as u8];

        let mut iter = Multiaddr::new(&buf).iter::<TestCodec>();

        assert_matches!(iter.next(), Some(Err(Error::Insufficient)));
        assert!(iter.next().is_none());
    }

    #[test]
    fn truncated_length_prefixed_value() {
        let buf = [DNS as u8, 3, b'a', b'b'];

        let mut iter = Multiaddr::new(&buf).iter::<TestCodec>();

        assert_matches!(iter.next(), Some(Err(Error::MissingValue)));
        assert!(iter.next().is_none());
    }

    #[test]
    fn unknown_protocol() {
        let buf = [0x7F];

        let mut iter = Multiaddr::new(&buf).iter::<TestCodec>();

        assert_matches!(iter.next(), Some(Err(Error::MissingValue)));
        assert!(iter.next().is_none());
    }

    // Text encoding

    #[test]
    fn encode_full_text() {
        let expected = b"/ip4/192.168.1.1/udp/8080/dns/example.com/tls";

        let mut out = [0u8; 128];

        let written = Multiaddr::new(&SAMPLE_ADDR)
            .encode_text::<TestCodec>(&mut out)
            .unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(&out[..written], expected);
    }

    #[test]
    fn encode_text_exact_buffer() {
        let expected = b"/tls";
        let mut out = [0u8; 4];

        let written = Multiaddr::new(&[0xC0, 0x03])
            .encode_text::<TestCodec>(&mut out)
            .unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(&out, expected);
    }

    #[test]
    fn encode_text_insufficient_buffer() {
        let mut out = [0u8; 3];

        assert_eq!(
            Multiaddr::new(&[0xC0, 0x03]).encode_text::<TestCodec>(&mut out),
            Err(Error::Insufficient)
        );
    }
}
