use magic_multiaddr::*;

/// Code, length of value, string of my known protocols.
///
/// See https://github.com/multiformats/multicodec/blob/master/table.csv for more
const CODEC_CODES: &[(u64, usize, &str)] = &[
    (0x04, 4, "ip4"),
    (0x29, 16, "ip6"),
    (0x06, 2, "tcp"),
    (0x0111, 2, "udp"),
];

struct MyCodec;

impl MyCodec {
    fn encode() {}
}

impl Codec for MyCodec {
    fn decode<'a>(code: u64, input: &'a [u8]) -> Result<(Protocol<'a>, &'a [u8]), Error> {
        // The length of the value for each known code
        let value_len = CODEC_CODES
            .iter()
            .find_map(|&(c, s, _)| (c == code).then_some(s))
            .ok_or(Error::MissingValue)?;

        // Gets the value and the remaing bytes to be returned
        let (value, rest) = input
            .split_at_checked(value_len)
            .ok_or(Error::Insufficient)?;

        Ok((Protocol::new(code, false, value), rest))
    }
}

fn main() {
    println!("Hello, world!");
}
