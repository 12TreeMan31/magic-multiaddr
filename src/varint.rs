use crate::Error;

/// Gets length in bytes `n` would be after encoding
pub const fn varint_length(n: u64) -> usize {
    // Edge case where an underflow happens
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
pub fn varint_encode(mut n: u64, out: &mut [u8]) -> Result<usize, Error> {
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

pub fn varint_decode(input: &[u8]) -> Result<(u64, &[u8]), Error> {
    let mut n = 0u64;
    for (i, &x) in input.iter().enumerate() {
        if i == 9 && x != 0x01 {
            return Err(Error::Overflow);
        }

        let shift = i * 7;
        n |= ((x & 0x7F) as u64) << shift;

        if x & 0x80 == 0x00 {
            return Ok((n, &input[i + 1..]));
        }
    }

    Err(Error::Insufficient)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &[u8] = &[];

    #[test]
    fn normal_varint() {
        let mut buf = [0u8; 2];
        assert_eq!(varint_encode(150, &mut buf), Ok(2));
        assert_eq!(buf, [0x96, 0x01]);

        assert_eq!(varint_decode(&buf), Ok((150, EMPTY)));
    }
    #[test]
    fn zero_varint() {
        let mut buf = [0u8; 1];
        assert_eq!(varint_encode(0, &mut buf), Ok(1));
        assert_eq!(buf, [0x00]);

        assert_eq!(varint_decode(&buf), Ok((0, EMPTY)));
    }
    #[test]
    fn overflow_varint() {
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(varint_decode(&buf), Err(Error::Overflow));
    }
    #[test]
    fn max_varint() {
        let mut buf = [0u8; 10];
        assert_eq!(varint_encode(u64::MAX, &mut buf), Ok(10));
        assert_eq!(
            buf,
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
        );

        assert_eq!(varint_decode(&buf), Ok((u64::MAX, EMPTY)));
    }
    #[test]
    fn invalid_varint() {
        let buf = [0x80, 0x80];
        assert_eq!(varint_decode(&buf), Err(Error::Insufficient));
    }
}
