use crate::Error;

/// Gets length in bytes `n` would be after encoding
pub const fn varint_length(n: u64) -> usize {
    // Edge case where an overflow happens
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
