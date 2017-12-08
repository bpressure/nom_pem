use std::fmt;
use super::HeaderEntry;

pub fn write_headers(f: &mut fmt::Formatter, headers: &Vec<HeaderEntry>) -> fmt::Result {
    if headers.len() > 0 {
        for header in headers.iter() {
            write!(f, "{}\n", header)?;
        }
        write!(f, "\n")
    } else {
        Ok(())
    }
}

pub fn write_base64(f: &mut fmt::Formatter, data: &[u8], width: usize) -> fmt::Result {
    let mut pos = 0;
    let mut register = 0usize;
    let mut bits = 0u8;
    let mut out = 0;

    let length = data.len();
    while pos < length {
        register = (register << 8) | data[pos] as usize;
        pos += 1;
        bits += 8;
        while bits >= 6 {
            let v6 = register >> (bits - 6) & 0b111111;
            let c = STANDARD_ENCODE[v6] as char;
            write!(f, "{}", c)?;
            out += 1;
            if out == width {
                write!(f, "\n")?;
                out = 0;
            }
            bits -= 6;
            register &= 0b111111;
        }
    }
    if bits > 0 {
        register = register << (6 - bits) & 0b111111;
        let c = STANDARD_ENCODE[register] as char;
        write!(f, "{}=", c)?;
        out += 2;
        if bits == 2 {
            write!(f, "=")?;
            out += 1;
        }
    }
    if out > 0 {
        write!(f, "\n")
    } else {
        Ok(())
    }
}

pub const STANDARD_ENCODE: &'static [u8; 64] = &[
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47, // input 63 (0x3F) => '/' (0x2F)
];