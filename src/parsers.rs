use std::str;
use nom::*;
use super::*;

static PEM_START: &'static [u8] = b"-----BEGIN ";
static PEM_END: &'static [u8] = b"-----END";

pub fn pem_dashed_string(i: &[u8]) -> ::nom::IResult<&[u8], &str> {
    let mut found = 0;
    for pos in 0..i.len() {
        let b = i[pos];
        if b == 13 { return ::nom::IResult::Error(::nom::ErrorKind::CrLf); }
        if b == 45 { found += 1 } else { found = 0 }
        if found == 5 {
            match str::from_utf8(&i[..(pos - 4)]) {
                Ok(s) => return ::nom::IResult::Done(&i[(pos + 1)..], s),
                Err(_) => return ::nom::IResult::Error(::nom::ErrorKind::Alpha)
            }
        }
    }
    ::nom::IResult::Incomplete(::nom::Needed::Size(5 - found))
}

named!(pub pem_begin<&str>, do_parse!(
        tag!(PEM_START) >>
        s: pem_dashed_string >>
        spaces >>
        line_ending >>
        (s)
    ));
named!(pub spaces, take_while!(is_space));
named!(pub pem_footer<&str>, do_parse!(
        tag!(PEM_END) >>
        s: pem_dashed_string >>
        spaces >>
        take_while!(is_nl) >>
        (s)
    ));

pub fn is_nl(c: u8) -> bool { c == 10 }
pub fn base64(input: &[u8]) -> ::nom::IResult<&[u8], Vec<u8>> {
    let mut ret: Vec<u8> = Vec::with_capacity(input.len() / 4 * 3);
    let mut reg = 0u16;
    let mut bits = 0u8;
    let mut pos = 0;
    while pos < input.len() {
        let b = STANDARD_DECODE[input[pos] as usize];
        if b == INVALID { break }
        pos += 1;
        if b == IGNORE { continue }
        reg = (reg << 6) | b as u16;
        bits += 6;
        if bits >= 8 {
            bits %= 8;
            ret.push((reg >> bits) as u8);
        }
    }
    while pos < input.len() && input[pos] == 61 { pos += 1 } // remove the padding
    ::nom::IResult::Done(&input[pos..], ret)
}

pub fn no_pem_headers(i: &[u8]) -> ::nom::IResult<&[u8], Vec<HeaderEntry>> {
    ::nom::IResult::Done(i, Vec::new())
}

named!(pub str_end_of_line<String>, do_parse!(
    s: map_res!(map_res!(take_till!(is_nl),str::from_utf8),str::FromStr::from_str) >>
    take!(1) >>
    (s)
    ));

named!(pub str_second_line<String>, do_parse!(
    tag!(" ") >>  // all following lines of a header value has to start with a space
    spaces >>
    s: str_end_of_line >>
    (s)
    ));



named!(pub multi_line<String>, do_parse!(
    s1: str_end_of_line >>
    s: fold_many1!(str_second_line, s1, |a: String,b| {
        format!("{}{}",a,b)
     }) >>
    (s)
    ));

named!(pub pem_block<Block>, do_parse!(
    block_type: pem_begin >>
    headers: alt!(pem_headers|no_pem_headers) >>
    data : ws!(base64) >>
    end : pem_footer >>
    (Block{block_type, headers, data})
    ));

named!(pub pem_blocks<Vec<Block>>, many1!(pem_block));

pub const INVALID: u8 = 255;
pub const IGNORE: u8 = 254;

pub const STANDARD_DECODE: &'static [u8; 256] = &[
    INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, IGNORE, IGNORE, INVALID, INVALID, IGNORE, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, IGNORE, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, 62, INVALID, INVALID, INVALID, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, // input 255 (0xFF)
];
#[allow(dead_code)]
pub const URL_SAFE_ENCODE: &'static [u8; 64] = &[
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, // input 63 (0x3F) => '_' (0x5F)
];
#[allow(dead_code)]
pub const URL_SAFE_DECODE: &'static [u8; 256] = &[
    INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, IGNORE, IGNORE, INVALID, INVALID, IGNORE, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, IGNORE, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, 62, INVALID, INVALID, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, INVALID, INVALID, INVALID, INVALID, 63, INVALID, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, // input 255 (0xFF)
];