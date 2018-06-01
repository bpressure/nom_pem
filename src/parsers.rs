static PEM_START: &'static [u8] = b"-----BEGIN ";
static PEM_END: &'static [u8] = b"-----END ";

use nom::{IResult, Err, Needed, ErrorKind, is_space, line_ending};
use super::{Block, base64, HeaderEntry};
use super::headers::pem_headers;
#[cfg(not(std))]
use core::str::from_utf8;
#[cfg(std)]
use std::str::from_utf8;

fn pem_dashed_string(i: &[u8]) -> IResult<&[u8], &str> {
    let mut found = 0;
    for pos in 0..i.len() {
        let b = i[pos];
        if b == 13 { return Err(Err::Error(error_position!(i, ErrorKind::Custom(0xbb0001)))); }
        if b == 45 { found += 1 } else {
            if found > 1 {
                return Err(Err::Error(error_position!(i, ErrorKind::Custom(0xbb0004))));
            }
            found = 0
        }
        if found == 5 {
            match from_utf8(&i[..(pos - 4)]) {
                Ok(s) => return Ok((&i[(pos + 1)..], s)),
                Err(_) => return Err(Err::Error(error_position!(i, ErrorKind::Custom(0xbb0002))))
            }
        }
        if b == 10 { return Err(Err::Error(error_position!(i, ErrorKind::Custom(0xbb0003)))); }
    }
    Err(Err::Incomplete(Needed::Size(5 - found)))
}

named!(pub spaces, take_while!(is_space));
named!(pub pem_begin<&str>, do_parse!(
        tag!(PEM_START) >>
        s: pem_dashed_string >>
        spaces >>
        line_ending >>
        (s)
    ));

#[cfg(test)]
#[test]
fn test_pem_begin() {
    use nom::Context;

    assert_eq!(Ok((&[88][..], "PUBLIC KEY")), pem_begin(b"-----BEGIN PUBLIC KEY-----
X"));
    let _c = Context::Code(&[45u8, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45][..], ErrorKind::Tag);
    assert_eq!(Err(Err::Error(_c)), pem_begin(b"----BEGIN PUBLIC KEY-----"));
    let _c = Context::Code(&[80u8, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 10, 120][..], ErrorKind::Custom(0xbb0004));
    assert_eq!(Err(Err::Error(_c)), pem_begin(b"-----BEGIN PUBLIC KEY----
x"));
    let _c = Context::Code(&[80u8, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 32, 45, 45, 45, 45, 45, 10, 120][..], ErrorKind::Custom(0xbb0004));
    assert_eq!(Err(Err::Error(_c)), pem_begin(b"-----BEGIN PUBLIC KEY---- -----
x"));
    assert_eq!(Ok((&[88][..], "SOMETHING-WITH-SINGLE-DASHES")), pem_begin(b"-----BEGIN SOMETHING-WITH-SINGLE-DASHES-----
X"));
}

#[inline(always)]
fn cleanup_spaces(i: &[u8]) -> IResult<&[u8], ()> {
    for pos in 0..i.len() {
        let b = i[pos];
        if b == 10 || b == 13 || b == 32 {
            continue;
        }
        return Ok((&i[pos..], ()));
    }
    Ok((i, ()))
}

#[cfg(test)]
#[test]
fn test_cleanup_spaces() {
    assert_eq!(Ok((&[88, 89, 90][..], ())), cleanup_spaces(b"  XYZ"));
    assert_eq!(Ok((&[88, 89, 88][..], ())), cleanup_spaces(b"
 XYX"));
}

named!(pub pem_footer<&str>, do_parse!(
    tag!(PEM_END) >>
    s: pem_dashed_string >>
    cleanup_spaces >>
    (s)
));

#[cfg(test)]
#[test]
fn test_pem_footer() {
    assert_eq!(Ok((&[88][..], "PUBLIC KEY")), pem_footer(b"-----END PUBLIC KEY-----
X"));
}

pub fn no_pem_headers(i: &[u8]) -> ::nom::IResult<&[u8], Vec<HeaderEntry>> {
  Ok((i, Vec::new()))
}


named!(pub pem_block<Block>,  do_parse!(
    block_type: pem_begin >>
    headers: alt!(pem_headers|no_pem_headers) >>
    data : ws!(base64::base64) >>
    pem_footer >>
    (Block{block_type, headers, data})
));

named!(pub pem_blocks<Vec<Block>>, many1!(pem_block));

