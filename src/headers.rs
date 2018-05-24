use std::str;
use super::{spaces, multi_line, str_end_of_line};
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum HeaderEntry<'a> {
    ProcType(u8, ProcTypeType),
    DEKInfo(RFC1423Algorithm, Vec<u8>),
    Entry(&'a str, Vec<String>)
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum ProcTypeType {
    ENCRYPTED,
    MIC_ONLY,
    MIC_CLEAR,
    CRL
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum RFC1423Algorithm {
    DES_CBC,
    DES_EDE3_CBC,
    AES_128_CBC,
    AES_192_CBC,
    AES_256_CBC
}

use RFC1423Algorithm::*;

impl RFC1423Algorithm {
    pub fn key_size(&self) -> usize {
        match *self {
            DES_CBC => 8,
            DES_EDE3_CBC => 24,
            AES_128_CBC => 16,
            AES_192_CBC => 16,
            AES_256_CBC => 16
        }
    }
    pub fn block_size(&self) -> usize {
        match *self {
            DES_CBC => 8,
            DES_EDE3_CBC => 8,
            AES_128_CBC => 16,
            AES_192_CBC => 16,
            AES_256_CBC => 16
        }
    }
}

pub fn is_pem_header_key_char(c: u8) -> bool { (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 45 }
named!(pub pem_header_key<&str>,map_res!(take_while!(is_pem_header_key_char),str::from_utf8));

named!(pub pem_header_value<Vec<String>>,  do_parse!(
    value: alt!(
        multi_line |
        str_end_of_line
    ) >>
    ({
        let str = &value;
        let v1 : Vec<&str> = str.split(",").collect();
        let v2 : Vec<String>= v1.iter().map(|&str| {String::from(str)}).collect();
        v2
    })
    ));



use nom::digit;
named!(u8_digit<u8>,map_res!(map_res!(digit,str::from_utf8),str::FromStr::from_str));
named!(pub pem_header_proctype<HeaderEntry>,  do_parse!(
    tag!("Proc-Type:") >>
    spaces >>
    code: u8_digit >>
    tag!(",") >>
    t: pem_proctype >>
    value: pem_header_value >>
    (HeaderEntry::ProcType(code, t))
    ));

named!(pub pem_header_dekinfo<HeaderEntry>,  do_parse!(
    tag!("DEK-Info:") >>
    spaces >>
    alg: pem_rfc1423_algorithm >>
    tag!(",") >>
    data: parse_hex >>
    str_end_of_line >>
    (HeaderEntry::DEKInfo(alg, data))
    ));

named!(pub pem_proctype<ProcTypeType>,  alt!(
    do_parse!(tag!("ENCRYPTED") >> (ProcTypeType::ENCRYPTED)) |
    do_parse!(tag!("MIC-ONLY")  >> (ProcTypeType::MIC_ONLY)) |
    do_parse!(tag!("MIC-CLEAR") >> (ProcTypeType::MIC_CLEAR)) |
    do_parse!(tag!("CRL")       >> (ProcTypeType::CRL))
    ));

named!(pem_rfc1423_algorithm<RFC1423Algorithm>, alt!(
     do_parse!(tag!("DES-CBC")      >> (DES_CBC)) |
     do_parse!(tag!("DES-EDE3-CBC") >> (DES_EDE3_CBC)) |
     do_parse!(tag!("AES-128-CBC")  >> (AES_128_CBC)) |
     do_parse!(tag!("AES-192-CBC")  >> (AES_192_CBC)) |
     do_parse!(tag!("AES-256-CBC")  >> (AES_256_CBC))
    ));

named!(pub pem_header_key_value<HeaderEntry>,  do_parse!(
    key: pem_header_key >>
    tag!(":") >>
    spaces >>
    values: pem_header_value >>
    (HeaderEntry::Entry(key, values))
    ));
named!(pub pem_header<HeaderEntry>,  alt!(
     pem_header_proctype |
     pem_header_dekinfo |
     pem_header_key_value
     ));
named!(pub pem_headers<Vec<HeaderEntry>>, do_parse!(
    headers: many1!(pem_header) >>
    tag!("\n") >>
    (headers)
    ));

pub fn parse_hex(i: &[u8]) -> ::nom::IResult<&[u8], Vec<u8>> {
    use nom::Needed::*;

    let mut high = true;
    let mut register = 0u8;
    let mut ret: Vec<u8> = Vec::new();
    let mut pos = 0;
    const T1: u8 = ('1' as u8) - 1;
    const T2: u8 = ('A' as u8) - 1;
    const T3: u8 = ('a' as u8) - 1;
    while pos < i.len() {
        let c = i[pos];
        let b: u8 = if c == ('0' as u8) {
            0
        } else if (c > T1) & (c <= ('9' as u8)) {
            c - T1
        } else if (c > T2) & (c <= ('F' as u8)) {
            c - T2 + 9
        } else if (c > T3) & (c <= ('f' as u8)) {
            c - T3 + 9
        } else {
            break;
        };
        if high {
            register = b << 4;
            high = false;
        } else {
            ret.push(register | b);
            high = true;
        }
        pos += 1;
    }
    if high {
        return Ok((&i[pos..], ret));
    } else {
        return Err(::nom::Err::Incomplete(Size(1)));
    }
}

impl fmt::Display for RFC1423Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DES_CBC => write!(f, "DES-CBC"),
            DES_EDE3_CBC => write!(f, "DES-EDE3-CBC"),
            AES_128_CBC => write!(f, "AES-128-CBC"),
            AES_192_CBC => write!(f, "AES-192-CBC"),
            AES_256_CBC => write!(f, "AES-256-CBC")
        }
    }
}

impl<'a> fmt::Display for HeaderEntry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &HeaderEntry::ProcType(ref l,ref t) => { write!(f, "Proc-Type: {},{:?}", l, t) }
            &HeaderEntry::DEKInfo(ref alg, ref v) => {
                write!(f, "DEK-Info: {},", alg)?;
                write_hex(f, &v)
            }
            &HeaderEntry::Entry(ref key, ref values) => {
                write!(f, "{}: ", key)?;
                let mut pos: usize = key.len() + 2;
                for (i, v) in values.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                        pos += 1
                    }
                    if (v.len() + pos) <= 65 {
                        write!(f, "{}", v)?;
                    } else {
                        let mut s: &str = v;
                        while s.len() > 64 {
                            let (head, tail) = s.split_at(64);
                            write!(f, "\n {}", head)?;
                            s = tail;
                        }
                        write!(f, "\n {}", s)?;
                        pos = s.len() + 1;
                    }
                }
                write!(f, "")
            }
        }
    }
}

fn write_hex(f: &mut fmt::Formatter, data: &[u8]) -> fmt::Result {
    for i in data.iter() {
        write_hex_char(f, i >> 4)?;
        write_hex_char(f, i & 0b1111)?;
    }
    Ok(())
}

fn write_hex_char(f: &mut fmt::Formatter, b: u8) -> fmt::Result {
    const T2: u8 = ('A' as u8) - 10;
    if b > 9 {
        write!(f, "{}", (b + T2) as char)
    } else {
        write!(f, "{}", b)
    }
}


#[cfg(test)]
#[test]
fn hex() {
    assert_eq!(Ok((&[45][..],
                                    vec!(0u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f))),
               parse_hex(b"000102030405060708090a0b0c0d0e0f-"));
    assert_eq!(Ok((&[45][..],
                                    vec!(0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))),
               parse_hex(b"112233445566778899AABBCCDDEEFF-"));
    use nom::Needed::*;
    assert_eq!(Err(::nom::Err::Incomplete(Size(1))),
               parse_hex(b"112233445566778899AABBCCDDEEFFF-"));
}
