use std::str;
use super::{spaces, multi_line, str_end_of_line};
use std::fmt;

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
named!(pub pem_header_proctype<HeaderEntry>,  do_parse!(
    tag!("Proc-Type:") >>
    spaces >>
    tag!("4,") >>
    t: pem_proctype >>
    value: pem_header_value >>
    (HeaderEntry::ProcType(4, t))
    ));
named!(pub pem_proctype<ProcTypeType>,  alt!(
    do_parse!(tag!("ENCRYPTED") >> (ProcTypeType::ENCRYPTED)) |
    do_parse!(tag!("MIC-ONLY") >> (ProcTypeType::MIC_ONLY)) |
    do_parse!(tag!("MIC-CLEAR") >> (ProcTypeType::MIC_CLEAR)) |
    do_parse!(tag!("CRL") >> (ProcTypeType::CRL))
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
     pem_header_key_value
     ));
named!(pub pem_headers<Vec<HeaderEntry>>, do_parse!(
    headers: many1!(pem_header) >>
    tag!("\n") >>
    (headers)
    ));

#[derive(Debug, PartialEq)]
pub enum HeaderEntry<'a> {
    ProcType(u8, ProcTypeType),
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

impl<'a> fmt::Display for HeaderEntry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HeaderEntry::ProcType(l, t) => { write!(f, "Proc-Type: {},{:?}", l, t) }
            HeaderEntry::Entry(key, values) => {
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
                            let (head, tail) =    s.split_at(64);
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