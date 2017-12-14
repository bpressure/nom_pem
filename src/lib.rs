//! Crate implements PEM data encoding and parsing, which originated in Privacy Enhanced Mail.
//! See RFC 1421 for details.
//! It supports PEM messages with headers as well as without.
//!
//! Based on nom as a parser combinator https://github.com/Geal/nom
//!
//!
//!```
//!  let b = b"-----BEGIN PRIVACY-ENHANCED MESSAGE-----
//!Proc-Type: 4,ENCRYPTED
//!Content-Domain: RFC822
//!DEK-Info: DES-CBC,F8143EDE5960C597
//!Originator-ID-Symmetric: linn@zendia.enet.dec.com,,
//!Recipient-ID-Symmetric: linn@zendia.enet.dec.com,ptf-kmc,3
//!Key-Info: DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,
//! B70665BB9BF7CBCDA60195DB94F727D3
//!Recipient-ID-Symmetric: pem-dev@tis.com,ptf-kmc,4
//!Key-Info: DES-ECB,RSA-MD2,161A3F75DC82EF26,
//! E2EF532C65CBCFF79F83A2658132DB47
//!
//!LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M
//!8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk
//!J6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot
//!dXd/H5LMDWnonNvPCwQUHt==
//!-----END PRIVACY-ENHANCED MESSAGE-----";
//!
//!let block = nom_pem::decode_block(b).unwrap();
//!
//!assert_eq!(block.block_type, "PRIVACY-ENHANCED MESSAGE");
//!assert_eq!(block.data.len(), 160);
//!```
//!
//!
#[macro_use]
extern crate nom;

mod parsers;
mod headers;
mod display;

use std::str;
use self::parsers::*;
pub use self::headers::{HeaderEntry, RFC1423Algorithm, ProcTypeType};
use self::headers::*;
use self::display::{write_base64, write_headers};
use std::fmt;
use nom::IResult::*;

#[cfg(test)]
mod test;

/// structure representing one PEM block
#[derive(Debug)]
pub struct Block<'a> {
    pub block_type: &'a str,
    pub headers: Vec<HeaderEntry<'a>>,
    pub data: Vec<u8>
}


#[derive(Debug)]
pub enum PemParsingError {
    NomError(nom::Err),
    Incomplete(nom::Needed)
}

pub fn decode_block<'a>(input: &[u8]) -> Result<Block, PemParsingError> {
    match pem_block(input) {
        Error(e) => Err(PemParsingError::NomError(e)),
        Incomplete(_i) => Err(PemParsingError::Incomplete(_i)),
        Done(_rest, block) => Ok(block)
    }
}


pub fn decode_blocks<'a>(input: &[u8]) -> Result<Vec<Block>, PemParsingError> {
    match pem_blocks(input) {
        Error(e) => Err(PemParsingError::NomError(e)),
        Incomplete(_i) => Err(PemParsingError::Incomplete(_i)),
        Done(_rest, block) => Ok(block)
    }
}

impl<'a> fmt::Display for Block<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "-----BEGIN {}-----\n", &self.block_type)?;
        write_headers(f, &self.headers)?;
        write_base64(f, &self.data, 64)?;
        write!(f, "-----END {}-----\n", &self.block_type)
    }
}
