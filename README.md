 # nom_pem
 
 [![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
 [![Build Status](https://travis-ci.org/bpressure/nom_pem.svg?branch=master)](https://travis-ci.org/bpressure/nom_pem)
 [![Crates.io Version](https://img.shields.io/crates/v/nom_pem.svg)](https://crates.io/crates/nom_pem)
 
 Rust Crate implements PEM data encoding and parsing, which originated in Privacy Enhanced Mail.
 See RFC 1421 for details.
 It supports PEM messages with headers as well as without.

 Based on nom as a parser combinator (https://github.com/Geal/nom).


```
  let b = b"-----BEGIN PRIVACY-ENHANCED MESSAGE-----
Proc-Type: 4,ENCRYPTED
Content-Domain: RFC822
DEK-Info: DES-CBC,F8143EDE5960C597
Originator-ID-Symmetric: linn@zendia.enet.dec.com,,
Recipient-ID-Symmetric: linn@zendia.enet.dec.com,ptf-kmc,3
Key-Info: DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,
 B70665BB9BF7CBCDA60195DB94F727D3
Recipient-ID-Symmetric: pem-dev@tis.com,ptf-kmc,4
Key-Info: DES-ECB,RSA-MD2,161A3F75DC82EF26,
 E2EF532C65CBCFF79F83A2658132DB47

LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M
8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk
J6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot
dXd/H5LMDWnonNvPCwQUHt==
-----END PRIVACY-ENHANCED MESSAGE-----";

let block = nom_pem::decode_block(b).unwrap();

assert_eq!(block.block_type, "PRIVACY-ENHANCED MESSAGE");
assert_eq!(block.data.len(), 160);
```


## nom v4 compatible