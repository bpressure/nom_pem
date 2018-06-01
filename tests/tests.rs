extern crate nom_pem;

use nom_pem::*;

#[test]
fn read_block1() {
    let b = b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxdGIU7iYImcnRoX4DXe+
vPFjKlXMY4mynUxHBK925t6+lKhc+lGfvBX0Aj7xlKsP33Mti8XRT2Syyeoh3vAW
Ts/3avMc0dX9FCLDUmmBWwEhnHNlCZ0KOTCozvkyXPStqrk8wX9SjXVGJmrHBuQU
pU7axXt8BHUv7zA4k6xPbv9vPXNUCbEXCi3QEUB3acPXzW900j6KHqF7NfL64pEL
/daeYCqzxlDmsefBPQAtpN0EaqfyIay0b33PpU1oavL3GNPDEJWtFuCLb7sQy81K
s+ma19vaZv2KD90HG7xlBD98klgW2kvp7SSm/RQel8/l6rQ2vs4e1YWpzoMNgBZ7
pwIDAQAB
-----END PUBLIC KEY-----";
    let data = vec![48u8, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 197, 209, 136, 83, 184, 152, 34, 103, 39, 70, 133, 248, 13, 119, 190, 188, 241, 99, 42, 85, 204, 99, 137, 178, 157, 76, 71, 4, 175, 118, 230, 222, 190, 148, 168, 92, 250, 81, 159, 188, 21, 244, 2, 62, 241, 148, 171, 15, 223, 115, 45, 139, 197, 209, 79, 100, 178, 201, 234, 33, 222, 240, 22, 78, 207, 247, 106, 243, 28, 209, 213, 253, 20, 34, 195, 82, 105, 129, 91, 1, 33, 156, 115, 101, 9, 157, 10, 57, 48, 168, 206, 249, 50, 92, 244, 173, 170, 185, 60, 193, 127, 82, 141, 117, 70, 38, 106, 199, 6, 228, 20, 165, 78, 218, 197, 123, 124, 4, 117, 47, 239, 48, 56, 147, 172, 79, 110, 255, 111, 61, 115, 84, 9, 177, 23, 10, 45, 208, 17, 64, 119, 105, 195, 215, 205, 111, 116, 210, 62, 138, 30, 161, 123, 53, 242, 250, 226, 145, 11, 253, 214, 158, 96, 42, 179, 198, 80, 230, 177, 231, 193, 61, 0, 45, 164, 221, 4, 106, 167, 242, 33, 172, 180, 111, 125, 207, 165, 77, 104, 106, 242, 247, 24, 211, 195, 16, 149, 173, 22, 224, 139, 111, 187, 16, 203, 205, 74, 179, 233, 154, 215, 219, 218, 102, 253, 138, 15, 221, 7, 27, 188, 101, 4, 63, 124, 146, 88, 22, 218, 75, 233, 237, 36, 166, 253, 20, 30, 151, 207, 229, 234, 180, 54, 190, 206, 30, 213, 133, 169, 206, 131, 13, 128, 22, 123, 167, 2, 3, 1, 0, 1];
    assert_eq!(data.len(), 294);
    if let Ok((a, _b)) = pem_block(b) {
        println!("{}\n", std::str::from_utf8(a).unwrap());
    }
    let r = pem_block(b);
    assert_eq!(Ok((&[][..], Block { block_type: "PUBLIC KEY", headers: vec![], data })), r);
}

#[test]
fn read_block2() {
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

    let result = decode_block(b).unwrap();

    assert_eq!(result.block_type, "PRIVACY-ENHANCED MESSAGE");
    assert_eq!(result.data.len(), 160);
    assert_eq!(result.headers.len(), 8);
    let dekinfo = &result.headers[2];
    match *dekinfo {
        HeaderEntry::DEKInfo(ref alg, ref iv) => {
            assert_eq!(&RFC1423Algorithm::DES_CBC, alg);
            assert_eq!(8, alg.block_size());
            assert_eq!(8, alg.key_size());
            assert_eq!(&vec![248u8, 20, 62, 222, 89, 96, 197, 151], iv);
        }
        _ => panic!("DEKInfo expected")
    }
    assert_eq!(&result.data[0..8], &[44u8, 186, 199, 7, 71, 137, 207, 40][..]);
    assert_eq!(&result.data[150..160], &[13u8, 105, 232, 156, 219, 207, 11, 4, 20, 30][..]);
}

#[test]
fn read_block3() {
    let b = b"-----BEGIN PRIVACY-ENHANCED MESSAGE-----
Proc-Type: 4,ENCRYPTED
Content-Domain: RFC822
DEK-Info: DES-CBC,BFF968AA74691AC1
Originator-Certificate:
 MIIBlTCCAScCAWUwDQYJKoZIhvcNAQECBQAwUTELMAkGA1UEBhMCVVMxIDAeBgNV
 BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMQ8wDQYDVQQLEwZCZXRhIDExDzAN
 BgNVBAsTBk5PVEFSWTAeFw05MTA5MDQxODM4MTdaFw05MzA5MDMxODM4MTZaMEUx
 CzAJBgNVBAYTAlVTMSAwHgYDVQQKExdSU0EgRGF0YSBTZWN1cml0eSwgSW5jLjEU
 MBIGA1UEAxMLVGVzdCBVc2VyIDEwWTAKBgRVCAEBAgICAANLADBIAkEAwHZHl7i+
 yJcqDtjJCowzTdBJrdAiLAnSC+CnnjOJELyuQiBgkGrgIh3j8/x0fM+YrsyF1u3F
 LZPVtzlndhYFJQIDAQABMA0GCSqGSIb3DQEBAgUAA1kACKr0PqphJYw1j+YPtcIq
 iWlFPuN5jJ79Khfg7ASFxskYkEMjRNZV/HZDZQEhtVaU7Jxfzs2wfX5byMp2X3U/
 5XUXGx7qusDgHQGs7Jk9W8CW1fuSWUgN4w==
Key-Info: RSA,
 I3rRIGXUGWAF8js5wCzRTkdhO34PTHdRZY9Tuvm03M+NM7fx6qc5udixps2Lng0+
 wGrtiUm/ovtKdinz6ZQ/aQ==
Issuer-Certificate:
 MIIB3DCCAUgCAQowDQYJKoZIhvcNAQECBQAwTzELMAkGA1UEBhMCVVMxIDAeBgNV
 BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMQ8wDQYDVQQLEwZCZXRhIDExDTAL
 BgNVBAsTBFRMQ0EwHhcNOTEwOTAxMDgwMDAwWhcNOTIwOTAxMDc1OTU5WjBRMQsw
 CQYDVQQGEwJVUzEgMB4GA1UEChMXUlNBIERhdGEgU2VjdXJpdHksIEluYy4xDzAN
 BgNVBAsTBkJldGEgMTEPMA0GA1UECxMGTk9UQVJZMHAwCgYEVQgBAQICArwDYgAw
 XwJYCsnp6lQCxYykNlODwutF/jMJ3kL+3PjYyHOwk+/9rLg6X65B/LD4bJHtO5XW
 cqAz/7R7XhjYCm0PcqbdzoACZtIlETrKrcJiDYoP+DkZ8k1gCk7hQHpbIwIDAQAB
 MA0GCSqGSIb3DQEBAgUAA38AAICPv4f9Gx/tY4+p+4DB7MV+tKZnvBoy8zgoMGOx
 dD2jMZ/3HsyWKWgSF0eH/AJB3qr9zosG47pyMnTf3aSy2nBO7CMxpUWRBcXUpE+x
 EREZd9++32ofGBIXaialnOgVUn0OzSYgugiQ077nJLDUj0hQehCizEs5wUJ35a5h
MIC-Info: RSA-MD5,RSA,
 UdFJR8u/TIGhfH65ieewe2lOW4tooa3vZCvVNGBZirf/7nrgzWDABz8w9NsXSexv
 AjRFbHoNPzBuxwmOAFeA0HJszL4yBvhG
Recipient-ID-Asymmetric:
 MFExCzAJBgNVBAYTAlVTMSAwHgYDVQQKExdSU0EgRGF0YSBTZWN1cml0eSwgSW5j
 LjEPMA0GA1UECxMGQmV0YSAxMQ8wDQYDVQQLEwZOT1RBUlk=,
 66
Key-Info: RSA,
 O6BS1ww9CTyHPtS3bMLD+L0hejdvX6Qv1HK2ds2sQPEaXhX8EhvVphHYTjwekdWv
 7x0Z3Jx2vTAhOYHMcqqCjA==

qeWlj/YJ2Uf5ng9yznPbtD0mYloSwIuV9FRYx+gzY+8iXd/NQrXHfi6/MhPfPF3d
jIqCJAxvld2xgqQimUzoS1a4r7kQQ5c/Iua4LqKeq3ciFzEv/MbZhA==
-----END PRIVACY-ENHANCED MESSAGE-----";

    let result = decode_block(b).unwrap();

    assert_eq!(result.block_type, "PRIVACY-ENHANCED MESSAGE");
    assert_eq!(result.headers.len(), 9);

    assert_eq!(result.data.len(), 88);
    assert_eq!(&result.data[0..8], &[169u8, 229, 165, 143, 246, 9, 217, 71][..]);
    assert_eq!(&result.data[80..88], &[34u8, 23, 49, 47, 252, 198, 217, 132][..]);
}