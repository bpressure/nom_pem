use nom::IResult;


pub fn base64(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let mut ret: Vec<u8> = Vec::with_capacity(input.len() / 4 * 3);
    let mut reg = 0u16;
    let mut bits = 0u8;
    let mut pos = 0;
    while pos < input.len() {
        let b = STANDARD_DECODE[input[pos] as usize];
        if b == X { break; }
        pos += 1;
        if b == I { continue; }
        reg = (reg << 6) | b as u16;
        bits += 6;
        if bits >= 8 {
            bits %= 8;
            ret.push((reg >> bits) as u8);
        }
    }
    while pos < input.len() && input[pos] == 61 { pos += 1 } // remove the padding
    Ok((&input[pos..], ret))
}

const X: u8 = 0xff; // INVALID
const I: u8 = 0xfe;  // IGNORE


pub const STANDARD_DECODE: &'static [u8; 256] = &[
    X, X, X, X, X, X, X, X, X, I, I, X, X, I, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, I,
    X, X, X, X, X, X, X, X, X, X, 62, X, X, X, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, X, X, X, X,
    X, X, X, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    X, X, X, X, X, X, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
    46, 47, 48, 49, 50, 51, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X, X];

#[cfg(test)]
#[test]
fn test() {
    let b = b"LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M
8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk
J6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot
dXd/H5LMDWnonNvPCwQUHt==";

    let r = base64(b);
    assert_eq!(r.is_ok(), true);
    let (rest, result) = r.unwrap();
    assert_eq!(&rest, &[]);

    assert_eq!(result.len(), 160);
    assert_eq!(&result[0..8], &[44u8, 186, 199, 7, 71, 137, 207, 40][..]);
    assert_eq!(&result[150..160], &[13u8, 105, 232, 156, 219, 207, 11, 4, 20, 30][..]);
}