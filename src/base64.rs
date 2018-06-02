use nom::*;
use std::ops::RangeFrom;


pub fn base64<T>(input: T) -> IResult<T, Vec<u8>>
    where
        T: Slice<RangeFrom<usize>>,
        T: InputIter,
        <T as InputIter>::Item: AsChar,
{
    let mut ret: Vec<u8> = Vec::with_capacity(/*input.input_len() / */ 4 * 3);
    let mut buffer = 0u16;
    let mut bits = 0u8;
    let mut pos: usize = 0;
    for c in input.iter_elements() {
        let b = STANDARD_DECODE[c.as_char() as usize];
        match b {
            X => break, // invalid character, base64 data stops here
            I => { // ignore
                pos += 1;
                continue;
            }
            _ => { // 6bit to 8bit calculation
                pos += 1;
                buffer = (buffer << 6) | b as u16;
                bits += 6;
                if bits >= 8 {
                    bits %= 8;
                    ret.push((buffer >> bits) as u8);
                }
            }
        }
    }
    let input = input.slice(pos..);
    pos = 0;
    for c in input.iter_elements() {
        match c.as_char() {
            '=' => pos += 1,
            _ => break
        }
    }
    Ok((input.slice(pos..), ret))
}

const X: u8 = 0xff;
// INVALID
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
    let binary = &b"LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M
8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk
J6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot
dXd/H5LMDWnonNvPCwQUHt=="[..];
    let string = "LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M
8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk
J6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot
dXd/H5LMDWnonNvPCwQUHt==";
    let expected = vec![0x2cu8, 186, 199, 7, 71, 137, 207, 40, 79, 251, 247, 210, 74, 215, 86, 242,
                        137, 30, 18, 123, 248, 238, 60, 94, 237, 34, 127, 136, 222, 246, 162, 19, 92, 82, 77, 163,
                        28, 69, 18, 160, 125, 103, 188, 212, 136, 88, 191, 76, 242, 209, 35, 152, 95, 243, 196, 31,
                        155, 1, 51, 45, 62, 48, 148, 89, 188, 252, 46, 191, 112, 150, 133, 200, 146, 49, 212, 148,
                        18, 233, 189, 116, 116, 82, 181, 51, 97, 185, 13, 166, 77, 26, 129, 93, 136, 205, 74, 100,
                        39, 165, 34, 69, 17, 156, 13, 43, 243, 174, 202, 10, 250, 131, 111, 170, 238, 179, 237, 123,
                        57, 93, 252, 249, 172, 58, 148, 112, 201, 74, 213, 158, 187, 219, 71, 92, 5, 97, 134, 176,
                        50, 233, 78, 148, 130, 158, 154, 45, 117, 119, 127, 31, 146, 204, 13, 105, 232, 156, 219,
                        207, 11, 4, 20, 0x1e];

    assert_eq!(Ok(("", expected.clone())), base64(string));
    assert_eq!(Ok((&[][..], expected)), base64(binary));
}