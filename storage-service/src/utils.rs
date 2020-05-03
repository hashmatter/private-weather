use serde::Deserialize;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;

use std::fmt;

use curve25519_dalek::scalar::Scalar;
use elgamal_ristretto::ciphertext::Ciphertext;
use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::public::PublicKey;
use rand_core::OsRng; 

// refactor to another file
#[derive(Debug)]
pub struct ServiceError {
    reason: String,
}

impl Error for ServiceError {}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.reason)
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: String,
}

pub fn parse_sk(s: String) -> Result<SecretKey, ServiceError> {
    let enc_sk = s[1..s.len() - 1]
        .split(", ")
        .map(|x| u8::from_str(x))
        .filter_map(Result::ok)
        .collect::<Vec<u8>>();

    let result = match bincode::deserialize(&enc_sk) {
        Ok(sk) => Ok(sk),
        Err(_) => Err(ServiceError {
            reason: String::from("Error parsing SecretKey"),
        }),
    };
    result
}

pub fn parse_ciphertexts(s: String) -> Result<Vec<Ciphertext>, ServiceError> {
    let u = s[1..s.len() - 1]
        .split(", ")
        .map(|x| u8::from_str(x))
        .filter_map(Result::ok)
        .collect::<Vec<u8>>();

    let result = match bincode::deserialize(&u) {
        Ok(c) => Ok(c),
        Err(_) => Err(ServiceError {
            reason: String::from("Error parsing ciphertext"),
        }),
    };
    result
}

pub fn get_or_generate_keypair() -> (SecretKey, PublicKey) {
    let (sk, pk) = match env::var("SECRET_KEY") {
        Ok(k) => {
            let decoded_sk = parse_sk(k).unwrap();
            let pk = PublicKey::from(&decoded_sk);
            (decoded_sk, pk)
        }
        Err(_) => {
            println!("SecretKey for server not provided. Generating...");
            let sk = SecretKey::new(&mut OsRng);
            let pk = PublicKey::from(&sk);
            (sk, pk)
        }
    };
    println!("Intializing with key pair:\n sk: {:?}\n pk: {:?}", 
        bincode::serialize(&sk).unwrap(),
        bincode::serialize(&pk).unwrap());

    (sk, pk)
}

pub fn parse_configs(path: String) -> Config {
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    let configs: Config = serde_json::from_str(&data).expect("JSON was not well-formatted");
    configs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sk() {
        let sk_encoded = String::from("[146, 181, 230, 28, 19, 134, 8, 20, 241, 1, 97, 193, 104, 131, 32, 195, 170, 132, 231, 104, 238, 248, 162, 185, 45, 179, 218, 94, 235, 126, 33, 11");
        let sk_encoded_malformed_string = String::from("[something here]");
        let sk_encoded_malformed = String::from("[146,181,230,28,19,134, 8, 20, 241, 1, 97,193, 104, 131, 32, 195, 170, 132, 231, 104, 238, 248, 162, 185, 45, 179, 218, 94, 235, 126, 33, 11]");
        let sk_encoded_fail = String::from("[0, 0, 0, 0, 75, 154, 132, 11, 79, 217, 186, 113, 163, 180, 124, 247, 114, 160, 241, 45, 150, 31, 151, 226, 27, 183]");

        assert!(!parse_sk(sk_encoded).is_err());

        assert!(parse_sk(sk_encoded_malformed_string).is_err());
        assert!(parse_sk(sk_encoded_malformed).is_err());
        assert!(parse_sk(sk_encoded_fail).is_err());
    }

    #[test]
    fn test_parse_ciphertext() {
        let cipher_encoded = String::from("[3, 0, 0, 0, 0, 0, 0, 0, 222, 209, 143, 14, 149, 210, 58, 144, 144, 163, 132, 155, 156, 32, 47, 241, 127, 193, 149, 22, 157, 41, 7, 68, 1, 175, 72, 3, 50, 139, 146, 90, 132, 68, 146, 66, 213, 91, 112, 61, 189, 233, 206, 44, 109, 30, 81, 81, 74, 222, 109, 201, 100, 116, 171, 62, 150, 126, 250, 69, 185, 117, 162, 54, 252, 168, 241, 2, 216, 75, 16, 202, 84, 6, 29, 127, 22, 134, 50, 230, 194, 112, 229, 54, 114, 171, 116, 104, 26, 45, 219, 74, 9, 193, 93, 9, 222, 209, 143, 14, 149, 210, 58, 144, 144, 163, 132, 155, 156, 32, 47, 241, 127, 193, 149, 22, 157, 41, 7, 68, 1, 175, 72, 3, 50, 139, 146, 90, 112, 227, 207, 161, 238, 169, 23, 107, 241, 223, 110, 54, 141, 141, 73, 27, 18, 113, 127, 34, 203, 182, 102, 160, 145, 137, 185, 120, 180, 182, 91, 36, 60, 188, 138, 126, 213, 174, 97, 201, 181, 12, 242, 20, 237, 171, 32, 214, 225, 61, 212, 102, 50, 123, 238, 184, 84, 227, 201, 198, 43, 65, 238, 92, 222, 209, 143, 14, 149, 210, 58, 144, 144, 163, 132, 155, 156, 32, 47, 241, 127, 193, 149, 22, 157, 41, 7, 68, 1, 175, 72, 3, 50, 139, 146, 90, 74, 254, 42, 64, 53, 58, 123, 188, 60, 186, 90, 251, 173, 228, 240, 29, 235, 16, 88, 176, 57, 165, 55, 61, 247, 135, 28, 160, 6, 132, 201, 115, 196, 77, 33, 36, 202, 93, 113, 251, 118, 115, 96, 30, 175, 59, 198, 216, 68, 39, 154, 217, 198, 246, 142, 188, 40, 170, 45, 119, 249, 199, 98, 69]");
        let cipher_encoded_malformed_string = String::from("[something here]");
        let cipher_encoded_fail = String::from("[0, 0, 0, 0, 75, 154, 132, 11, 79, 217, 186, 113, 163, 180, 124, 247, 114, 160, 241, 45, 150, 31, 151, 226, 27, 183]");

        assert!(!parse_ciphertexts(cipher_encoded).is_err());

        assert!(parse_ciphertexts(cipher_encoded_malformed_string).is_err());
        assert!(parse_ciphertexts(cipher_encoded_fail).is_err());
    }
}
