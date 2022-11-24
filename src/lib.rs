extern crate core;

use std::collections::HashMap;
use std::error;
use num_bigint::RandBigInt;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use serde_json::Value;
use crate::aes::Cipher;


type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

mod aes;

#[cfg(test)]
mod tests {
    use crate::EncryptoAES;

    #[test]
    fn it_works() {
        let msg = b"abc";
        let mut c = EncryptoAES::init(256).unwrap();
        let enc = c.encrypt_cbc(msg);
        let dec = c.decrypt_cbc(enc.clone());
        assert_eq!(&*msg.as_slice(), dec);

        let enc = c.encrypt_cfb128(msg);
        let dec = c.decrypt_cfb128(zenc.clone());
        assert_eq!(&*msg.as_slice(), dec);
    }
}

#[derive(Debug)]
pub struct EncryptoAES {
    c: Cipher,
    rng: ThreadRng,
    bitlen: u32
}

impl EncryptoAES {
    pub fn init(bitlen: u32) -> Result<Self> {
        let mut  rng = thread_rng();
        match bitlen {
            128 => {
                Ok(
                    EncryptoAES {
                        c: Cipher::new_128(&*rng.gen_biguint(128).to_bytes_le()),
                        rng,
                        bitlen
                    }
                )
            },
            198 => {
                Ok(
                    EncryptoAES{
                        c: Cipher::new_192(&rng.gen_biguint(198).to_bytes_le()),
                        rng,
                        bitlen
                    }
                )
            },
            256 => {
                Ok(
                    EncryptoAES{
                        c: Cipher::new_256(&rng.gen_biguint(256).to_bytes_le()),
                        rng,
                        bitlen
                    }
                )
            }
            _ => {
                panic!("The bitlength can only be 128, 198 or 256")
            }
        }
    }

    pub fn encrypt_cbc(&mut self, data: &[u8]) -> String {
        let iv = self.rng.gen_biguint(self.bitlen as u64).to_bytes_le();
        let enc = self.c.cbc_encrypt(iv.as_slice(), data);
        let mut hm = HashMap::<&str, String>::new();
        hm.insert("iv", base64::encode(iv));
        hm.insert("cypher", base64::encode(enc));
        base64::encode(serde_json::to_value(hm).unwrap().to_string().as_bytes())
    }

    pub fn decrypt_cbc(&mut self, data: String) -> Vec<u8>{
        let b64d = base64::decode(data.as_bytes()).unwrap();
        let json: Value = serde_json::from_slice(&*b64d).unwrap();
        let iv = base64::decode(json.get("iv").unwrap().as_str().unwrap().as_bytes()).unwrap();
        let data = base64::decode(json.get("cypher").unwrap().as_str().unwrap().as_bytes()).unwrap();
        self.c.cbc_decrypt(&*iv, &*data)
    }

    pub fn encrypt_cfb128(&mut self, data: &[u8])-> String {
        let iv = self.rng.gen_biguint(self.bitlen as u64).to_bytes_le();
        let enc = self.c.cfb128_encrypt(iv.as_slice(), data);
        let mut hm = HashMap::<&str, String>::new();
        hm.insert("iv", base64::encode(iv));
        hm.insert("cypher", base64::encode(enc));
        base64::encode(serde_json::to_value(hm).unwrap().to_string().as_bytes())
    }

    pub fn decrypt_cfb128(&mut self, data: String) -> Vec<u8>{
        let b64d = base64::decode(data.as_bytes()).unwrap();
        let json: Value = serde_json::from_slice(&*b64d).unwrap();
        let iv = base64::decode(json.get("iv").unwrap().as_str().unwrap().as_bytes()).unwrap();
        let data = base64::decode(json.get("cypher").unwrap().as_str().unwrap().as_bytes()).unwrap();
        self.c.cfb128_decrypt(&*iv, &*data)
    }

}