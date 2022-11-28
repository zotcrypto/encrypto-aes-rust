use std::collections::HashMap;
use std::error;
use std::str::FromStr;
use encrypto_rsa::{EncryptoRSA, ZotPublicKey};
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::{OsRng, ThreadRng};
use rand::thread_rng;
use serde_json::Value;
use crate::aes::{AesKey, Cipher};
use crate::bigint::Generator;


type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

mod aes;
mod bigint;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt::format;
    use std::thread::spawn;
    use encrypto_rsa::EncryptoRSA;
    use num_bigint::{BigUint, RandBigInt};
    use rand::thread_rng;
    use serde_json::Value;
    use crate::{Cipher, EncryptoAES};

    #[test]
    fn bytes(){
        fn get_u32(bytes: &[u8]) -> u32 {
            let u8_array: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
            u32::from_be_bytes(u8_array)
        }
        println!("{}", get_u32(b"abcd"));
    }

    #[test]
    fn ster_dester() {
        // let mut hm = HashMap::new();
        // let mut rng = thread_rng();
        // let x = rng.gen_biguint(128);
        // let c = Cipher::new_128(x.to_bytes_le().as_slice());
        // let x = BigUint::from_slice(c.encrypt_key.rd_key.as_ref());
        // println!("{}", x.clone());
        // let mut hm = HashMap::new();
        // hm.insert("x", x.to_string());
        // let json = serde_json::to_value(hm).unwrap();
        // println!("{}", json.clone());
        // let json = json.get("x").unwrap().as_str().unwrap();
        // println!("{}", BigUint::parse_bytes(json.as_bytes(), 10).unwrap());
        /*      hm.insert("enc", );
              hm.insert("dec", BigUint::from_slice(self.c.decrypt_key.rd_key.as_slice()).to_string());
              hm.insert("keylen", self.bitlen.to_string());*/
    }

    #[test]
    fn it_works() {
        let msg = b"abc";
        let mut c = EncryptoAES::init(256).unwrap();
        // let enc = c.encrypt_cbc(msg);
        // let dec = c.decrypt_cbc(enc.clone());
        // assert_eq!(&*msg.as_slice(), dec);

        // let enc = c.encrypt_cfb128(msg);
        // let dec = c.decrypt_cfb128(enc.clone());
        // assert_eq!(&*msg.as_slice(), dec);

        let encrypto = EncryptoRSA::init(1024);

        let mut x = EncryptoAES::desterilize_encrypted_key(c.get_encrypted_sterilised_key(encrypto.get_public_key()), encrypto);
        let mut foo = 0;
        while foo != 1000000 {
            let enc = c.encrypt_cbc(msg);
            x.decrypt_cbc(enc);
            foo += 1;
            // assert_eq!(msg.to_vec(), x.decrypt_cbc(enc));
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptoAES {
    c: Cipher,
    rng: ThreadRng,
    bitlen: u32,
    bu: BigUint,
}

impl EncryptoAES {
    pub fn init(bitlen: u32) -> Result<Self> {
        let mut rng = thread_rng();
        match bitlen {
            128 => {
                let bu = rng.gen_biguint(198);
                Ok(
                    EncryptoAES {
                        c: Cipher::new_128(bu.to_bytes_le().as_slice()),
                        rng,
                        bitlen,
                        bu,
                    }
                )
            }
            198 => {
                let bu = rng.gen_biguint(198);
                Ok(
                    EncryptoAES {
                        c: Cipher::new_192(bu.to_bytes_le().as_slice()),
                        rng,
                        bitlen,
                        bu,
                    }
                )
            }
            256 => {
                let bu = rng.gen_biguint(256);
                Ok(
                    EncryptoAES {
                        c: Cipher::new_256(bu.to_bytes_le().as_slice()),
                        rng,
                        bitlen,
                        bu,
                    }
                )
            }
            _ => {
                panic!("The bitlength can only be 128, 198 or 256")
            }
        }
    }

    pub fn priv_init(bitlen: u32, bu: BigUint) -> Result<Self> {
        let mut rng = thread_rng();
        match bitlen {
            128 => {
                Ok(
                    EncryptoAES {
                        c: Cipher::new_128(bu.to_bytes_le().as_slice()),
                        rng,
                        bitlen,
                        bu,
                    }
                )
            }
            198 => {
                Ok(
                    EncryptoAES {
                        c: Cipher::new_192(bu.to_bytes_le().as_slice()),
                        rng,
                        bitlen,
                        bu,
                    }
                )
            }
            256 => {
                Ok(
                    EncryptoAES {
                        c: Cipher::new_256(bu.to_bytes_le().as_slice()),
                        rng,
                        bitlen,
                        bu,
                    }
                )
            }
            _ => {
                panic!("The bitlength can only be 128, 198 or 256")
            }
        }
    }

    pub fn desterilize_key(encoded: String) -> EncryptoAES {
        let x = base64::decode(encoded).unwrap();
        let json: Value = serde_json::from_slice(&*x).unwrap();
        let bu = json.get("bu").unwrap().as_str().unwrap();
        let bu = BigUint::parse_bytes(bu.as_bytes(), 10).unwrap();
        let bitlen = json.get("keylen").unwrap().as_str().unwrap();
        let bitlen = u16::from_str(bitlen).unwrap();
        EncryptoAES::priv_init(bitlen as u32, bu).unwrap()
    }

    pub fn get_encrypted_sterilised_key(&mut self, pub_key: ZotPublicKey) -> String {
        let mut hm = HashMap::new();
        hm.insert("bu", self.bu.to_string());
        hm.insert("keylen", self.bitlen.to_string());
        let json = serde_json::to_value(hm).unwrap().to_string();
        ZotPublicKey::encrypt_with_pkcsv1_15(json.as_bytes(), pub_key).unwrap()
    }

    pub fn desterilize_encrypted_key(encoded: String, encrypto: EncryptoRSA) -> EncryptoAES {
        let x = encrypto.decrypt_with_pkcsv1_15(encoded);
        let json: Value = serde_json::from_slice(&*x).unwrap();
        let bu = json.get("bu").unwrap().as_str().unwrap();
        let bu = BigUint::parse_bytes(bu.as_bytes(), 10).unwrap();
        let bitlen = json.get("keylen").unwrap().as_str().unwrap();
        let bitlen = u16::from_str(bitlen).unwrap();
        EncryptoAES::priv_init(bitlen as u32, bu).unwrap()
    }

    pub fn get_sterilised_key(&mut self) -> String {
        let mut hm = HashMap::new();
        hm.insert("bu", self.bu.to_string());
        hm.insert("keylen", self.bitlen.to_string());
        base64::encode(serde_json::to_value(hm).unwrap().to_string().as_bytes())
    }

    pub fn encrypt_cbc(&mut self, data: &[u8]) -> String {
        let iv = self.rng.gen_biguint(self.bitlen as u64).to_bytes_le();
        let enc = self.c.cbc_encrypt(iv.as_slice(), data);
        let mut hm = HashMap::<&str, String>::new();
        hm.insert("iv", base64::encode(iv));
        hm.insert("cypher", base64::encode(enc));
        base64::encode(serde_json::to_value(hm).unwrap().to_string().as_bytes())
    }

    pub fn decrypt_cbc(&mut self, data: String) -> Vec<u8> {
        let b64d = base64::decode(data.as_bytes()).unwrap();
        let json: Value = serde_json::from_slice(b64d.as_slice()).unwrap();
        let iv = base64::decode(json.get("iv").unwrap().as_str().unwrap().as_bytes()).unwrap();
        let data = base64::decode(json.get("cypher").unwrap().as_str().unwrap().as_bytes()).unwrap();
        self.c.cbc_decrypt(iv.as_slice(), data.as_slice())
    }

    pub fn encrypt_cfb128(&mut self, data: &[u8]) -> String {
        let iv = self.rng.gen_biguint(self.bitlen as u64).to_bytes_le();
        let enc = self.c.cfb128_encrypt(iv.as_slice(), data);
        let mut hm = HashMap::<&str, String>::new();
        hm.insert("iv", base64::encode(iv));
        hm.insert("cypher", base64::encode(enc));
        base64::encode(serde_json::to_value(hm).unwrap().to_string().as_bytes())
    }

    pub fn decrypt_cfb128(&mut self, data: String) -> Vec<u8> {
        let b64d = base64::decode(data.as_bytes()).unwrap();
        let json: Value = serde_json::from_slice(&*b64d).unwrap();
        let iv = base64::decode(json.get("iv").unwrap().as_str().unwrap().as_bytes()).unwrap();
        let data = base64::decode(json.get("cypher").unwrap().as_str().unwrap().as_bytes()).unwrap();
        self.c.cfb128_decrypt(&*iv, &*data)
    }
}