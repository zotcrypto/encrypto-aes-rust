![Visitor Badge](https://visitor-badge.laobi.icu/badge?page_id=encrypto-aes-rust)
![Crates Badge](https://img.shields.io/crates/v/encrypto_aes)
![Crates Downloads](https://img.shields.io/crates/d/encrypto_aes)


# About Project
End to End encryption (AES) for multiple languages (cross-platform) with [CBC](https://www.ssdd.dev/ssdd/zot/crypto/aes#cbc)

| Icon |             Item              |
|:----:|:-----------------------------:|
|  🥳  |   [**Upcoming**](#Upcoming)   |
|  ⚖️  |    [**License**](#License)    |
|  📝  | [**ChangeLog**](CHANGELOG.md) |

# Usage (rust)

## Implementation
### Cargo
`encrypto_aes =` [latest](https://crates.io/crates/encrypto_aes)


## RSA


### Documentation will be published soon at our [website](https://www.ssdd.dev/zot/crypto/aes/rust)

## You can try:

```rust       
 let msg = b"abc";
        let mut c = EncryptoAES::init(256).unwrap();
        let enc = c.encrypt_cbc(msg);
        let dec = c.decrypt_cbc(enc.clone());
        assert_eq!(&*msg.as_slice(), dec);

        let enc = c.encrypt_cfb128(msg);
        let dec = c.decrypt_cfb128(zenc.clone());
        assert_eq!(&*msg.as_slice(), dec);
```

### Please raise an issue [here](https://github.com/zotcrypto/encrypto-aes/issues) if the documentation isn't uploaded in long time

## Upcoming

| Supported Languages | Status              |
|---------------------|---------------------|
| Flutter             | Priority: Less      |
| Java                | Priority: Very high |
| JavaScript          | Priority: High      |

* Amazing encrypto with prevention against man in the middle attacks and AES-CBC with RSA key exchange for multiple language

## License

### Click [here](LICENSE.md)
