# 0.1.0
* Initial release
# 0.2.0
* Added cfb128 support
# 0.3.0
* added methods get_sterilised_key() and get_encrypted_sterilised_key(), which returns base64 encoded public key which can be sent to other clients who uses EncryptoAES, and get_encrypted_sterilised_key() returns base64 encoded AES keys encrypted using ZotPublicKey from [EncryptoRSA](https://github.com/zotcrypto/encrypto-rsa-rust)