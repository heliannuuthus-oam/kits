use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum EncryptionMode {
    Ecb,
    Cbc,
    Gcm,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AsymmetricKeyFormat {
    Pkcs1Pem,
    Pkcs1Der,
    Pkcs8Pem,
    Pkcs8Der,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RsaEncryptionPadding {
    Pkcs1v15,
    Oaep,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AesEncryptionPadding {
    Pkcs7Padding,
    NoPadding,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Digest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}
