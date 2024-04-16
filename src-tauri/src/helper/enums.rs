use digest::{Digest as Di, DynDigest};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum EncryptionMode {
    Ecb,
    Cbc,
    Gcm,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
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

impl Digest {
    pub fn to_digest(&self) -> Box<dyn DynDigest + Send + Sync> {
        match self {
            Digest::Sha1 => Box::new(sha1::Sha1::new()),
            Digest::Sha256 => Box::new(sha2::Sha256::new()),
            Digest::Sha384 => Box::new(sha2::Sha384::new()),
            Digest::Sha512 => Box::new(sha2::Sha512::new()),
            Digest::Sha3_256 => Box::new(sha3::Sha3_256::new()),
            Digest::Sha3_384 => Box::new(sha3::Sha3_384::new()),
            Digest::Sha3_512 => Box::new(sha3::Sha3_512::new()),
        }
    }
}
