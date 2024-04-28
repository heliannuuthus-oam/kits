use digest::{Digest as Di, DynDigest};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum EccCurveName {
    NistP256,
    NistP384,
    NistP521,
    Secp256k1,
    Curve25519,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum EncryptionMode {
    Ecb,
    Cbc,
    Gcm,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum AsymmetricKeyFormat {
    #[serde(rename = "pkcs1-pem")]
    Pkcs1Pem,
    #[serde(rename = "pkcs1-der")]
    Pkcs1Der,
    #[serde(rename = "pkcs8-pem")]
    Pkcs8Pem,
    #[serde(rename = "pkcs8-der")]
    Pkcs8Der,
}


#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum PkcsEncoding {
    #[serde(rename = "pkcs8")]
    Pkcs8,
    #[serde(rename = "pkcs1")]
    Pkcs1,
    #[serde(rename = "sec1")]
    Sec1,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum BaseKeyFormat {
    #[serde(rename = "pkcs8")]
    Pkcs8,
    #[serde(rename = "spki")]
    Spki,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum RsaKeyFormat {
    BaseKeyFormat(BaseKeyFormat),
    #[serde(rename = "pkcs1")]
    Pkcs1,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum EccKeyFormat {
    BaseKeyFormat(BaseKeyFormat),
    #[serde(rename = "sec1")]
    Sec1,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum KeyEncoding {
    #[serde(rename = "pem")]
    Pem,
    #[serde(rename = "der")]
    Der,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum EciesEncryptionAlgorithm {
    #[serde(rename = "AES-256-GCM")]
    Aes256Gcm,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RsaEncryptionPadding {
    #[serde(rename = "pkcs1-v1_5")]
    Pkcs1v15,
    #[serde(rename = "oaep")]
    Oaep,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AesEncryptionPadding {
    Pkcs7Padding,
    NoPadding,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
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
