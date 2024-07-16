use digest::{Digest as Di, DynDigest};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumIter, EnumString, FromRepr};

use super::{
    codec::{
        base64_decode, base64_encode, hex_decode, hex_encode, string_decode,
        string_encode,
    },
    errors::Result,
};

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    EnumIter,
    FromRepr,
)]
#[repr(usize)]
pub enum RsaKeySize {
    #[serde(rename = "2048")]
    Rsa2048 = 2048,
    #[serde(rename = "3072")]
    Rsa3072 = 3072,
    #[serde(rename = "4096")]
    Rsa4096 = 4096,
}

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    EnumIter,
    EnumString,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum EccCurveName {
    NistP256,
    NistP384,
    NistP521,
    Secp256k1,
    SM2,
}

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    EnumIter,
)]
#[serde(rename_all = "lowercase")]
pub enum EdwardsCurveName {
    Curve25519,
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum EncryptionMode {
    Ecb,
    Cbc,
    Gcm,
}

#[derive(
    Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "lowercase")]
pub enum TextEncoding {
    Base64,
    Utf8,
    Hex,
}

impl TextEncoding {
    pub fn encode(&self, input: &[u8]) -> Result<String> {
        match self {
            TextEncoding::Base64 => base64_encode(input, false, false),
            TextEncoding::Utf8 => string_encode(input),
            TextEncoding::Hex => hex_encode(input, false),
        }
    }

    pub fn decode(&self, input: &str) -> Result<Vec<u8>> {
        match self {
            TextEncoding::Base64 => base64_decode(input, false, false),
            TextEncoding::Utf8 => string_decode(input),
            TextEncoding::Hex => hex_decode(input, false),
        }
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum Pkcs {
    #[serde(rename = "pkcs8")]
    Pkcs8,
    #[serde(rename = "pkcs1")]
    Pkcs1,
    #[serde(rename = "sec1")]
    Sec1,
    #[serde(rename = "skpi")]
    Spki,
}

#[derive(
    Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum KeyFormat {
    #[serde(rename = "pem")]
    Pem,
    #[serde(rename = "der")]
    Der,
}

#[derive(
    Serialize,
    Deserialize,
    Copy,
    Clone,
    Debug,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum EciesEncryptionAlgorithm {
    #[serde(rename = "AES-GCM")]
    AesGcm,
}

impl EciesEncryptionAlgorithm {
    pub fn as_encryption_mode(&self) -> EncryptionMode {
        match self {
            EciesEncryptionAlgorithm::AesGcm => EncryptionMode::Gcm,
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    EnumIter,
)]
pub enum RsaEncryptionPadding {
    #[serde(rename = "pkcs1-v1_5")]
    Pkcs1v15,
    #[serde(rename = "oaep")]
    Oaep,
}

#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum AesEncryptionPadding {
    Pkcs7Padding,
    NoPadding,
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
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
    pub fn as_digest(&self) -> Box<dyn DynDigest + Send + Sync> {
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

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "lowercase")]
pub enum Kdf {
    HKdf,
    Concatenation,
    PbKdf2,
    Scrypt,
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum JwkAlgorithm {
    #[serde(rename = "dir")]
    Dir,
    A128KW,
    A192KW,
    A256KW,
    A128GCM,
    A192GCM,
    A256GCM,
    A128GCMKW,
    A192GCMKW,
    A256GCMKW,
    #[serde(rename = "A128CBC-HS256")]
    A128cbcHs256,
    #[serde(rename = "A192CBC-HS384")]
    A192cbcHs384,
    #[serde(rename = "A256CBC-HS512")]
    A256cbcHs512,
    HS256,
    HS384,
    HS512,

    ES256,
    ES384,
    ES521,
    ES256K,

    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    #[serde(rename = "RSA1_5")]
    Rsa1_5,
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    #[serde(rename = "RSA-OAEP-384")]
    RsaOaep384,
    #[serde(rename = "RSA-OAEP-512")]
    RsaOaep521,

    EdDSA,
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128kw,
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192kw,
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256kw,
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum JwkeyUsage {
    Encryption,
    Signature,
}
