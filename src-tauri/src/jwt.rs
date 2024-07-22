use std::fmt::Display;

use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

pub mod jwe;
pub mod jwk;
pub mod jws;

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
pub enum JwkeyType {
    RSA,
    EcDSA,
    Ed25519,
    X25519,
    Symmetric,
}

impl JwkeyType {
    pub fn default_algorithm(self) -> JwkeyAlgorithm {
        match self {
            JwkeyType::RSA => JwkeyAlgorithm::RS256,
            JwkeyType::EcDSA => JwkeyAlgorithm::ES256,
            JwkeyType::Ed25519 => JwkeyAlgorithm::EdDSA,
            JwkeyType::X25519 => JwkeyAlgorithm::EcdhEs,
            JwkeyType::Symmetric => JwkeyAlgorithm::A256GCM,
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
pub enum JwkeyAlgorithm {
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
    #[serde(rename = "Encryption")]
    Encryption,
    #[serde(rename = "Signature")]
    Signature,
}

impl Display for JwkeyUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            JwkeyUsage::Encryption => "enc",
            JwkeyUsage::Signature => "sig",
        };

        write!(f, "{}", str)
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
#[serde(rename_all = "camelCase")]
pub enum JwkeyOperation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
}
