use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

use super::{
    enums::{
        Digest, EccCurveName, EciesEncryptionAlgorithm, EdwardsCurveName, Kdf,
        RsaEncryptionPadding,
    },
    errors::Result,
};
use crate::{
    enums::{JwkAlgorithm, JwkeyUsage, RsaKeySize},
    jwt::JwkeyType,
};
#[derive(Serialize, Deserialize)]
pub struct KeyTuple(pub Option<String>, pub Option<String>);

impl KeyTuple {
    pub fn new(private_key: String, public_key: String) -> Self {
        KeyTuple(Some(private_key), Some(public_key))
    }

    pub fn empty() -> Self {
        KeyTuple(None, None)
    }

    pub fn private(&mut self, key: Option<String>) -> &mut Self {
        self.0 = key;
        self
    }

    pub fn public(&mut self, key: Option<String>) -> &mut Self {
        self.1 = key;
        self
    }
}

#[tauri::command]
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    Ok(rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .collect())
}

#[tauri::command]
pub fn random_id() -> Result<String> {
    let base = random_bytes(20)?;
    let base_int =
        num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &base);
    Ok(base_int.to_str_radix(36))
}

#[tauri::command]
pub fn elliptic_curve() -> Vec<EccCurveName> {
    EccCurveName::iter().collect::<Vec<EccCurveName>>()
}

#[tauri::command]
pub fn edwards() -> Vec<EdwardsCurveName> {
    EdwardsCurveName::iter().collect::<Vec<EdwardsCurveName>>()
}

#[tauri::command]
pub fn kdfs() -> Vec<Kdf> {
    Kdf::iter().collect::<Vec<Kdf>>()
}

#[tauri::command]
pub fn digests() -> Vec<Digest> {
    Digest::iter().collect::<Vec<Digest>>()
}

#[tauri::command]
pub fn ecies_enc_alg() -> Vec<EciesEncryptionAlgorithm> {
    EciesEncryptionAlgorithm::iter().collect::<Vec<EciesEncryptionAlgorithm>>()
}

#[tauri::command]
pub fn rsa_key_size() -> Vec<RsaKeySize> {
    RsaKeySize::iter().collect::<Vec<RsaKeySize>>()
}

#[tauri::command]
pub fn rsa_encryption_padding() -> Vec<RsaEncryptionPadding> {
    RsaEncryptionPadding::iter().collect::<Vec<RsaEncryptionPadding>>()
}

#[tauri::command]
pub(crate) fn jwkey_algorithm(kty: JwkeyType) -> Vec<JwkAlgorithm> {
    match kty {
        JwkeyType::RSA => vec![
            JwkAlgorithm::RS256,
            JwkAlgorithm::RS384,
            JwkAlgorithm::RS512,
            JwkAlgorithm::PS256,
            JwkAlgorithm::PS384,
            JwkAlgorithm::PS512,
        ],
        JwkeyType::EcDSA => vec![
            JwkAlgorithm::ES256,
            JwkAlgorithm::ES384,
            JwkAlgorithm::ES521,
            JwkAlgorithm::ES256K,
        ],
        JwkeyType::Ed25519 => vec![JwkAlgorithm::EdDSA],
        JwkeyType::X25519 => vec![
            JwkAlgorithm::EcdhEs,
            JwkAlgorithm::EcdhEsA128kw,
            JwkAlgorithm::EcdhEsA192kw,
            JwkAlgorithm::EcdhEsA256kw,
        ],
        JwkeyType::Symmetric => vec![
            JwkAlgorithm::Dir,
            JwkAlgorithm::HS256,
            JwkAlgorithm::A128GCM,
            JwkAlgorithm::A128GCMKW,
            JwkAlgorithm::A128KW,
            JwkAlgorithm::A128cbcHs256,
            JwkAlgorithm::HS384,
            JwkAlgorithm::A192GCM,
            JwkAlgorithm::A192GCMKW,
            JwkAlgorithm::A192KW,
            JwkAlgorithm::A192cbcHs384,
            JwkAlgorithm::HS512,
            JwkAlgorithm::A256GCM,
            JwkAlgorithm::A256GCMKW,
            JwkAlgorithm::A256KW,
            JwkAlgorithm::A256cbcHs512,
        ],
    }
}

#[tauri::command]
pub(crate) fn jwkey_usage(kty: JwkeyType) -> Vec<JwkeyUsage> {
    match kty {
        JwkeyType::RSA => vec![JwkeyUsage::Encryption, JwkeyUsage::Signature],
        JwkeyType::EcDSA => vec![JwkeyUsage::Signature],
        JwkeyType::Ed25519 => vec![JwkeyUsage::Signature],
        JwkeyType::X25519 => vec![JwkeyUsage::Encryption],
        JwkeyType::Symmetric => {
            vec![JwkeyUsage::Encryption, JwkeyUsage::Signature]
        }
    }
}

#[tauri::command]
pub async fn jwkey_type() -> Vec<JwkeyType> {
    JwkeyType::iter().collect::<Vec<JwkeyType>>()
}
