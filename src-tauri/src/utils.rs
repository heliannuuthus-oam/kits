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
    enums::RsaKeySize,
    jwt::{JwkeyAlgorithm, JwkeyOperation, JwkeyType, JwkeyUsage},
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
pub(crate) fn jwkey_algorithm(kty: JwkeyType) -> Vec<JwkeyAlgorithm> {
    match kty {
        JwkeyType::RSA => vec![
            JwkeyAlgorithm::RS256,
            JwkeyAlgorithm::RS384,
            JwkeyAlgorithm::RS512,
            JwkeyAlgorithm::PS256,
            JwkeyAlgorithm::PS384,
            JwkeyAlgorithm::PS512,
        ],
        JwkeyType::EcDSA => vec![
            JwkeyAlgorithm::ES256,
            JwkeyAlgorithm::ES384,
            JwkeyAlgorithm::ES521,
            JwkeyAlgorithm::ES256K,
        ],
        JwkeyType::Ed25519 => vec![JwkeyAlgorithm::EdDSA],
        JwkeyType::X25519 => vec![
            JwkeyAlgorithm::EcdhEs,
            JwkeyAlgorithm::EcdhEsA128kw,
            JwkeyAlgorithm::EcdhEsA192kw,
            JwkeyAlgorithm::EcdhEsA256kw,
        ],
        JwkeyType::Symmetric => vec![
            JwkeyAlgorithm::Dir,
            JwkeyAlgorithm::HS256,
            JwkeyAlgorithm::A128GCM,
            JwkeyAlgorithm::A128GCMKW,
            JwkeyAlgorithm::A128KW,
            JwkeyAlgorithm::A128cbcHs256,
            JwkeyAlgorithm::HS384,
            JwkeyAlgorithm::A192GCM,
            JwkeyAlgorithm::A192GCMKW,
            JwkeyAlgorithm::A192KW,
            JwkeyAlgorithm::A192cbcHs384,
            JwkeyAlgorithm::HS512,
            JwkeyAlgorithm::A256GCM,
            JwkeyAlgorithm::A256GCMKW,
            JwkeyAlgorithm::A256KW,
            JwkeyAlgorithm::A256cbcHs512,
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

#[tauri::command]
pub async fn jwkey_operation() -> Vec<JwkeyOperation> {
    JwkeyOperation::iter().collect::<Vec<JwkeyOperation>>()
}
