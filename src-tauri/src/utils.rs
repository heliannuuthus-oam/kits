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
use crate::enums::RsaKeySize;
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
