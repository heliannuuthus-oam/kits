use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    add_encryption_trait_impl,
    crypto::{self, kdf::SALT, EncryptionDto},
    enums::{
        AesEncryptionPadding, EciesEncryptionAlgorithm, EdwardsCurveName,
        EncryptionMode, KeyFormat, TextEncoding,
    },
    errors::Result,
};

pub mod key;

add_encryption_trait_impl!(EciesEdwardsDto {
    curve_name: EdwardsCurveName,
    format: KeyFormat,
    encryption_alg: EciesEncryptionAlgorithm,
    for_encryption: bool
});

#[tauri::command]
pub fn ecies_edwards(data: EciesEdwardsDto) -> Result<String> {
    let input = data.get_input()?;
    let key = data.get_key()?;
    let output_encoding = data.get_output_encoding();

    let output = match data.curve_name {
        EdwardsCurveName::Curve25519 => curve_25519_ecies(
            &input,
            &key,
            data.format,
            data.encryption_alg,
            data.for_encryption,
        ),
    }?;
    output_encoding.encode(&output)
}

pub(crate) fn curve_25519_ecies(
    input: &[u8],
    key: &[u8],
    format: KeyFormat,
    ea: EciesEncryptionAlgorithm,
    for_encryption: bool,
) -> Result<Vec<u8>> {
    if for_encryption {
        curve_25519_ecies_encrypt(input, key, format, ea)
    } else {
        curve_25519_ecies_decrypt(input, key, format, ea)
    }
}

fn curve_25519_ecies_encrypt(
    input: &[u8],
    key: &[u8],
    format: KeyFormat,
    _ea: EciesEncryptionAlgorithm,
) -> Result<Vec<u8>> {
    let rng = rand::thread_rng();
    let mut result = Vec::new();
    let receiver_secret_key =
        x25519_dalek::EphemeralSecret::random_from_rng(rng);
    let verifying_key = key::import_curve_25519_public_key(key, format)?;
    let public_key =
        x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes());
    let receiver_public_key =
        x25519_dalek::PublicKey::from(&receiver_secret_key);
    let receiver_public_key_bytes = receiver_public_key.as_bytes();
    result.extend_from_slice(receiver_public_key_bytes);
    let shared_secret = receiver_secret_key.diffie_hellman(&public_key);
    let pkf_key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 44>(
        shared_secret.as_bytes(),
        SALT.as_bytes(),
        210_000,
    );

    let (secret, iv) = pkf_key.split_at(32);
    debug!(
        "decryption shared_secret_bytes: {}",
        base64ct::Base64::encode_string(secret)
    );
    let encrypted = crypto::aes::encrypt_or_decrypt_aes(
        EncryptionMode::Gcm,
        input,
        secret,
        Some(iv.to_vec()),
        None,
        AesEncryptionPadding::NoPadding,
        true,
    )?;
    result.extend_from_slice(&encrypted);
    Ok(result)
}

fn curve_25519_ecies_decrypt(
    input: &[u8],
    key: &[u8],
    format: KeyFormat,
    _ea: EciesEncryptionAlgorithm,
) -> Result<Vec<u8>> {
    let signing_key = key::import_curve_25519_private_key(key, format)?;

    let verify_key = signing_key.verifying_key();
    let mont_verify_key = verify_key.to_montgomery().to_bytes();

    let (receiver_secret_bytes, input) = input.split_at(mont_verify_key.len());
    let mut receiver_secret = [0; 32];
    receiver_secret.copy_from_slice(receiver_secret_bytes);

    let private_key =
        x25519_dalek::StaticSecret::from(signing_key.to_scalar_bytes());
    let public_key = x25519_dalek::PublicKey::from(receiver_secret);
    let shared_secret = private_key.diffie_hellman(&public_key);
    let pkf_key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 44>(
        shared_secret.as_bytes(),
        SALT.as_bytes(),
        210_000,
    );

    let (secret, iv) = pkf_key.split_at(32);
    debug!(
        "decryption shared_secret_bytes: {}",
        base64ct::Base64::encode_string(secret)
    );
    crypto::aes::encrypt_or_decrypt_aes(
        EncryptionMode::Gcm,
        input,
        secret,
        Some(iv.to_vec()),
        None,
        AesEncryptionPadding::NoPadding,
        false,
    )
}
