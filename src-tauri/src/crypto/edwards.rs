use anyhow::Context;
use base64ct::Encoding;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use spki::DecodePublicKey;
use tracing::debug;

use crate::{
    add_encryption_trait_impl,
    crypto::{self, kdf::SALT, EncryptionDto},
    utils::{
        common::KeyTuple,
        enums::{
            AesEncryptionPadding, EciesEncryptionAlgorithm, EdwardsCurveName,
            EncryptionMode, KeyFormat, TextEncoding,
        },
        errors::Result,
    },
};

add_encryption_trait_impl!(EciesEdwardsDto {
    curve_name: EdwardsCurveName,
    format: KeyFormat,
    encryption_alg: EciesEncryptionAlgorithm,
    for_encryption: bool
});

#[tauri::command]
pub fn generate_edwards(
    curve_name: EdwardsCurveName,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<KeyTuple> {
    let (private_key, public_key) = match curve_name {
        EdwardsCurveName::Curve25519 => generate_curve_25519_key(format),
    }?;

    Ok(KeyTuple::new(
        encoding.encode(&private_key)?,
        encoding.encode(&public_key)?,
    ))
}

#[tauri::command]
pub fn derive_edwards(
    curve_name: EdwardsCurveName,
    private_key: String,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<String> {
    let input = encoding.decode(&private_key)?;

    let public_key = match curve_name {
        EdwardsCurveName::Curve25519 => derive_curve_25519(&input, format),
    }?;

    encoding.encode(&public_key)
}

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
    Ok(output_encoding.encode(&output)?)
}

pub(crate) fn generate_curve_25519_key(
    format: KeyFormat,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand::thread_rng();
    let secret_key = ed25519_dalek::SigningKey::generate(&mut rng);

    let private_key = export_curve_25519_private_key(&secret_key, format)?;
    let public_secret_key = secret_key.verifying_key();
    let public_key = export_curve_25519_public_key(public_secret_key, format)?;
    Ok((private_key, public_key))
}

pub(crate) fn derive_curve_25519(
    input: &[u8],
    format: KeyFormat,
) -> Result<Vec<u8>> {
    let ecc_private_key = import_curve_25519_private_key(input, format)?;
    export_curve_25519_public_key(ecc_private_key.verifying_key(), format)
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
    let verifying_key = import_curve_25519_public_key(key, format)?;
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
        &input,
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
    let signing_key = import_curve_25519_private_key(key, format)?;

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

fn import_curve_25519_private_key(
    input: &[u8],
    format: KeyFormat,
) -> Result<ed25519_dalek::SigningKey> {
    Ok(match format {
        KeyFormat::Pem => {
            let private_key_str = String::from_utf8(input.to_vec())
                .context("informal curve 25519 private key")?;
            ed25519_dalek::SigningKey::from_pkcs8_pem(&private_key_str)
                .context("informal curve 25519 pkcs8 pem private key")?
        }
        KeyFormat::Der => ed25519_dalek::SigningKey::from_pkcs8_der(input)
            .context("informal ecc pkcs8 der private key")?,
    })
}

fn import_curve_25519_public_key(
    input: &[u8],
    format: KeyFormat,
) -> Result<ed25519_dalek::VerifyingKey> {
    Ok(match format {
        KeyFormat::Pem => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc public key")?;
            ed25519_dalek::VerifyingKey::from_public_key_pem(&public_key_str)
                .context("informal pem public key")?
        }
        KeyFormat::Der => {
            ed25519_dalek::VerifyingKey::from_public_key_der(input)
                .context("informal der public key")?
        }
    })
}

fn export_curve_25519_private_key(
    secret_key: &ed25519_dalek::SigningKey,
    format: KeyFormat,
) -> Result<Vec<u8>> {
    Ok(match format {
        KeyFormat::Pem => secret_key
            .to_pkcs8_pem(base64ct::LineEnding::LF)
            .context("export ecc pkcs8 pem private key failed")?
            .as_bytes()
            .to_vec(),
        KeyFormat::Der => secret_key
            .to_pkcs8_der()
            .context("export ecc pkcs8 der private key failed")?
            .as_bytes()
            .to_vec(),
    })
}

pub(crate) fn export_curve_25519_public_key(
    public_key: ed25519_dalek::VerifyingKey,
    format: KeyFormat,
) -> Result<Vec<u8>> {
    Ok(match format {
        KeyFormat::Pem => public_key
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("init pem private key failed")?
            .as_bytes()
            .to_vec(),
        KeyFormat::Der => public_key
            .to_public_key_der()
            .context("init der private key failed")?
            .to_vec(),
    })
}
