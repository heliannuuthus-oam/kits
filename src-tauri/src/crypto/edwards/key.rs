use anyhow::Context;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use spki::DecodePublicKey;
use tracing::info;

use crate::{
    codec::{
        private_bytes_to_pkcs8, private_pkcs8_to_bytes, public_bytes_to_pkcs8,
        public_pkcs8_to_bytes, PkcsDto,
    },
    enums::{EdwardsCurveName, KeyFormat, TextEncoding},
    errors::Result,
    utils::KeyTuple,
};
#[tauri::command]
pub async fn generate_edwards(
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
    input: String,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<String> {
    let input = encoding.decode(&input)?;

    let public_key = match curve_name {
        EdwardsCurveName::Curve25519 => derive_curve_25519(&input, format),
    }?;

    encoding.encode(&public_key)
}

#[tauri::command]
pub fn transfer_edwards_key(
    curve_name: EdwardsCurveName,
    private_key: Option<String>,
    public_key: Option<String>,
    from: PkcsDto,
    to: PkcsDto,
) -> Result<KeyTuple> {
    info!(
        "edwards key format transfer, curve_name: {:?}, {:?} to {:?}. \
         private->{}, public->{}",
        curve_name,
        from,
        to,
        private_key.is_some(),
        public_key.is_some()
    );

    let mut tuple = KeyTuple::empty();

    tuple
        .private(if let Some(key) = private_key {
            if !key.trim().is_empty() {
                let key_bytes = from.encoding.decode(&key)?;
                let private_bytes = private_bytes_to_pkcs8::<
                    ed25519_dalek::SigningKey,
                >(&key_bytes, from.format)
                .and_then(|key| {
                    private_pkcs8_to_bytes::<ed25519_dalek::SigningKey>(
                        key, to.format,
                    )
                })?;
                Some(to.encoding.encode(&private_bytes)?)
            } else {
                None
            }
        } else {
            None
        })
        .public(if let Some(key) = public_key {
            if !key.trim().is_empty() {
                let key_bytes = from.encoding.decode(&key)?;
                let public_bytes = public_bytes_to_pkcs8::<
                    ed25519_dalek::VerifyingKey,
                >(&key_bytes, from.format)
                .and_then(|key| {
                    public_pkcs8_to_bytes::<ed25519_dalek::VerifyingKey>(
                        key, to.format,
                    )
                })?;
                Some(to.encoding.encode(&public_bytes)?)
            } else {
                None
            }
        } else {
            None
        });
    Ok(tuple)
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

pub(crate) fn import_curve_25519_private_key(
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

pub(crate) fn import_curve_25519_public_key(
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

pub(crate) fn export_curve_25519_private_key(
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
