use anyhow::Context;
use base64ct::Encoding;
use der::{pem::PemLabel, Encode};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde_bytes::ByteBuf;
use spki::DecodePublicKey;
use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    crypto::{self, kdf::SALT},
    helper::{
        common::KeyTuple,
        enums::{
            AesEncryptionPadding, EccKeyFormat, EciesEncryptionAlgorithm,
            EncryptionMode, KeyEncoding,
        },
        errors::{Error, Result},
    },
};

#[tauri::command]
pub fn generate_ed25519() -> Result<String> {
    let mut rng = rand::thread_rng();
    Ok(ed25519_dalek::SigningKey::generate(&mut rng)
        .to_pkcs8_pem(base64ct::LineEnding::LF)
        .context("export ed25519 key failed")?
        .to_string())
}

pub(crate) fn generate_curve_25519_key(
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<KeyTuple> {
    let mut rng = rand::thread_rng();
    let secret_key = ed25519_dalek::SigningKey::generate(&mut rng);

    let private_key =
        export_curve_25519_private_key(&secret_key, format, encoding)?;
    let public_secret_key = secret_key.verifying_key();
    let public_key =
        export_curve_25519_public_key(public_secret_key, encoding)?;
    Ok(KeyTuple(
        ByteBuf::from(private_key),
        ByteBuf::from(public_key),
    ))
}

pub(crate) fn curve_25519_ecies_inner(
    input: &[u8],
    key: &[u8],
    format: EccKeyFormat,
    encoding: KeyEncoding,
    _ea: EciesEncryptionAlgorithm,
    for_encryption: bool,
) -> Result<ByteBuf> {
    let rng = rand::thread_rng();
    let result = if for_encryption {
        let mut result = Vec::new();
        let receiver_secret_key =
            x25519_dalek::EphemeralSecret::random_from_rng(rng);
        let verifying_key = import_curve_25519_public_key(key, encoding)?;
        let public_key = x25519_dalek::PublicKey::from(
            verifying_key.to_montgomery().to_bytes(),
        );
        let receiver_public_key =
            x25519_dalek::PublicKey::from(&receiver_secret_key);
        let receiver_public_key_bytes = receiver_public_key.as_bytes();
        result.push(receiver_public_key_bytes.len() as u8);
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
            secret,
            input,
            AesEncryptionPadding::NoPadding,
            Some(iv.to_vec()),
            None,
            for_encryption,
        )?;
        result.extend_from_slice(&encrypted);
        result
    } else {
        let (public_key_len, input) = input.split_at(1);
        let public_key_len = public_key_len[0] as usize;
        if public_key_len != 32 {
            return Err(Error::Unsupported(format!(
                "unsupported pubkey length {}",
                public_key_len,
            )));
        }

        let (receiver_secret_bytes, input) = input.split_at(32);
        let mut receiver_secret = [0; 32];
        receiver_secret.copy_from_slice(receiver_secret_bytes);
        let signing_key =
            import_curve_25519_private_key(key, format, encoding)?;
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
            secret,
            input,
            AesEncryptionPadding::NoPadding,
            Some(iv.to_vec()),
            None,
            for_encryption,
        )?
    };
    Ok(ByteBuf::from(result))
}

pub(crate) fn import_curve_25519_private_key(
    input: &[u8],
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<ed25519_dalek::SigningKey> {
    let transfer = |der_bytes| {
        sec1::EcPrivateKey::try_from(der_bytes).context("unprocessed error")
    };

    Ok(match (format, encoding) {
        (EccKeyFormat::BaseKeyFormat(_), KeyEncoding::Pem) => {
            let private_key_str = String::from_utf8(input.to_vec())
                .context("informal curve 25519 private key")?;
            ed25519_dalek::SigningKey::from_pkcs8_pem(&private_key_str)
                .context("informal curve 25519 pkcs8 pem private key")?
        }
        (EccKeyFormat::BaseKeyFormat(_), KeyEncoding::Der) => {
            ed25519_dalek::SigningKey::from_pkcs8_der(input)
                .context("informal ecc pkcs8 der private key")?
        }
        (EccKeyFormat::Sec1, KeyEncoding::Pem) => {
            let private_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc pkcs8 private key")?;

            let private_key_pem = pem::parse(private_key_str)
                .context("pem parse private key failed")?;

            if private_key_pem.tag() != sec1::EcPrivateKey::PEM_LABEL {
                return Err(Error::Unsupported(
                    "unsuppoted sec1 tag".to_string(),
                ));
            }
            let sec1_private_key: sec1::EcPrivateKey =
                transfer(private_key_pem.contents())?;
            let mut private_key: ed25519_dalek::SecretKey = [0; 32];
            private_key[.. 32].clone_from_slice(sec1_private_key.private_key);
            ed25519_dalek::SigningKey::from_bytes(&private_key)
        }
        (EccKeyFormat::Sec1, KeyEncoding::Der) => {
            let sec1_private_key = transfer(input)?;
            let mut private_key: ed25519_dalek::SecretKey = [0; 32];
            private_key[.. 32].clone_from_slice(sec1_private_key.private_key);
            ed25519_dalek::SigningKey::from_bytes(&private_key)
        }
    })
}

pub(crate) fn import_curve_25519_public_key(
    input: &[u8],
    from: KeyEncoding,
) -> Result<ed25519_dalek::VerifyingKey> {
    Ok(match from {
        KeyEncoding::Pem => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc public key")?;
            ed25519_dalek::VerifyingKey::from_public_key_pem(&public_key_str)
                .context("informal pem public key")?
        }
        KeyEncoding::Der => {
            ed25519_dalek::VerifyingKey::from_public_key_der(input)
                .context("informal der public key")?
        }
    })
}

pub(crate) fn export_curve_25519_private_key(
    secret_key: &ed25519_dalek::SigningKey,
    format: EccKeyFormat,
    codec: KeyEncoding,
) -> Result<Vec<u8>> {
    let transfer = |secret_key: &ed25519_dalek::SigningKey| {
        let private_key_bytes = Zeroizing::new(secret_key.to_bytes());
        let public_key_bytes = secret_key.verifying_key();
        let cc = Zeroizing::new(
            sec1::EcPrivateKey {
                private_key: private_key_bytes.as_ref(),
                parameters: None,
                public_key: Some(public_key_bytes.as_bytes()),
            }
            .to_der()
            .context("curve_25519 to sec1 private key der failed")?,
        );
        Ok(cc)
    };

    Ok(match format {
        EccKeyFormat::BaseKeyFormat(_) => match codec {
            KeyEncoding::Pem => secret_key
                .to_pkcs8_pem(base64ct::LineEnding::LF)
                .context("export ecc pkcs8 pem private key failed")?
                .as_bytes()
                .to_vec(),
            KeyEncoding::Der => secret_key
                .to_pkcs8_der()
                .context("export ecc pkcs8 der private key failed")?
                .as_bytes()
                .to_vec(),
        },
        EccKeyFormat::Sec1 => match codec {
            KeyEncoding::Pem => {
                let ec_private_key_res: Result<Zeroizing<Vec<u8>>> =
                    transfer(secret_key);
                let ec_private_key_res = ec_private_key_res?;
                let ec_private_key: &[u8] = ec_private_key_res.as_ref();
                let pem = pem::Pem::new(
                    sec1::EcPrivateKey::PEM_LABEL,
                    ec_private_key,
                );
                pem::encode(&pem).as_bytes().to_vec()
            }
            KeyEncoding::Der => transfer(secret_key)?.to_vec(),
        },
    })
}

pub(crate) fn export_curve_25519_public_key(
    public_key: ed25519_dalek::VerifyingKey,
    codec: KeyEncoding,
) -> Result<Vec<u8>> {
    Ok(match codec {
        KeyEncoding::Pem => public_key
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("init pem private key failed")?
            .as_bytes()
            .to_vec(),
        KeyEncoding::Der => public_key
            .to_public_key_der()
            .context("init der private key failed")?
            .to_vec(),
    })
}
