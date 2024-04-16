use anyhow::Context;
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    traits::PaddingScheme,
    Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::Sha1;
use sha2::{digest::DynDigest, Sha256};

use crate::helper::{
    enums::{AsymmetricKeyFormat, Digest, RsaEncryptionPadding},
    errors::Result,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct RsaEncryptionDto {
    key: ByteBuf,
    key_format: AsymmetricKeyFormat,
    #[serde(flatten)]
    padding: RsaEncryptionPaddingDto,
    input: ByteBuf,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RsaEncryptionPaddingDto {
    padding: RsaEncryptionPadding,
    digest: Option<Digest>,
    mgf_digest: Option<Digest>,
}

#[tauri::command]
pub fn generate_rsa(key_size: usize) -> Result<String> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, key_size)
        .expect("failed to generate a key");
    let secret = priv_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .context("export rsa key failed")?;
    Ok(secret.to_string())
}

pub fn rsa_encrypt(
    key: ByteBuf,
    key_format: AsymmetricKeyFormat,
    _padding: RsaEncryptionPadding,
    input: ByteBuf,
) -> Result<ByteBuf> {
    let public_key = match key_format {
        AsymmetricKeyFormat::Pkcs1Pem => {
            let key_str = String::from_utf8(key.to_vec())
                .context("rsa pubkey to string squence failed")?;
            RsaPublicKey::from_pkcs1_pem(&key_str)
                .context("init pkcs1 rsa pub key failed")?
        }
        AsymmetricKeyFormat::Pkcs1Der => RsaPublicKey::from_pkcs1_der(&key)
            .context("init pkcs1 rsa pub key failed")?,
        AsymmetricKeyFormat::Pkcs8Pem => {
            let key_str = String::from_utf8(key.to_vec())
                .context("rsa pubkey to string squence failed")?;

            RsaPublicKey::from_public_key_pem(&key_str)
                .context("init pkcs8 rsa publikey key failed")?
        }
        AsymmetricKeyFormat::Pkcs8Der => {
            RsaPublicKey::from_public_key_der(&key)
                .context("init pkcs8 rsa publikey key failed")?
        }
    };
    let mut rng = rand::thread_rng();
    Ok(ByteBuf::from(
        public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, &input)
            .context("rsa decrypt failed")?,
    ))
}

pub fn rsa_decrypt(
    key: ByteBuf,
    format: AsymmetricKeyFormat,
    input: ByteBuf,
    padding: RsaEncryptionPaddingDto,
) -> Result<ByteBuf> {
    let private_key = match format {
        AsymmetricKeyFormat::Pkcs1Pem => {
            let key_str = String::from_utf8(key.to_vec())
                .context("rsa key to string squence failed")?;
            RsaPrivateKey::from_pkcs1_pem(&key_str)
                .context("init pkcs1 rsa private key failed")?
        }
        AsymmetricKeyFormat::Pkcs1Der => RsaPrivateKey::from_pkcs1_der(&key)
            .context("init pkcs1 rsa private key failed")?,
        AsymmetricKeyFormat::Pkcs8Pem => {
            let key_str = String::from_utf8(key.to_vec())
                .context("rsa key to string squence failed")?;

            RsaPrivateKey::from_pkcs8_pem(&key_str)
                .context("init pkcs8 rsa private key failed")?
        }
        AsymmetricKeyFormat::Pkcs8Der => RsaPrivateKey::from_pkcs8_der(&key)
            .context("init pkcs8 rsa private key failed")?,
    };
    decrypt_rsa_inner(private_key, &input, padding)
}

pub fn encrypt_rsa_inner<D, H>(
    key: RsaPublicKey,
    input: &[u8],
    padding: RsaEncryptionPadding,
    digest: Digest,
    mgf_digest: Digest,
) -> Result<ByteBuf>
where
    D: DynDigest
        + std::marker::Send
        + std::marker::Sync
        + sha2::digest::FixedOutput
        + std::default::Default
        + sha2::digest::HashMarker
        + 'static,
    H: DynDigest
        + std::marker::Send
        + std::marker::Sync
        + sha2::digest::FixedOutput
        + std::default::Default
        + sha2::digest::HashMarker
        + 'static,
{
    let padding = Oaep::new_with_mgf_hash::<D, H>();
    let mut rng = rand::thread_rng();
    Ok(ByteBuf::from(
        key.encrypt(&mut rng, padding, input)
            .context("rsa encrypt failed")?,
    ))
}

pub fn decrypt_rsa_inner(
    key: RsaPrivateKey,
    input: &[u8],
    padding: RsaEncryptionPaddingDto,
) -> Result<ByteBuf> {
    Ok(ByteBuf::from(match padding.padding {
        RsaEncryptionPadding::Pkcs1v15 => key
            .decrypt(Pkcs1v15Encrypt, &input)
            .context("rsa decrypt failed")?,
        RsaEncryptionPadding::Oaep => {
            let digest = padding.digest.unwrap_or(Digest::Sha256);
            let mgf_digest = padding.mgf_digest.unwrap_or(Digest::Sha256);
            match (digest, mgf_digest) {
                (Digest::Sha1, Digest::Sha1) => todo!(),
                (Digest::Sha1, Digest::Sha256) => todo!(),
                (Digest::Sha1, Digest::Sha384) => todo!(),
                (Digest::Sha1, Digest::Sha512) => todo!(),
                (Digest::Sha1, Digest::Sha3_256) => todo!(),
                (Digest::Sha1, Digest::Sha3_384) => todo!(),
                (Digest::Sha1, Digest::Sha3_512) => todo!(),
                (Digest::Sha256, Digest::Sha1) => todo!(),
                (Digest::Sha256, Digest::Sha256) => todo!(),
                (Digest::Sha256, Digest::Sha384) => todo!(),
                (Digest::Sha256, Digest::Sha512) => todo!(),
                (Digest::Sha256, Digest::Sha3_256) => todo!(),
                (Digest::Sha256, Digest::Sha3_384) => todo!(),
                (Digest::Sha256, Digest::Sha3_512) => todo!(),
                (Digest::Sha384, Digest::Sha1) => todo!(),
                (Digest::Sha384, Digest::Sha256) => todo!(),
                (Digest::Sha384, Digest::Sha384) => todo!(),
                (Digest::Sha384, Digest::Sha512) => todo!(),
                (Digest::Sha384, Digest::Sha3_256) => todo!(),
                (Digest::Sha384, Digest::Sha3_384) => todo!(),
                (Digest::Sha384, Digest::Sha3_512) => todo!(),
                (Digest::Sha512, Digest::Sha1) => todo!(),
                (Digest::Sha512, Digest::Sha256) => todo!(),
                (Digest::Sha512, Digest::Sha384) => todo!(),
                (Digest::Sha512, Digest::Sha512) => todo!(),
                (Digest::Sha512, Digest::Sha3_256) => todo!(),
                (Digest::Sha512, Digest::Sha3_384) => todo!(),
                (Digest::Sha512, Digest::Sha3_512) => todo!(),
                (Digest::Sha3_256, Digest::Sha1) => todo!(),
                (Digest::Sha3_256, Digest::Sha256) => todo!(),
                (Digest::Sha3_256, Digest::Sha384) => todo!(),
                (Digest::Sha3_256, Digest::Sha512) => todo!(),
                (Digest::Sha3_256, Digest::Sha3_256) => todo!(),
                (Digest::Sha3_256, Digest::Sha3_384) => todo!(),
                (Digest::Sha3_256, Digest::Sha3_512) => todo!(),
                (Digest::Sha3_384, Digest::Sha1) => todo!(),
                (Digest::Sha3_384, Digest::Sha256) => todo!(),
                (Digest::Sha3_384, Digest::Sha384) => todo!(),
                (Digest::Sha3_384, Digest::Sha512) => todo!(),
                (Digest::Sha3_384, Digest::Sha3_256) => todo!(),
                (Digest::Sha3_384, Digest::Sha3_384) => todo!(),
                (Digest::Sha3_384, Digest::Sha3_512) => todo!(),
                (Digest::Sha3_512, Digest::Sha1) => todo!(),
                (Digest::Sha3_512, Digest::Sha256) => todo!(),
                (Digest::Sha3_512, Digest::Sha384) => todo!(),
                (Digest::Sha3_512, Digest::Sha512) => todo!(),
                (Digest::Sha3_512, Digest::Sha3_256) => todo!(),
                (Digest::Sha3_512, Digest::Sha3_384) => todo!(),
                (Digest::Sha3_512, Digest::Sha3_512) => todo!(),
            }

            let padding = Oaep::new_with_mgf_hash<Sha1>();
        }
    }))
}
