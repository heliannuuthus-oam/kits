use anyhow::Context;
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::helper::{
    enums::{AsymmetricKeyFormat, Digest, RsaEncryptionPadding},
    errors::Result,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct RsaEncryptionDto {
    key: ByteBuf,
    format: AsymmetricKeyFormat,
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

enum RsaPaddingScheme {
    Pkcs1v15(rsa::Pkcs1v15Encrypt),
    Oaep(rsa::Oaep),
}

impl rsa::traits::PaddingScheme for RsaPaddingScheme {
    fn decrypt<Rng: rand_core::CryptoRngCore>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        match self {
            RsaPaddingScheme::Pkcs1v15(scheme) => {
                scheme.decrypt(rng, priv_key, ciphertext)
            }
            RsaPaddingScheme::Oaep(scheme) => {
                scheme.decrypt(rng, priv_key, ciphertext)
            }
        }
    }

    fn encrypt<Rng: rand_core::CryptoRngCore>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        match self {
            RsaPaddingScheme::Pkcs1v15(scheme) => {
                scheme.encrypt(rng, pub_key, msg)
            }
            RsaPaddingScheme::Oaep(scheme) => scheme.encrypt(rng, pub_key, msg),
        }
    }
}

impl RsaEncryptionPaddingDto {
    fn to_padding(&self) -> RsaPaddingScheme {
        match self.padding {
            RsaEncryptionPadding::Pkcs1v15 => {
                RsaPaddingScheme::Pkcs1v15(rsa::Pkcs1v15Encrypt)
            }
            RsaEncryptionPadding::Oaep => {
                let digest = self.digest.as_ref().unwrap_or(&Digest::Sha256);
                let mgf_digest =
                    self.mgf_digest.as_ref().unwrap_or(&Digest::Sha256);
                RsaPaddingScheme::Oaep(rsa::Oaep {
                    digest: digest.to_digest(),
                    mgf_digest: mgf_digest.to_digest(),
                    label: None,
                })
            }
        }
    }
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

#[tauri::command]
pub fn encrypt_rsa(dto: RsaEncryptionDto) -> Result<ByteBuf> {
    let public_key = match dto.format {
        AsymmetricKeyFormat::Pkcs1Pem => {
            let key_str = String::from_utf8(dto.key.to_vec())
                .context("rsa pubkey to string squence failed")?;
            RsaPublicKey::from_pkcs1_pem(&key_str)
                .context("init pkcs1 rsa pub key failed")?
        }
        AsymmetricKeyFormat::Pkcs1Der => RsaPublicKey::from_pkcs1_der(&dto.key)
            .context("init pkcs1 rsa pub key failed")?,
        AsymmetricKeyFormat::Pkcs8Pem => {
            let key_str = String::from_utf8(dto.key.to_vec())
                .context("rsa pubkey to string squence failed")?;

            RsaPublicKey::from_public_key_pem(&key_str)
                .context("init pkcs8 rsa publikey key failed")?
        }
        AsymmetricKeyFormat::Pkcs8Der => {
            RsaPublicKey::from_public_key_der(&dto.key)
                .context("init pkcs8 rsa publikey key failed")?
        }
    };
    encrypt_rsa_inner(public_key, &dto.input, dto.padding)
}

#[tauri::command]
pub fn decrypt_rsa(dto: RsaEncryptionDto) -> Result<ByteBuf> {
    let private_key = match dto.format {
        AsymmetricKeyFormat::Pkcs1Pem => {
            let key_str = String::from_utf8(dto.key.to_vec())
                .context("rsa key to string squence failed")?;
            RsaPrivateKey::from_pkcs1_pem(&key_str)
                .context("init pkcs1 rsa private key failed")?
        }
        AsymmetricKeyFormat::Pkcs1Der => {
            RsaPrivateKey::from_pkcs1_der(&dto.key)
                .context("init pkcs1 rsa private key failed")?
        }
        AsymmetricKeyFormat::Pkcs8Pem => {
            let key_str = String::from_utf8(dto.key.to_vec())
                .context("rsa key to string squence failed")?;

            RsaPrivateKey::from_pkcs8_pem(&key_str)
                .context("init pkcs8 rsa private key failed")?
        }
        AsymmetricKeyFormat::Pkcs8Der => {
            RsaPrivateKey::from_pkcs8_der(&dto.key)
                .context("init pkcs8 rsa private key failed")?
        }
    };
    decrypt_rsa_inner(private_key, &dto.input, dto.padding)
}

pub fn encrypt_rsa_inner(
    key: RsaPublicKey,
    input: &[u8],
    padding: RsaEncryptionPaddingDto,
) -> Result<ByteBuf> {
    let mut rng = rand::thread_rng();
    let pad = padding.to_padding();
    Ok(ByteBuf::from(
        key.encrypt(&mut rng, pad, input)
            .context("rsa encrypt failed")?,
    ))
}

pub fn decrypt_rsa_inner(
    key: RsaPrivateKey,
    input: &[u8],
    padding: RsaEncryptionPaddingDto,
) -> Result<ByteBuf> {
    let pad = padding.to_padding();
    Ok(ByteBuf::from(
        key.decrypt(pad, input).context("rsa decrypt failed")?,
    ))
}
