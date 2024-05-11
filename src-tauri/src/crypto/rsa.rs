use anyhow::Context;
use pkcs8::{
    der::zeroize::Zeroizing, DecodePrivateKey, DecodePublicKey,
    EncodePrivateKey,
};
use rsa::{
    pkcs1::{
        DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey,
        EncodeRsaPublicKey,
    },
    pkcs8::EncodePublicKey,
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tracing::info;

use crate::helper::{
    codec::PkcsDto,
    common::KeyTuple,
    enums::{Digest, KeyEncoding, PkcsEncoding, RsaEncryptionPadding},
    errors::{Error, Result},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct RsaEncryptionDto {
    key: ByteBuf,
    pkcs: PkcsEncoding,
    encoding: KeyEncoding,
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
pub async fn generate_rsa(
    key_size: usize,
    pkcs: PkcsEncoding,
    encoding: KeyEncoding,
) -> Result<ByteBuf> {
    info!(
        "generate rsa private key, key_size: {}, pkcs_encoding: {:?}, \
         encoding: {:?}",
        key_size, pkcs, encoding
    );
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, key_size)
        .expect("failed to generate rsa key");
    private_key_to_bytes(priv_key, pkcs, encoding)
}

#[tauri::command]
pub async fn derive_rsa(
    key: ByteBuf,
    pkcs: PkcsEncoding,
    encoding: KeyEncoding,
) -> Result<ByteBuf> {
    info!(
        "generate rsa public key, pkcs_encoding: {:?}, key_encoding: {:?}",
        pkcs, encoding
    );
    let private_key = bytes_to_private_key(&key, pkcs, encoding)?;
    let public_key = RsaPublicKey::from(private_key);
    public_key_to_bytes(public_key, pkcs, encoding)
}

#[tauri::command]
pub async fn encrypt_rsa(data: RsaEncryptionDto) -> Result<ByteBuf> {
    let public_key = bytes_to_public_key(&data.key, data.pkcs, data.encoding)?;
    encrypt_rsa_inner(public_key, &data.input, data.padding)
}

#[tauri::command]
pub async fn decrypt_rsa(data: RsaEncryptionDto) -> Result<ByteBuf> {
    let private_key =
        bytes_to_private_key(&data.key, data.pkcs, data.encoding)?;
    decrypt_rsa_inner(private_key, &data.input, data.padding)
}

#[tauri::command]
pub async fn transfer_rsa_key(
    private_key: Option<ByteBuf>,
    public_key: Option<ByteBuf>,
    from: PkcsDto,
    to: PkcsDto,
) -> Result<KeyTuple> {
    info!(
        "transfer rsa key,  {:?} to {:?}. private->{}, public->{}",
        from,
        to,
        private_key.is_some(),
        public_key.is_some()
    );
    Ok(KeyTuple(
        if let Some(key) = private_key {
            let current = bytes_to_private_key(&key, from.pkcs, from.encoding)?;
            private_key_to_bytes(current, to.pkcs, to.encoding)?
        } else {
            ByteBuf::new()
        },
        if let Some(key) = public_key {
            let current = bytes_to_public_key(&key, from.pkcs, from.encoding)?;
            public_key_to_bytes(current, to.pkcs, from.encoding)?
        } else {
            ByteBuf::new()
        },
    ))
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

fn bytes_to_private_key(
    key: &[u8],
    pkcs: PkcsEncoding,
    encoding: KeyEncoding,
) -> Result<RsaPrivateKey> {
    Ok(match (pkcs, encoding) {
        (PkcsEncoding::Pkcs8, KeyEncoding::Pem) => {
            let key_str = String::from_utf8(key.to_vec())
                .context("rsa key to string squence failed")?;

            RsaPrivateKey::from_pkcs8_pem(&key_str)
                .context("init pkcs8 rsa private key failed")?
        }
        (PkcsEncoding::Pkcs8, KeyEncoding::Der) => {
            RsaPrivateKey::from_pkcs8_der(key)
                .context("init pkcs8 rsa private key failed")?
        }
        (PkcsEncoding::Pkcs1, KeyEncoding::Pem) => {
            let key_str = String::from_utf8(key.to_vec())
                .context("rsa key to string squence failed")?;
            RsaPrivateKey::from_pkcs1_pem(&key_str)
                .context("init pkcs1 rsa private key failed")?
        }
        (PkcsEncoding::Pkcs1, KeyEncoding::Der) => {
            RsaPrivateKey::from_pkcs1_der(key)
                .context("init pkcs1 rsa private key failed")?
        }
        _ => {
            return Err(Error::Unsupported(
                "unsupported ecc secret".to_string(),
            ))
        }
    })
}

fn private_key_to_bytes(
    private_key: RsaPrivateKey,
    pkcs: PkcsEncoding,
    encoding: KeyEncoding,
) -> Result<ByteBuf> {
    Ok(ByteBuf::from(
        match (pkcs, encoding) {
            (PkcsEncoding::Pkcs8, KeyEncoding::Pem) => Zeroizing::new(
                private_key
                    .to_pkcs8_pem(base64ct::LineEnding::LF)
                    .context("generate rsa key to pkcs8 pem failed")?
                    .as_bytes()
                    .to_vec(),
            ),
            (PkcsEncoding::Pkcs8, KeyEncoding::Der) => private_key
                .to_pkcs8_der()
                .context("generate rsa key to pkcs8 der failed")?
                .to_bytes(),
            (PkcsEncoding::Pkcs1, KeyEncoding::Pem) => Zeroizing::new(
                private_key
                    .to_pkcs1_pem(base64ct::LineEnding::LF)
                    .context("generate rsa key to pkcs1 pem failed")?
                    .as_bytes()
                    .to_vec(),
            ),
            (PkcsEncoding::Pkcs1, KeyEncoding::Der) => private_key
                .to_pkcs1_der()
                .context("generate rsa key to pkcs1 der failed")?
                .to_bytes(),
            _ => {
                return Err(Error::Unsupported(
                    "unsupported ecc secret".to_string(),
                ))
            }
        }
        .to_vec(),
    ))
}

pub fn bytes_to_public_key(
    key: &[u8],
    pkcs: PkcsEncoding,
    encoding: KeyEncoding,
) -> Result<RsaPublicKey> {
    Ok(match (pkcs, encoding) {
        (PkcsEncoding::Pkcs1, KeyEncoding::Pem) => {
            let key_str = String::from_utf8(key.to_vec())
                .context("rsa pubkey to string squence failed")?;
            RsaPublicKey::from_pkcs1_pem(&key_str)
                .context("init pkcs1 rsa pub key failed")?
        }
        (PkcsEncoding::Pkcs1, KeyEncoding::Der) => {
            RsaPublicKey::from_pkcs1_der(key)
                .context("init pkcs1 rsa pub key failed")?
        }
        (PkcsEncoding::Pkcs8, KeyEncoding::Pem) => {
            let key_str = String::from_utf8(key.to_vec())
                .context("rsa pubkey to string squence failed")?;

            RsaPublicKey::from_public_key_pem(&key_str)
                .context("init pkcs8 rsa publikey key failed")?
        }
        (PkcsEncoding::Pkcs8, KeyEncoding::Der) => {
            RsaPublicKey::from_public_key_der(key)
                .context("init pkcs8 rsa publikey key failed")?
        }
        _ => {
            return Err(Error::Unsupported(
                "unsupported ecc secret".to_string(),
            ))
        }
    })
}

fn public_key_to_bytes(
    public_key: RsaPublicKey,
    pkcs: PkcsEncoding,
    encoding: KeyEncoding,
) -> Result<ByteBuf> {
    Ok(ByteBuf::from(match (pkcs, encoding) {
        (PkcsEncoding::Pkcs1, KeyEncoding::Pem) => public_key
            .to_pkcs1_pem(base64ct::LineEnding::LF)
            .context("derive rsa key to pkcs1 pem failed")?
            .as_bytes()
            .to_vec(),
        (PkcsEncoding::Pkcs1, KeyEncoding::Der) => public_key
            .to_pkcs1_der()
            .context("derive rsa key to pkcs1 der failed")?
            .to_vec(),
        (PkcsEncoding::Pkcs8, KeyEncoding::Pem) => public_key
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("derive rsa key to pkcs8 pem failed")?
            .into_bytes(),
        (PkcsEncoding::Pkcs8, KeyEncoding::Der) => public_key
            .to_public_key_der()
            .context("derive rsa key to pkcs8 pem failed")?
            .to_vec(),
        _ => {
            return Err(Error::Unsupported(
                "unsupported ecc secret".to_string(),
            ))
        }
    }))
}
