use std::fmt::Debug;

use anyhow::Context;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::utils::{
    codec::{
        pkcs8_pkcs1_converter_inner, private_bytes_to_pkcs1,
        private_bytes_to_pkcs8, private_pkcs1_to_bytes, private_pkcs8_to_bytes,
        public_bytes_to_pkcs1, public_bytes_to_pkcs8, public_pkcs1_to_bytes,
        public_pkcs8_to_bytes, PkcsDto,
    },
    common::KeyTuple,
    enums::{Digest, KeyFormat, Pkcs, RsaEncryptionPadding, TextEncoding},
    errors::{Error, Result},
};

#[derive(Serialize, Deserialize)]
pub struct RsaEncryptionDto {
    key: String,
    key_encoding: TextEncoding,
    input: String,
    input_encoding: TextEncoding,
    output_encoding: TextEncoding,
    pkcs: Pkcs,
    key_format: KeyFormat,
    #[serde(flatten)]
    padding: RsaEncryptionPaddingDto,
}

impl Debug for RsaEncryptionDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaEncryptionDto")
            .field("key_encoding", &self.key_encoding)
            .field("input_encoding", &self.input_encoding)
            .field("output_encoding", &self.output_encoding)
            .field("pkcs", &self.pkcs)
            .field("format", &self.key_format)
            .field("padding", &self.padding)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RsaEncryptionPaddingDto {
    padding: RsaEncryptionPadding,
    digest: Option<Digest>,
    #[serde(rename = "mgfDigest")]
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
    pkcs: Pkcs,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<KeyTuple> {
    info!(
        "generate rsa key, key_size: {}, pkcs_encoding: {:?}, encoding: {:?}",
        key_size, pkcs, format
    );
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, key_size)
        .expect("generate rsa key failed");
    let public_key = private_key.to_public_key();
    let private_key_bytes = private_key_to_bytes(private_key, pkcs, format)?;
    let public_key_bytes = public_key_to_bytes(public_key, pkcs, format)?;
    Ok(KeyTuple::new(
        encoding.encode(&private_key_bytes)?,
        encoding.encode(&public_key_bytes)?,
    ))
}

#[tauri::command]
pub async fn derive_rsa(
    key: String,
    pkcs: Pkcs,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<String> {
    info!(
        "generate rsa public key, pkcs_encoding: {:?}, key_encoding: {:?}",
        pkcs, format
    );
    let key_bytes = encoding.decode(&key)?;
    let private_key = bytes_to_private_key(&key_bytes, pkcs, format)?;
    let public_key = RsaPublicKey::from(private_key);
    encoding.encode(&public_key_to_bytes(public_key, pkcs, format)?)
}

#[tauri::command]
pub async fn encrypt_rsa(data: RsaEncryptionDto) -> Result<String> {
    info!("rsa encryption: {:?}", data);

    let key_bytes = data.key_encoding.decode(&data.key)?;
    let input_bytes = data.input_encoding.decode(&data.input)?;

    let public_key =
        bytes_to_public_key(&key_bytes, data.pkcs, data.key_format)?;

    let cipher_bytes =
        encrypt_rsa_inner(public_key, &input_bytes, data.padding)?;
    data.output_encoding.encode(&cipher_bytes)
}

#[tauri::command]
pub async fn decrypt_rsa(data: RsaEncryptionDto) -> Result<String> {
    info!("rsa encryption: {:?}", data);

    let key_bytes = data.key_encoding.decode(&data.key)?;
    let input_bytes = data.input_encoding.decode(&data.input)?;

    let private_key =
        bytes_to_private_key(&key_bytes, data.pkcs, data.key_format)?;

    let plain_bytes =
        decrypt_rsa_inner(private_key, &input_bytes, data.padding)?;
    data.output_encoding.encode(&plain_bytes)
}

#[tauri::command]
pub async fn rsa_transfer_key(
    private_key: Option<String>,
    public_key: Option<String>,
    from: PkcsDto,
    to: PkcsDto,
) -> Result<KeyTuple> {
    info!(
        "rsa key format transfer,  {:?} to {:?}. private->{}, public->{}",
        from,
        to,
        private_key.is_some(),
        public_key.is_some()
    );

    Ok(KeyTuple::new(
        if let Some(key) = private_key {
            let key_bytes = from.encoding.decode(&key)?;
            let private_bytes = pkcs8_pkcs1_converter_inner(
                key_bytes.as_slice(),
                from,
                to,
                false,
            )?;
            to.encoding.encode(&private_bytes)?
        } else {
            "".to_string()
        },
        if let Some(key) = public_key {
            let key_bytes = from.encoding.decode(&key)?;
            let public_bytes = pkcs8_pkcs1_converter_inner(
                key_bytes.as_slice(),
                from,
                to,
                true,
            )?;
            to.encoding.encode(&public_bytes)?
        } else {
            "".to_string()
        },
    ))
}

pub fn encrypt_rsa_inner(
    key: RsaPublicKey,
    input: &[u8],
    padding: RsaEncryptionPaddingDto,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let pad = padding.to_padding();
    Ok(key
        .encrypt(&mut rng, pad, input)
        .context("rsa encrypt failed")?)
}

pub fn decrypt_rsa_inner(
    key: RsaPrivateKey,
    input: &[u8],
    padding: RsaEncryptionPaddingDto,
) -> Result<Vec<u8>> {
    let pad = padding.to_padding();
    Ok(key.decrypt(pad, input).context("rsa decrypt failed")?)
}

fn bytes_to_private_key(
    input: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<RsaPrivateKey> {
    match pkcs {
        Pkcs::Pkcs8 => {
            private_bytes_to_pkcs8::<rsa::RsaPrivateKey>(input, format)
        }
        Pkcs::Pkcs1 => {
            private_bytes_to_pkcs1::<rsa::RsaPrivateKey>(input, format)
        }
        _ => Err(Error::Unsupported("unsupported rsa secret".to_string())),
    }
}

fn private_key_to_bytes(
    input: RsaPrivateKey,
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<Vec<u8>> {
    match pkcs {
        Pkcs::Pkcs8 => {
            private_pkcs8_to_bytes::<rsa::RsaPrivateKey>(input, format)
        }
        Pkcs::Pkcs1 => {
            private_pkcs1_to_bytes::<rsa::RsaPrivateKey>(input, format)
        }
        _ => Err(Error::Unsupported("unsupported rsa secret".to_string())),
    }
}

pub fn bytes_to_public_key(
    input: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<RsaPublicKey> {
    match pkcs {
        Pkcs::Pkcs8 => {
            public_bytes_to_pkcs8::<rsa::RsaPublicKey>(input, format)
        }
        Pkcs::Pkcs1 => {
            public_bytes_to_pkcs1::<rsa::RsaPublicKey>(input, format)
        }
        _ => Err(Error::Unsupported("unsupported rsa secret".to_string())),
    }
}

fn public_key_to_bytes(
    input: RsaPublicKey,
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<Vec<u8>> {
    match pkcs {
        Pkcs::Pkcs8 => {
            public_pkcs8_to_bytes::<rsa::RsaPublicKey>(input, format)
        }
        Pkcs::Pkcs1 => {
            public_pkcs1_to_bytes::<rsa::RsaPublicKey>(input, format)
        }
        _ => Err(Error::Unsupported("unsupported rsa secret".to_string())),
    }
}
