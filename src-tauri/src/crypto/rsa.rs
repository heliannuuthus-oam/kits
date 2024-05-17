use std::fmt::Debug;

use anyhow::Context;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    add_encryption_trait_impl,
    crypto::EncryptionDto,
    utils::{
        codec::{
            pkcs8_pkcs1_converter_inner, private_bytes_to_pkcs1,
            private_bytes_to_pkcs8, private_pkcs1_to_bytes,
            private_pkcs8_to_bytes, public_bytes_to_pkcs1,
            public_bytes_to_pkcs8, public_pkcs1_to_bytes,
            public_pkcs8_to_bytes, PkcsDto,
        },
        common::KeyTuple,
        enums::{Digest, KeyFormat, Pkcs, RsaEncryptionPadding, TextEncoding},
        errors::{Error, Result},
    },
};

add_encryption_trait_impl!(RsaEncryptionDto {
    pkcs: Pkcs,
    format: KeyFormat,
    padding: RsaEncryptionPadding,
    digest: Option<Digest>,
    mgf_digest: Option<Digest>,
    for_encryption: bool
});

impl Debug for RsaEncryptionDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaEncryptionDto")
            .field("key_encoding", &self.key_encoding)
            .field("input_encoding", &self.input_encoding)
            .field("output_encoding", &self.output_encoding)
            .field("pkcs", &self.pkcs)
            .field("format", &self.format)
            .field("padding", &self.padding)
            .finish()
    }
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

fn to_padding(
    padding: RsaEncryptionPadding,
    digest: Option<Digest>,
    mgf_digest: Option<Digest>,
) -> RsaPaddingScheme {
    match padding {
        RsaEncryptionPadding::Pkcs1v15 => {
            RsaPaddingScheme::Pkcs1v15(rsa::Pkcs1v15Encrypt)
        }
        RsaEncryptionPadding::Oaep => {
            let digest = digest.as_ref().unwrap_or(&Digest::Sha256);
            let mgf_digest = mgf_digest.as_ref().unwrap_or(&Digest::Sha256);
            RsaPaddingScheme::Oaep(rsa::Oaep {
                digest: digest.to_digest(),
                mgf_digest: mgf_digest.to_digest(),
                label: None,
            })
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
pub async fn crypto_rsa(data: RsaEncryptionDto) -> Result<String> {
    info!("rsa crypto: {:?}", data);
    let key = data.get_key()?;
    let input = data.get_input()?;
    let output_encoding = data.get_output_encoding();
    let output = if data.for_encryption {
        let public_key = bytes_to_public_key(&key, data.pkcs, data.format)?;
        encrypt_rsa_inner(
            public_key,
            &input,
            data.padding,
            data.digest,
            data.mgf_digest,
        )?
    } else {
        let input = data.input_encoding.decode(&data.input)?;
        let private_key = bytes_to_private_key(&key, data.pkcs, data.format)?;
        decrypt_rsa_inner(
            private_key,
            &input,
            data.padding,
            data.digest,
            data.mgf_digest,
        )?
    };
    output_encoding.encode(&output)
}

#[tauri::command]
pub async fn transfer_rsa_key(
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
    padding: RsaEncryptionPadding,
    digest: Option<Digest>,
    mgf_digest: Option<Digest>,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let pad = to_padding(padding, digest, mgf_digest);
    Ok(key
        .encrypt(&mut rng, pad, input)
        .context("rsa encrypt failed")?)
}

pub fn decrypt_rsa_inner(
    key: RsaPrivateKey,
    input: &[u8],
    padding: RsaEncryptionPadding,
    digest: Option<Digest>,
    mgf_digest: Option<Digest>,
) -> Result<Vec<u8>> {
    let pad = to_padding(padding, digest, mgf_digest);
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
