use std::fmt::Debug;

use anyhow::Context;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    add_encryption_trait_impl,
    crypto::EncryptionDto,
    utils::{
        enums::{Digest, KeyFormat, Pkcs, RsaEncryptionPadding, TextEncoding},
        errors::Result,
    },
};

pub mod key;

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
                digest: digest.as_digest(),
                mgf_digest: mgf_digest.as_digest(),
                label: None,
            })
        }
    }
}

#[tauri::command]
pub async fn crypto_rsa(data: RsaEncryptionDto) -> Result<String> {
    info!("rsa crypto: {:?}", data);
    let key = data.get_key()?;
    let input = data.get_input()?;
    let output_encoding = data.get_output_encoding();
    let output = if data.for_encryption {
        let public_key =
            key::bytes_to_public_key(&key, data.pkcs, data.format)?;
        encrypt_rsa_inner(
            public_key,
            &input,
            data.padding,
            data.digest,
            data.mgf_digest,
        )?
    } else {
        let input = data.input_encoding.decode(&data.input)?;
        let private_key =
            key::bytes_to_private_key(&key, data.pkcs, data.format)?;
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
