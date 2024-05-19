use std::fmt::Debug;

use aes::{
    cipher::{
        block_padding::Pkcs7, typenum, BlockCipher, BlockDecrypt,
        BlockDecryptMut, BlockEncrypt, BlockEncryptMut, BlockSizeUser, KeyInit,
        KeyIvInit,
    },
    Aes128, Aes256,
};
use aes_gcm::{aead::AeadMutInPlace, AesGcm, Nonce};
use anyhow::Context;
use block_padding::NoPadding;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    add_encryption_trait_impl,
    crypto::EncryptionDto,
    utils::{
        common::random_bytes,
        enums::{AesEncryptionPadding, EncryptionMode, TextEncoding},
        errors::{Error, Result},
    },
};

add_encryption_trait_impl!(
    AesEncryptoinDto {
        mode: EncryptionMode,
        padding: AesEncryptionPadding,
        iv: Option<String>,
        iv_encoding: Option<TextEncoding>,
        aad: Option<String>,
        aad_encoding: Option<TextEncoding>,
        for_encryption: bool
    }
);

impl Debug for AesEncryptoinDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesEncryptoinDto")
            .field("input_encoding", &self.input_encoding)
            .field("key_encoding", &self.key_encoding)
            .field("output_encoding", &self.output_encoding)
            .field("mode", &self.mode)
            .field("padding", &self.padding)
            .field("iv", &self.iv)
            .field("iv_encoding", &self.iv_encoding)
            .field("aad", &self.aad)
            .field("aad_encoding", &self.aad_encoding)
            .field("for_encryption", &self.for_encryption)
            .finish()
    }
}

#[tauri::command]
pub fn generate_iv(size: usize, encoding: TextEncoding) -> Result<String> {
    let iv = random_bytes(size)?;
    encoding.encode(&iv)
}

#[tauri::command]
pub fn generate_aes(key_size: usize, encoding: TextEncoding) -> Result<String> {
    let key: Vec<u8> = random_bytes(key_size / 8)?;
    encoding.encode(&key)
}

#[tauri::command]
#[tracing::instrument(level = "debug")]
pub fn crypto_aes(data: AesEncryptoinDto) -> Result<String> {
    info!(
        "aes crypto-> for_encryption: {} mode: {:?} padding: {:?}",
        data.for_encryption, data.mode, data.padding
    );
    let iv: Option<Vec<u8>> = data.iv.as_ref().and_then(|nonce| {
        data.iv_encoding
            .map(|enc| enc.decode(nonce).unwrap_or_default())
    });

    let aad: Option<Vec<u8>> = data.aad.as_ref().and_then(|association| {
        data.aad_encoding
            .map(|enc| enc.decode(association).unwrap_or_default())
    });
    let key_bytes = data.get_key()?;
    let plaintext = data.get_input()?;
    let output_encoding = data.get_output_encoding();
    let output = encrypt_or_decrypt_aes(
        data.mode,
        &plaintext,
        &key_bytes,
        iv,
        aad,
        data.padding,
        data.for_encryption,
    )?;
    output_encoding.encode(&output)
}

pub(crate) fn encrypt_or_decrypt_aes(
    mode: EncryptionMode,
    plaintext: &[u8],
    key: &[u8],
    iv: Option<Vec<u8>>,
    aad: Option<Vec<u8>>,
    padding: AesEncryptionPadding,
    for_encryption: bool,
) -> Result<Vec<u8>> {
    match key.len() {
        16 => encrypt_or_decrypt_aes_inner::<Aes128>(
            mode,
            plaintext,
            key,
            iv,
            aad,
            padding,
            for_encryption,
        ),
        32 => encrypt_or_decrypt_aes_inner::<Aes256>(
            mode,
            plaintext,
            key,
            iv,
            aad,
            padding,
            for_encryption,
        ),
        _ => Err(Error::Unsupported(format!("keysize {}", key.len()))),
    }
}

fn encrypt_or_decrypt_aes_inner<C>(
    mode: EncryptionMode,
    plaintext: &[u8],
    key: &[u8],
    iv: Option<Vec<u8>>,
    aad: Option<Vec<u8>>,
    padding: AesEncryptionPadding,
    for_encryption: bool,
) -> Result<Vec<u8>>
where
    C: BlockDecryptMut
        + BlockEncryptMut
        + BlockCipher
        + BlockDecrypt
        + BlockEncrypt
        + KeyInit
        + BlockSizeUser<BlockSize = typenum::U16>,
{
    match mode {
        EncryptionMode::Ecb => {
            let c = C::new_from_slice(key)
                .context("construct aes_ecb_cipher failed")?;
            if for_encryption {
                encrypt_aes_inner_in(c, padding, plaintext)
            } else {
                decrypt_aes_inner_in(c, padding, plaintext)
            }
        }
        EncryptionMode::Cbc => {
            if for_encryption {
                encrypt_aes_inner_in(
                    cbc::Encryptor::<C>::new_from_slices(
                        key,
                        iv.unwrap().as_ref(),
                    )
                    .context("construct aes_cbc_encryptor failed")?,
                    padding,
                    plaintext,
                )
            } else {
                decrypt_aes_inner_in(
                    cbc::Decryptor::<C>::new_from_slices(
                        key,
                        iv.unwrap().as_ref(),
                    )
                    .context("construct aes_ecb_decryptor failed")?,
                    padding,
                    plaintext,
                )
            }
        }
        EncryptionMode::Gcm => {
            let nonce = iv.unwrap();
            let nonce = Nonce::from_slice(&nonce);
            let mut payload = Vec::from(plaintext);
            let association = &if let Some(association) = aad {
                association.to_vec()
            } else {
                vec![]
            };

            let mut c = AesGcm::<C, typenum::U12>::new_from_slice(key)
                .context("construct aes_gcm_cipher failed")?;
            if for_encryption {
                c.encrypt_in_place(nonce, association, &mut payload)
                    .context("aes gcm encrypt failed")?
            } else {
                c.decrypt_in_place(nonce, association, &mut payload)
                    .context("aes gcm decrypt failed")?
            };
            Ok(payload)
        }
    }
}

fn encrypt_aes_inner_in<C>(
    c: C,
    padding: AesEncryptionPadding,
    plaintext: &[u8],
) -> Result<Vec<u8>>
where
    C: BlockEncryptMut,
{
    let pt_len = plaintext.len();
    let mut buf = vec![0u8; 16 * (pt_len / 16 + 1)];
    buf[.. pt_len].copy_from_slice(plaintext);
    let ciphertext = match padding {
        AesEncryptionPadding::Pkcs7Padding => {
            c.encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
        }
        AesEncryptionPadding::NoPadding => {
            c.encrypt_padded_b2b_mut::<NoPadding>(plaintext, &mut buf)
        }
    }
    .context("aes encrypt failed")?;
    Ok(ciphertext.to_vec())
}

fn decrypt_aes_inner_in<C>(
    c: C,
    padding: AesEncryptionPadding,
    ciphertext: &[u8],
) -> Result<Vec<u8>>
where
    C: BlockDecryptMut,
{
    let pt_len = ciphertext.len();
    let mut buf = vec![0u8; 16 * (pt_len / 16 + 1)];
    buf[.. pt_len].copy_from_slice(ciphertext);
    let ciphertext = match padding {
        AesEncryptionPadding::Pkcs7Padding => {
            c.decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buf)
        }
        AesEncryptionPadding::NoPadding => {
            c.decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut buf)
        }
    }
    .context("aes decrypt failed")?;
    Ok(ciphertext.to_vec())
}

#[cfg(test)]
mod test {
    use super::generate_aes;
    use crate::{
        crypto::aes::{crypto_aes, generate_iv, AesEncryptoinDto},
        utils::{
            common::random_bytes,
            enums::{AesEncryptionPadding, EncryptionMode, TextEncoding},
        },
    };

    #[test]
    fn test_aes_gcm_generate_and_encryption() {
        for key_size in [128, 256] {
            let plaintext = "plaintext";
            let encoding = TextEncoding::Base64;
            let key = generate_aes(key_size, encoding).unwrap();
            let iv = generate_iv(12, encoding).unwrap();
            let aad_bytes = random_bytes(128).unwrap();
            let aad = encoding.encode(&aad_bytes).unwrap();
            let ciphertext = crypto_aes(AesEncryptoinDto {
                input: plaintext.to_string(),
                input_encoding: TextEncoding::Utf8,
                key: key.to_string(),
                key_encoding: encoding,
                output_encoding: encoding,
                mode: EncryptionMode::Gcm,
                padding: AesEncryptionPadding::NoPadding,
                iv: Some(iv.to_string()),
                iv_encoding: Some(encoding),
                aad: Some(aad.to_string()),
                aad_encoding: Some(encoding),
                for_encryption: true,
            })
            .unwrap();
            assert_eq!(
                plaintext,
                crypto_aes(AesEncryptoinDto {
                    input: ciphertext,
                    input_encoding: encoding,
                    key,
                    key_encoding: encoding,
                    output_encoding: TextEncoding::Utf8,
                    mode: EncryptionMode::Gcm,
                    padding: AesEncryptionPadding::NoPadding,
                    iv: Some(iv),
                    iv_encoding: Some(encoding),
                    aad: Some(aad),
                    aad_encoding: Some(encoding),
                    for_encryption: false
                })
                .unwrap()
            )
        }
    }
}
