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
use base64ct::{Base64, Encoding};
use block_padding::NoPadding;
use serde_bytes::ByteBuf;
use tracing::info;

use crate::helper::{
    common::random_bytes,
    enums::{AesEncryptionPadding, EncryptionMode},
    errors::{Error, Result},
};

#[tauri::command]
pub fn generate_iv(size: usize) -> Result<String> {
    let iv = random_bytes(size)?;
    Ok(Base64::encode_string(&iv))
}
#[tauri::command]
pub fn generate_aes(key_size: usize) -> Result<String> {
    let key = random_bytes(key_size / 8)?;
    Ok(Base64::encode_string(&key))
}

#[tauri::command]
#[tracing::instrument(level = "debug")]
pub fn encrypt_aes(
    mode: EncryptionMode,
    key: &str,
    input: ByteBuf,
    padding: AesEncryptionPadding,
    iv: Option<&str>,
    aad: Option<&str>,
) -> Result<Vec<u8>> {
    info!("aes encryption-> mode: {:?} padding: {:?}", mode, padding);
    encrypt_or_decrypt_aes(mode, key, input, padding, iv, aad, true)
}

#[tauri::command]
#[tracing::instrument(level = "debug")]
pub fn decrypt_aes(
    mode: EncryptionMode,
    key: &str,
    input: ByteBuf,
    padding: AesEncryptionPadding,
    iv: Option<&str>,
    aad: Option<&str>,
) -> Result<Vec<u8>> {
    info!("aes decryption-> mode: {:?} padding: {:?}", mode, padding);
    encrypt_or_decrypt_aes(mode, key, input, padding, iv, aad, false)
}

fn encrypt_or_decrypt_aes(
    mode: EncryptionMode,
    key: &str,
    input: ByteBuf,
    padding: AesEncryptionPadding,
    iv: Option<&str>,
    aad: Option<&str>,
    for_encryption: bool,
) -> Result<Vec<u8>> {
    let key_slice = Base64::decode_vec(key).context("decode key failed")?;
    let ciphertext = match key_slice.len() {
        16 => encrypt_or_decrypt_aes_inner::<Aes128>(
            mode,
            &input,
            &key_slice,
            padding,
            iv,
            aad,
            for_encryption,
        )?,
        32 => encrypt_or_decrypt_aes_inner::<Aes256>(
            mode,
            &input,
            &key_slice,
            padding,
            iv,
            aad,
            for_encryption,
        )?,
        _ => {
            return Err(Error::Unsupported(format!(
                "keysize {}",
                key_slice.len()
            )));
        }
    };
    Ok(ciphertext)
}

fn encrypt_or_decrypt_aes_inner<C>(
    mode: EncryptionMode,
    plaintext: &[u8],
    key: &[u8],
    padding: AesEncryptionPadding,
    iv: Option<&str>,
    aad: Option<&str>,
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
            let nonce = Base64::decode_vec(iv.unwrap())
                .context("decode iv failed".to_string())?;
            if for_encryption {
                encrypt_aes_inner_in(
                    cbc::Encryptor::<C>::new_from_slices(key, &nonce)
                        .context("construct aes_cbc_encryptor failed")?,
                    padding,
                    plaintext,
                )
            } else {
                decrypt_aes_inner_in(
                    cbc::Decryptor::<C>::new_from_slices(key, &nonce)
                        .context("construct aes_ecb_decryptor failed")?,
                    padding,
                    plaintext,
                )
            }
        }
        EncryptionMode::Gcm => {
            let cc = Base64::decode_vec(iv.unwrap())
                .context("decode iv failed".to_string())?;
            let nonce = Nonce::from_slice(&cc);
            let mut payload = Vec::from(plaintext);
            let association = &if let Some(association) = aad {
                association.as_bytes().to_vec()
            } else {
                vec![]
            };

            let mut c = AesGcm::<C, typenum::U12>::new_from_slice(key)
                .context("construct aes_gcm_cipher failed")?;
            if for_encryption {
                c.encrypt_in_place(nonce, association, &mut payload)
                    .context("invoke gcm encrypt failed")?
            } else {
                c.decrypt_in_place(nonce, association, &mut payload)
                    .context("invoke gcm decrypt failed")?
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
