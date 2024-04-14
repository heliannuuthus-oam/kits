use aes::{
    cipher::{
        block_padding::Pkcs7, typenum, BlockCipher, BlockEncrypt,
        BlockEncryptMut, BlockSizeUser, KeyInit, KeyIvInit,
    },
    Aes128, Aes256,
};
use aes_gcm::{
    aead::{Aead, Payload},
    AesGcm, Nonce,
};
use anyhow::Context;
use base64ct::{Base64, Encoding};
use block_padding::NoPadding;

use crate::helper::{
    common::random_bytes,
    enums::{AesEncryptionPadding, EncryptionMode},
    errors::{Error, Result},
};

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
            c.encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        }
        AesEncryptionPadding::NoPadding => {
            c.encrypt_padded_mut::<NoPadding>(&mut buf, pt_len)
        }
    }
    .context("aes encrypt failed")?;
    Ok(ciphertext.to_vec())
}

fn encrypt_aes_inner<C>(
    mode: EncryptionMode,
    plaintext: &[u8],
    key: &[u8],
    padding: AesEncryptionPadding,
    iv: Option<&str>,
    aad: Option<&str>,
) -> Result<Vec<u8>>
where
    C: BlockEncryptMut
        + BlockCipher
        + KeyInit
        + BlockSizeUser<BlockSize = typenum::U16>
        + BlockEncrypt,
{
    match mode {
        EncryptionMode::Ecb => encrypt_aes_inner_in(
            C::new_from_slice(key).context("invoke ecb encryption failed")?,
            padding,
            plaintext,
        ),
        EncryptionMode::Cbc => {
            let nonce = Base64::decode_vec(iv.unwrap())
                .context("decode iv failed".to_string())?;
            encrypt_aes_inner_in(
                cbc::Encryptor::<C>::new_from_slices(key, &nonce)
                    .context("invoke cbc encryption failed")?,
                padding,
                plaintext,
            )
        }
        EncryptionMode::Gcm => {
            let cc = Base64::decode_vec(iv.unwrap())
                .context("decode iv failed".to_string())?;
            let nonce = Nonce::from_slice(&cc);
            let mut payload: Payload = plaintext.into();
            let association = &if let Some(association) = aad {
                Base64::decode_vec(association)
                    .context("decode aad failed".to_string())?
            } else {
                vec![]
            };
            payload.aad = association;
            Ok(AesGcm::<C, typenum::U12>::new_from_slice(key)
                .context("construct aes_gcm_cipher failed")?
                .encrypt(nonce, payload)
                .context("invoke gcm encrypt failed")?)
        }
    }
}

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
pub fn encrypt_aes(
    mode: EncryptionMode,
    key: &str,
    plaintext: &str,
    padding: AesEncryptionPadding,
    iv: Option<&str>,
    aad: Option<&str>,
) -> Result<Vec<u8>> {
    let key_slice = Base64::decode_vec(key).context("decode key failed")?;
    let ciphertext = match key_slice.len() {
        16 => encrypt_aes_inner::<Aes128>(
            mode,
            plaintext.as_bytes(),
            &key_slice,
            padding,
            iv,
            aad,
        )?,
        32 => encrypt_aes_inner::<Aes256>(
            mode,
            plaintext.as_bytes(),
            &key_slice,
            padding,
            iv,
            aad,
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
