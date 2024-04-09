use aes::{
    cipher::{
        block_padding::Pkcs7, consts, BlockCipher, BlockEncryptMut, KeyInit,
        KeyIvInit,
    },
    Aes128, Aes256,
};
use aes_gcm::AesGcm;
use anyhow::Context;
use base64ct::{Base64, Encoding};
use block_padding::NoPadding;
use rand::RngCore;

use crate::helper::{
    enums::{AesEncryptionPadding, EncryptionMode},
    errors::{Error, Result},
};

fn encrypt_aes_inner_in<C>(
    c: C,
    padding: AesEncryptionPadding,
    plaintext: &str,
) -> Result<Vec<u8>>
where
    C: BlockEncryptMut,
{
    Ok(match padding {
        AesEncryptionPadding::Pkcs7Padding => {
            c.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes())
        }
        AesEncryptionPadding::NoPadding => {
            c.encrypt_padded_vec_mut::<NoPadding>(plaintext.as_bytes())
        }
    })
}

fn encrypt_aes_inner<C>(
    mode: EncryptionMode,
    plaintext: &str,
    key: &str,
    padding: AesEncryptionPadding,
    iv: Option<&str>,
    aad: Option<&str>,
) -> Result<Vec<u8>>
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
{
    match mode {
        EncryptionMode::ECB => {
            let d = C::new_from_slice(key.as_bytes())
                .context("invoke ecb encryption failed")?;
            encrypt_aes_inner_in(d, padding, plaintext)
        }
        EncryptionMode::CBC => {
            let c = cbc::Encryptor::<C>::new_from_slices(
                key.as_bytes(),
                &Base64::decode_vec(iv.unwrap()).unwrap(),
            )
            .context("invoke cbc encryption failed")?;
            encrypt_aes_inner_in(c, padding, plaintext)
        }
        EncryptionMode::GCM => {
            let d: C = C::new_from_slice(key.as_bytes())
                .context("invoke ecb encryption failed")?;
            let ca = AesGcm::<C, consts::U12>::from(d);

            Ok(vec![12])
        }
    }
}

#[tauri::command]
pub fn generate_aes(key_size: usize) -> Result<String> {
    let mut rng = rand::thread_rng();
    let mut secret: Vec<u8> = vec![0; key_size / 8];
    rng.fill_bytes(&mut secret);
    Ok(base64ct::Base64::encode_string(&secret))
}

#[tauri::command]
pub fn encrypt_aes(
    mode: EncryptionMode,
    key: &str,
    plaintext: &str,
    padding: AesEncryptionPadding,
    iv: Option<&str>,
    aad: Option<&str>,
) -> Result<String> {
    let key_slice = Base64::decode_vec(key).unwrap();
    let ciphertext = match key_slice.len() {
        16 => {
            encrypt_aes_inner::<Aes128>(mode, plaintext, key, padding, iv, aad)?
        }
        32 => {
            encrypt_aes_inner::<Aes256>(mode, plaintext, key, padding, iv, aad)?
        }
        _ => {
            return Err(Error::Unsupported(format!(
                "keysize {}",
                key_slice.len()
            )))
        }
    };
    Ok(Base64::encode_string(&ciphertext))
}
