use anyhow::Context;
use base64ct::{
    Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding,
};
use serde_bytes::ByteBuf;

use super::{enums::KeyEncoding, errors::Result};

#[tauri::command]
pub fn base64_encode(
    input: ByteBuf,
    unpadded: bool,
    urlsafety: bool,
) -> Result<String> {
    if input.is_empty() {
        Ok("".to_string())
    } else {
        Ok(match (unpadded, urlsafety) {
            (true, true) => Base64UrlUnpadded::encode_string(&input),
            (true, false) => Base64Unpadded::encode_string(&input),
            (false, true) => Base64Url::encode_string(&input),
            (false, false) => Base64::encode_string(&input),
        })
    }
}

#[tauri::command]
pub fn base64_decode(
    input: &str,
    unpadded: bool,
    urlsafety: bool,
) -> Result<ByteBuf> {
    if input.is_empty() {
        Ok(ByteBuf::from(b""))
    } else {
        Ok(ByteBuf::from(
            match (unpadded, urlsafety) {
                (true, true) => Base64UrlUnpadded::decode_vec(input),
                (true, false) => Base64Unpadded::decode_vec(input),
                (false, true) => Base64Url::decode_vec(input),
                (false, false) => Base64::decode_vec(input),
            }
            .context(format!(
                "base64 decode failed, unppaded: {}, urlsafety: {}",
                unpadded, urlsafety
            ))?,
        ))
    }
}

#[tauri::command]
pub fn hex_encode(input: ByteBuf, uppercase: bool) -> Result<String> {
    if input.is_empty() {
        Ok("".to_string())
    } else {
        let elen = base16ct::encoded_len(&input);
        let mut dst = vec![0u8; elen];
        Ok(if uppercase {
            base16ct::upper::encode_str(&input, &mut dst)
                .context("hex encode failed")?
                .to_string()
        } else {
            base16ct::lower::encode_str(&input, &mut dst)
                .context("hex encode failed")?
                .to_string()
        })
    }
}

#[tauri::command]
pub fn hex_decode(input: &str, uppercase: bool) -> Result<ByteBuf> {
    if input.is_empty() {
        Ok(ByteBuf::from(b""))
    } else {
        Ok(ByteBuf::from(if uppercase {
            base16ct::upper::decode_vec(input).context("hex encode failed")?
        } else {
            base16ct::lower::decode_vec(input).context("hex encode failed")?
        }))
    }
}

#[tauri::command]
pub fn string_encode(input: ByteBuf) -> Result<String> {
    Ok(String::from_utf8(input.into_vec()).context("utf-8 encode failed")?)
}

#[tauri::command]
pub fn string_decode(input: &str) -> Result<ByteBuf> {
    Ok(ByteBuf::from(input.as_bytes()))
}

// pem to der or der to pem
fn public_key_transfer<C>(
    input: ByteBuf,
    from: KeyEncoding,
    to: KeyEncoding,
) -> Result<Vec<u8>>
where
    C: spki::DecodePublicKey
        + pkcs8::DecodePublicKey
        + spki::EncodePublicKey
        + pkcs8::EncodePublicKey,
{
    let public_key = match from {
        KeyEncoding::Pem => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc public key")?;
            C::from_public_key_pem(&public_key_str)
                .context("informal pem public key")?
        }
        KeyEncoding::Der => {
            C::from_public_key_der(&input).context("informal der public key")?
        }
    };

    Ok(match to {
        KeyEncoding::Pem => public_key
            .to_public_key_der()
            .context("pem public key to der failed")?
            .as_bytes()
            .to_vec(),
        KeyEncoding::Der => public_key
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("der public key to pem failed")?
            .as_bytes()
            .to_vec(),
    })
}

fn pem_to_der<E>(input: E, is_public: bool) -> Result<ByteBuf>
where
    E: spki::EncodePublicKey + pkcs8::EncodePrivateKey,
{
    Ok(ByteBuf::from(if is_public {
        input
            .to_public_key_der()
            .context("public key pem to der failed")?
            .as_bytes()
            .to_vec()
    } else {
        input
            .to_pkcs8_der()
            .context("private key pem to der failed")?
            .as_bytes()
            .to_vec()
    }))
}

fn der_to_pem<E>(input: E, is_public: bool) -> Result<ByteBuf>
where
    E: spki::EncodePublicKey + pkcs8::EncodePrivateKey,
{
    Ok(ByteBuf::from(if is_public {
        input
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("public key der to pem failed")?
            .as_bytes()
            .to_vec()
    } else {
        input
            .to_pkcs8_pem(base64ct::LineEnding::LF)
            .context("private key der to pem failed")?
            .as_bytes()
            .to_vec()
    }))
}
