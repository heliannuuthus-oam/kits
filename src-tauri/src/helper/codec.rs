use anyhow::Context;
use base64ct::{
    Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding,
};
use serde_bytes::ByteBuf;

use super::errors::Result;

#[tauri::command]
pub fn base64_encode(
    input: ByteBuf,
    unpadded: bool,
    urlsafety: bool,
) -> Result<String> {
    Ok(match (unpadded, urlsafety) {
        (true, true) => Base64UrlUnpadded::encode_string(&input),
        (true, false) => Base64Unpadded::encode_string(&input),
        (false, true) => Base64Url::encode_string(&input),
        (false, false) => Base64::encode_string(&input),
    })
}

#[tauri::command]
pub fn base64_decode(
    input: &str,
    unpadded: bool,
    urlsafety: bool,
) -> Result<ByteBuf> {
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

#[tauri::command]
pub fn hex_encode(input: ByteBuf, uppercase: bool) -> Result<String> {
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

#[tauri::command]
pub fn hex_decode(input: &str, uppercase: bool) -> Result<ByteBuf> {
    Ok(ByteBuf::from(if uppercase {
        base16ct::upper::decode_vec(input).context("hex encode failed")?
    } else {
        base16ct::lower::decode_vec(input).context("hex encode failed")?
    }))
}

#[tauri::command]
pub fn string_encode(input: ByteBuf) -> Result<String> {
    Ok(String::from_utf8(input.into_vec()).context("utf-8 encode failed")?)
}

#[tauri::command]
pub fn string_decode(input: &str) -> Result<ByteBuf> {
    Ok(ByteBuf::from(input.as_bytes()))
}

pub fn pkcs8_private_encode<P>(input: P, pem: bool) -> Result<ByteBuf>
where
    P: pkcs8::EncodePrivateKey,
{
    Ok(ByteBuf::from(if pem {
        input
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .context("private key pkcs8 pem encode failed")?
            .as_bytes()
            .to_vec()
    } else {
        input
            .to_pkcs8_der()
            .context("public key pkcs8 der encode failed")?
            .as_bytes()
            .to_vec()
    }))
}

pub fn pkcs8_public_encode<P: pkcs8::EncodePublicKey>(
    input: P,
    pem: bool,
) -> Result<ByteBuf> {
    Ok(ByteBuf::from(if pem {
        input
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .context("public key pkcs8 pem encode failed")?
            .into_bytes()
    } else {
        input
            .to_public_key_der()
            .context("public key pkcs8 der encode failed")?
            .into_vec()
    }))
}
