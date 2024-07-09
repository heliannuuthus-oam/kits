use anyhow::Context;
use base64ct::{
    Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding,
};

use crate::{
    enums::{KeyFormat, Pkcs, TextEncoding},
    errors::Result,
};

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Copy)]
pub struct PkcsDto {
    pub pkcs: Pkcs,
    pub format: KeyFormat,
    pub encoding: TextEncoding,
}

#[tauri::command]
pub fn convert_encoding(
    input: String,
    from: TextEncoding,
    to: TextEncoding,
) -> Result<String> {
    let decoded = from.decode(&input)?;

    to.encode(&decoded)
}

pub fn base64_encode(
    input: &[u8],
    unpadded: bool,
    urlsafety: bool,
) -> Result<String> {
    if input.is_empty() {
        Ok("".to_string())
    } else {
        Ok(match (unpadded, urlsafety) {
            (true, true) => Base64UrlUnpadded::encode_string(input),
            (true, false) => Base64Unpadded::encode_string(input),
            (false, true) => Base64Url::encode_string(input),
            (false, false) => Base64::encode_string(input),
        })
    }
}

pub fn base64_decode(
    input: &str,
    unpadded: bool,
    urlsafety: bool,
) -> Result<Vec<u8>> {
    if input.is_empty() {
        Ok(b"".to_vec())
    } else {
        Ok((match (unpadded, urlsafety) {
            (true, true) => Base64UrlUnpadded::decode_vec(input),
            (true, false) => Base64Unpadded::decode_vec(input),
            (false, true) => Base64Url::decode_vec(input),
            (false, false) => Base64::decode_vec(input),
        })
        .context(format!(
            "base64 decode failed, unppaded: {}, urlsafety: {}",
            unpadded, urlsafety
        ))?)
    }
}

pub fn hex_encode(input: &[u8], uppercase: bool) -> Result<String> {
    if input.is_empty() {
        Ok("".to_string())
    } else {
        let elen = base16ct::encoded_len(input);
        let mut dst = vec![0u8; elen];
        Ok(if uppercase {
            base16ct::upper::encode_str(input, &mut dst)
                .context("hex encode failed")?
                .to_string()
        } else {
            base16ct::lower::encode_str(input, &mut dst)
                .context("hex encode failed")?
                .to_string()
        })
    }
}

pub fn hex_decode(input: &str, uppercase: bool) -> Result<Vec<u8>> {
    if input.is_empty() {
        Ok("".as_bytes().to_vec())
    } else {
        Ok(if uppercase {
            base16ct::upper::decode_vec(input).context("hex encode failed")?
        } else {
            base16ct::lower::decode_vec(input).context("hex encode failed")?
        })
    }
}

pub fn string_encode(input: &[u8]) -> Result<String> {
    Ok(String::from_utf8(input.to_vec()).context("utf-8 encode failed")?)
}

pub fn string_decode(input: &str) -> Result<Vec<u8>> {
    Ok(input.as_bytes().to_vec())
}

pub(crate) fn private_bytes_to_pkcs8<E>(
    input: &[u8],
    encoding: KeyFormat,
) -> Result<E>
where
    E: pkcs8::DecodePrivateKey,
{
    Ok(match encoding {
        KeyFormat::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_pkcs8_pem(&key_string)
                .context("invalid pkcs8 pem private key")?
        }
        KeyFormat::Der => {
            E::from_pkcs8_der(input).context("invalid pkcs8 der private key")?
        }
    })
}

pub(crate) fn public_bytes_to_pkcs8<E>(
    input: &[u8],
    format: KeyFormat,
) -> Result<E>
where
    E: pkcs8::DecodePublicKey,
{
    Ok(match format {
        KeyFormat::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_public_key_pem(&key_string)
                .context("invalid pkcs8 pem public key")?
        }
        KeyFormat::Der => E::from_public_key_der(input)
            .context("invalid pkcs8 der public key")?,
    })
}

pub(crate) fn private_pkcs8_to_bytes<E>(
    input: E,
    format: KeyFormat,
) -> Result<Vec<u8>>
where
    E: pkcs8::EncodePrivateKey,
{
    Ok(match format {
        KeyFormat::Pem => input
            .to_pkcs8_pem(base64ct::LineEnding::LF)
            .context("invalid pkcs8 private key to pem")?
            .as_bytes()
            .to_vec(),
        KeyFormat::Der => input
            .to_pkcs8_der()
            .context("invalid pkcs8 private key to der")?
            .as_bytes()
            .to_vec(),
    })
}
pub(crate) fn public_pkcs8_to_bytes<E>(
    input: E,
    encoding: KeyFormat,
) -> Result<Vec<u8>>
where
    E: spki::EncodePublicKey,
{
    Ok(match encoding {
        KeyFormat::Pem => input
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("invalid pkcs8 public key to pem")?
            .into_bytes(),
        KeyFormat::Der => input
            .to_public_key_der()
            .context("invalid pkcs8 public key to der")?
            .to_vec(),
    })
}
