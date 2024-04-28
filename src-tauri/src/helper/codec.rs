use anyhow::Context;
use base64ct::{
    Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding,
};
use pkcs1::EncodeRsaPublicKey;
use serde_bytes::ByteBuf;
use crate::helper::enums::PkcsEncoding;

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


fn sec1_pem_to_der<E>(input: E, is_public: bool) -> Result<ByteBuf>
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


fn bytes_to_pkcs8<E>(input: &[u8], is_public: bool, encoding: KeyEncoding) -> Result<E>
    where E: spki::DecodePublicKey + pkcs8::DecodePrivateKey {
    match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec()).context("invalid utf-8 key")?;
            if is_public {
                E::from_public_key_pem(&key_string)
                    .context("invalid sec1 pem public key")?
            } else {
                E::from_pkcs8_pem(&key_string)
                    .context("invalid sec1 pem private key")?
            }
        }
        KeyEncoding::Der => {
            if is_public {
                E::from_public_key_der(input)
                    .context("invalid sec1 der public key")?
            } else {
                E::from_pkcs8_der(input)
                    .context("invalid sec1 der private key")?
            }
        }
    }
}

fn pkcs8_to_bytes<E>(input: E, is_public: bool, encoding: KeyEncoding) -> Result<Vec<u8>>
    where E: spki::EncodePublicKey + pkcs8::EncodePrivateKey {
    Ok(match encoding {
        KeyEncoding::Pem => {
            if is_public {
                input.to_public_key_pem(base64ct::LineEnding::LF)
                    .context("invalid pkcs8 pem public key")?
                    .into_bytes()
            } else {
                input.to_pkcs1_pem(base64ct::LineEnding::LF)
                    .context("invalid pkcs8 pem private key")?
                    .into_bytes()
            }
        }
        KeyEncoding::Der => {
            if is_public {
                input.to_public_key_der()
                    .context("invalid pkcs8 der public key")?
                    .to_bytes().to_vec()
            } else {
                input.to_pkcs8_der()
                    .context("invalid pkcs8 der private key")?
                    .to_bytes().to_vec()
            }
        }
    })
}


fn bytes_to_pkcs1<E>(input: &[u8], encoding: KeyEncoding) -> Result<E>
    where E: pkcs1::DecodeRsaPrivateKey + pkcs1::DecodeRsaPublicKey {
    match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec()).context("invalid utf-8 key")?;
            E::from_pkcs1_pem(&key_string)
                .context("invalid pkcs1 pem key")?
        }
        KeyEncoding::Der => {
            E::from_pkcs1_der(input)
                .context("invalid pkcs1 der key")?
        }
    }
}

fn pkcs1_to_bytes<E>(input: E, encoding: KeyEncoding) -> Result<Vec<u8>>
    where E: pkcs1::EncodeRsaPrivateKey + pkcs1::EncodeRsaPublicKey {
    Ok(match encoding {
        KeyEncoding::Pem => {
            input.to_pkcs1_pem(base64ct::LineEnding::LF).context("invalid pkcs1 pem key")
                .as_bytes().to_vec()
        }
        KeyEncoding::Der => {
            input.to_pkcs1_der().context("invalid pkcs1 der key")?
                .as_bytes().to_vec()
        }
    })
}


fn bytes_to_sec1<E>(input: &[u8], encoding: KeyEncoding) -> Result<E>
    where E: sec1::DecodeEcPrivateKey + sec1:: {
    match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec()).context("invalid utf-8 key")?;
            E::from_pkcs1_pem(&key_string)
                .context("invalid pkcs1 pem key")?
        }
        KeyEncoding::Der => {
            E::from_pkcs1_der(input)
                .context("invalid pkcs1 der key")?
        }
    }
}

fn sec1_to_bytes<E>(input: E, encoding: KeyEncoding) -> Result<Vec<u8>>
    where E: pkcs1::EncodeRsaPrivateKey + pkcs1::EncodeRsaPublicKey {
    Ok(match encoding {
        KeyEncoding::Pem => {
            input.to_pkcs1_pem(base64ct::LineEnding::LF).context("invalid pkcs1 pem key")
                .as_bytes().to_vec()
        }
        KeyEncoding::Der => {
            input.to_pkcs1_der().context("invalid pkcs1 der key")?
                .as_bytes().to_vec()
        }
    })
}

fn sec1_to_pkcs8<E>(input: &[u8], is_public: bool, from: KeyEncoding, to: KeyEncoding) -> Result<Vec<u8>>
    where E: pkcs8::EncodePublicKey + pkcs8::EncodePrivateKey
    + sec1::DecodeEcPrivateKey + spki::DecodePublicKey {
    let pkcs8_key = match from {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec()).context("invalid utf-8 key")?;
            if is_public {
                E::from_public_key_pem(&key_string)
                    .context("invalid sec1 pem public key")?
            } else {
                E::from_sec1_pem(&key_string)
                    .context("invalid sec1 pem private key")?
            }
        }
        KeyEncoding::Der => {
            if is_public {
                E::from_public_key_der(input)
                    .context("invalid sec1 der public key")?
            } else {
                E::from_sec1_der(input)
                    .context("invalid sec1 der private key")?
            }
        }
    };

    Ok(match to {
        KeyEncoding::Pem => {
            if is_public {
                pkcs8_key
                    .to_public_key_pem(base64ct::LineEnding::LF)
                    .context("invalid pkcs8 pem public key")?
                    .as_bytes()
                    .to_vec()
            } else {
                pkcs8_key
                    .to_pkcs8_pem(base64ct::LineEnding::LF)
                    .context("invalid pkcs8 pem private key")?
                    .as_bytes()
                    .to_vec()
            }
        }
        KeyEncoding::Der => {
            if is_public {
                pkcs8_key
                    .to_public_key_der()
                    .context("invalid pkcs8 der public key")?
                    .as_bytes()
                    .to_vec()
            } else {
                pkcs8_key
                    .to_pkcs8_der()
                    .context("invalid pkcs8 der private key")?
                    .as_bytes()
                    .to_vec()
            }
        }
    })
}

fn pkcs8_to_sec1<E>(input: &[u8], is_public: bool, from: KeyEncoding, to: KeyEncoding) -> Result<Vec<u8>>
    where E: pkcs8::DecodePublicKey + pkcs8::DecodePrivateKey
    + sec1::EncodeEcPrivateKey + spki::EncodePublicKey {
    let pkcs8_key = match from {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec()).context("invalid utf-8 key")?;
            if is_public {
                E::from_public_key_pem(&key_string)
                    .context("invalid pkcs8 pem public key")?
            } else {
                E::from_pkcs8_pem(&key_string)
                    .context("invalid pkcs8 pem private key")?
            }
        }
        KeyEncoding::Der => {
            if is_public {
                E::from_public_key_der(input)
                    .context("invalid pkcs8 der public key")?
            } else {
                E::from_pkcs8_der(input)
                    .context("invalid pkcs8 der private key")?
            }
        }
    };

    Ok(match to {
        KeyEncoding::Pem => {
            if is_public {
                pkcs8_key
                    .to_public_key_pem(base64ct::LineEnding::LF)
                    .context("invalid sec1 pem public key")?
                    .as_bytes()
                    .to_vec()
            } else {
                pkcs8_key
                    .to_sec1_pem(base64ct::LineEnding::LF)
                    .context("invalid sec1 pem private key")?
                    .as_bytes()
                    .to_vec()
            }
        }
        KeyEncoding::Der => {
            if is_public {
                pkcs8_key
                    .to_public_key_der()
                    .context("invalid sec1 der public key")?
                    .as_bytes()
                    .to_vec()
            } else {
                pkcs8_key
                    .to_sec1_der()
                    .context("invalid sec1 der private key")?
                    .as_bytes()
                    .to_vec()
            }
        }
    })
}


fn pkcs1_to_pkcs8<E>(input: &[u8], is_public: bool, from: KeyEncoding, to: KeyEncoding) -> Result<Vec<u8>>
    where E: pkcs8::EncodePublicKey + pkcs8::EncodePrivateKey
    + sec1::DecodeEcPrivateKey + sec1::DecodeEcPrivateKey {
    let pkcs8_key = match from {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec()).context("invalid utf-8 key")?;
            if is_public {
                E::from_sec1_pem(&key_string)
                    .context("invalid sec1 pem public key")?
            } else {
                E::from_sec1_pem(&key_string)
                    .context("invalid sec1 pem private key")?
            }
        }
        KeyEncoding::Der => {
            if is_public {
                E::from_sec1_der(input)
                    .context("invalid sec1 der public key")?
            } else {
                E::from_sec1_der(input)
                    .context("invalid sec1 der private key")?
            }
        }
    };

    Ok(match to {
        KeyEncoding::Pem => {
            if is_public {
                pkcs8_key
                    .to_public_key_pem(base64ct::LineEnding::LF)
                    .context("invalid pkcs8 pem public key")?
                    .as_bytes()
                    .to_vec()
            } else {
                pkcs8_key
                    .to_pkcs8_pem(base64ct::LineEnding::LF)
                    .context("invalid pkcs8 pem private key")?
                    .as_bytes()
                    .to_vec()
            }
        }
        KeyEncoding::Der => {
            if is_public {
                pkcs8_key
                    .to_public_key_der()
                    .context("invalid pkcs8 der public key")?
                    .as_bytes()
                    .to_vec()
            } else {
                pkcs8_key
                    .to_pkcs8_der()
                    .context("invalid pkcs8 der private key")?
                    .as_bytes()
                    .to_vec()
            }
        }
    })
}

fn pkcs8_to_pkcs1<E>(input: &[u8], is_public: bool, from: KeyEncoding, to: KeyEncoding) -> Result<Vec<u8>>
    where E: pkcs8::DecodePublicKey + pkcs8::DecodePrivateKey
    + pkcs1::EncodeRsaPrivateKey + pkcs1::EncodeRsaPublicKey {
    let pkcs8_key = match from {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec()).context("invalid utf-8 key")?;
            if is_public {
                E::from_public_key_pem(&key_string)
                    .context("invalid pkcs8 pem public key")?
            } else {
                E::from_pkcs8_pem(&key_string)
                    .context("invalid pkcs8 pem private key")?
            }
        }
        KeyEncoding::Der => {
            if is_public {
                E::from_public_key_der(input)
                    .context("invalid pkcs8 der public key")?
            } else {
                E::from_pkcs8_der(input)
                    .context("invalid pkcs8 der private key")?
            }
        }
    };

    Ok(match to {
        KeyEncoding::Pem => {
            if is_public {
                pkcs8_key
                    .to_pkcs1_pem(base64ct::LineEnding::LF)
                    .context("invalid sec1 pem public key")?
                    .as_bytes()
                    .to_vec()
            } else {
                pkcs8_key
                    .to_pkcs1_pem(base64ct::LineEnding::LF)
                    .context("invalid sec1 pem private key")?
                    .as_bytes()
                    .to_vec()
            }
        }
        KeyEncoding::Der => {
            if is_public {
                pkcs8_key
                    .to_public_key_der()
                    .context("invalid sec1 der public key")?
                    .as_bytes()
                    .to_vec()
            } else {
                pkcs8_key
                    .to_sec1_der()
                    .context("invalid sec1 der private key")?
                    .as_bytes()
                    .to_vec()
            }
        }
    })
}

fn pkcs8_pem_to_der<E>(input: E, is_public: bool) -> Result<ByteBuf>
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

fn pkcs8_der_to_pem<E>(input: E, is_public: bool) -> Result<ByteBuf>
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
