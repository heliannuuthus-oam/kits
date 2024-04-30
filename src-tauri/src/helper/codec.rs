use anyhow::Context;
use base64ct::{
    Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding,
};
use serde_bytes::ByteBuf;
use tracing::info;

use super::{
    enums::{EccCurveName, KeyEncoding},
    errors::{Error, Result},
};
use crate::helper::enums::PkcsEncoding;

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct PkcsDto {
   pub pkcs: PkcsEncoding,
    pub encoding: KeyEncoding,
}

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

#[tauri::command]
pub fn pkcs8_sec1_transfer(
    curve_name: EccCurveName,
    input: ByteBuf,
    from: PkcsDto,
    to: PkcsDto,
    is_public: bool,
) -> Result<ByteBuf> {
    info!(
        "pkcs8_sec1_converter, curve_name: {:?}, from: {:?}, to: {:?}, \
         public: {:?}",
        curve_name, from, to, is_public
    );
    Ok(ByteBuf::from(match curve_name {
        EccCurveName::NistP256 => pkcs8_sec1_transfer_inner::<p256::NistP256>(
            input.as_ref(),
            is_public,
            from,
            to,
        )?,
        EccCurveName::NistP384 => pkcs8_sec1_transfer_inner::<p384::NistP384>(
            input.as_ref(),
            is_public,
            from,
            to,
        )?,
        EccCurveName::NistP521 => pkcs8_sec1_transfer_inner::<p521::NistP521>(
            input.as_ref(),
            is_public,
            from,
            to,
        )?,
        EccCurveName::Secp256k1 => {
            pkcs8_sec1_transfer_inner::<k256::Secp256k1>(
                input.as_ref(),
                is_public,
                from,
                to,
            )?
        }
    }))
}

fn pkcs8_sec1_transfer_inner<C>(
    input: &[u8],
    is_public: bool,
    from: PkcsDto,
    to: PkcsDto,
) -> Result<Vec<u8>>
where
    C: pkcs8::AssociatedOid + elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    match from.pkcs {
        PkcsEncoding::Pkcs8 => {
            if is_public {
                let key = public_bytes_to_pkcs8::<elliptic_curve::PublicKey<C>>(
                    input,
                    from.encoding,
                )?;
                match to.pkcs {
                    PkcsEncoding::Pkcs8 => {
                        public_pkcs8_to_bytes(key, to.encoding)
                    }
                    PkcsEncoding::Sec1 => {
                        public_sec1_to_bytes(key, to.encoding)
                    }
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            } else {
                let key = private_bytes_to_pkcs8::<elliptic_curve::SecretKey<C>>(
                    input,
                    from.encoding,
                )?;
                match to.pkcs {
                    PkcsEncoding::Pkcs8 => {
                        private_pkcs8_to_bytes(key, to.encoding)
                    }
                    PkcsEncoding::Sec1 => {
                        private_sec1_to_bytes(key, to.encoding)
                    }
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            }
        }
        PkcsEncoding::Sec1 => {
            if is_public {
                let key = public_bytes_to_sec1::<elliptic_curve::PublicKey<C>>(
                    input,
                    from.encoding,
                )?;
                match to.pkcs {
                    PkcsEncoding::Pkcs8 => {
                        public_pkcs8_to_bytes(key, to.encoding)
                    }
                    PkcsEncoding::Sec1 => {
                        public_sec1_to_bytes(key, to.encoding)
                    }
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            } else {
                let key = private_bytes_to_sec1::<elliptic_curve::SecretKey<C>>(
                    input,
                    from.encoding,
                )?;
                match to.pkcs {
                    PkcsEncoding::Pkcs8 => {
                        private_pkcs8_to_bytes(key, to.encoding)
                    }
                    PkcsEncoding::Sec1 => {
                        private_sec1_to_bytes(key, to.encoding)
                    }
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            }
        }
        _ => Err(Error::Unsupported("only supported ecc key".to_string())),
    }
}

#[tauri::command]
pub fn pkcs8_pkcs1_transfer(
    input: ByteBuf,
    from: PkcsDto,
    to: PkcsDto,
    is_public: bool,
) -> Result<ByteBuf> {
    Ok(ByteBuf::from(pkcs8_pkcs1_transfer_inner(
        &input, from, to, is_public,
    )?))
}

fn pkcs8_pkcs1_transfer_inner(
    input: &[u8],
    from: PkcsDto,
    to: PkcsDto,
    is_public: bool,
) -> Result<Vec<u8>> {
    match from.pkcs {
        PkcsEncoding::Pkcs8 => {
            if is_public {
                let key = public_bytes_to_pkcs8::<rsa::RsaPublicKey>(
                    input,
                    from.encoding,
                )?;
                match to.pkcs {
                    PkcsEncoding::Pkcs8 => {
                        public_pkcs8_to_bytes(key, to.encoding)
                    }
                    PkcsEncoding::Pkcs1 => {
                        public_pkcs1_to_bytes(key, to.encoding)
                    }
                    _ => Err(Error::Unsupported(
                        "only supported rsa key".to_string(),
                    )),
                }
            } else {
                let key = private_bytes_to_pkcs8::<rsa::RsaPrivateKey>(
                    input,
                    from.encoding,
                )?;
                match to.pkcs {
                    PkcsEncoding::Pkcs8 => {
                        private_pkcs8_to_bytes(key, to.encoding)
                    }
                    PkcsEncoding::Pkcs1 => {
                        private_pkcs1_to_bytes(key, to.encoding)
                    }
                    _ => Err(Error::Unsupported(
                        "only supported rsa key".to_string(),
                    )),
                }
            }
        }
        PkcsEncoding::Pkcs1 => {
            if is_public {
                let key = public_bytes_to_pkcs8::<rsa::RsaPublicKey>(
                    input,
                    from.encoding,
                )?;
                match to.pkcs {
                    PkcsEncoding::Pkcs8 => {
                        public_pkcs8_to_bytes(key, to.encoding)
                    }
                    PkcsEncoding::Sec1 => {
                        public_sec1_to_bytes(key, to.encoding)
                    }
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            } else {
                let key = private_bytes_to_pkcs8::<rsa::RsaPrivateKey>(
                    input,
                    from.encoding,
                )?;
                match to.pkcs {
                    PkcsEncoding::Pkcs8 => {
                        private_pkcs8_to_bytes(key, to.encoding)
                    }
                    PkcsEncoding::Pkcs1 => {
                        private_pkcs1_to_bytes(key, to.encoding)
                    }
                    _ => Err(Error::Unsupported(
                        "only supported rsa key".to_string(),
                    )),
                }
            }
        }
        _ => Err(Error::Unsupported("only supported rsa key".to_string())),
    }
}

// =================================== pkcs8 start
// ===================================
fn private_bytes_to_pkcs8<E>(input: &[u8], encoding: KeyEncoding) -> Result<E>
where
    E: pkcs8::DecodePrivateKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_pkcs8_pem(&key_string)
                .context("invalid sec1 pem private key")?
        }
        KeyEncoding::Der => {
            E::from_pkcs8_der(input).context("invalid sec1 der private key")?
        }
    })
}

fn public_bytes_to_pkcs8<E>(input: &[u8], encoding: KeyEncoding) -> Result<E>
where
    E: pkcs8::DecodePublicKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_public_key_pem(&key_string)
                .context("invalid sec1 pem public key")?
        }
        KeyEncoding::Der => E::from_public_key_der(input)
            .context("invalid sec1 der public key")?,
    })
}

fn private_pkcs8_to_bytes<E>(input: E, encoding: KeyEncoding) -> Result<Vec<u8>>
where
    E: pkcs8::EncodePrivateKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => input
            .to_pkcs8_pem(base64ct::LineEnding::LF)
            .context("invalid pkcs8 pem private key")?
            .as_bytes()
            .to_vec(),
        KeyEncoding::Der => input
            .to_pkcs8_der()
            .context("invalid pkcs8 der private key")?
            .as_bytes()
            .to_vec(),
    })
}
fn public_pkcs8_to_bytes<E>(input: E, encoding: KeyEncoding) -> Result<Vec<u8>>
where
    E: spki::EncodePublicKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => input
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("invalid pkcs8 pem public key")?
            .into_bytes(),
        KeyEncoding::Der => input
            .to_public_key_der()
            .context("invalid pkcs8 der public key")?
            .to_vec(),
    })
}
// =================================== pkcs8 end
// ===================================

// =================================== pkcs1 start
// ===================================
fn public_bytes_to_pkcs1<E>(input: &[u8], encoding: KeyEncoding) -> Result<E>
where
    E: pkcs1::DecodeRsaPublicKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_pkcs1_pem(&key_string)
                .context("invalid pkcs1 pem public key")?
        }
        KeyEncoding::Der => {
            E::from_pkcs1_der(input).context("invalid pkcs1 der public key")?
        }
    })
}

fn private_bytes_to_pkcs1<E>(input: &[u8], encoding: KeyEncoding) -> Result<E>
where
    E: pkcs1::DecodeRsaPrivateKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            <E as pkcs1::DecodeRsaPrivateKey>::from_pkcs1_pem(&key_string)
                .context("invalid pkcs1 pem private key")?
        }
        KeyEncoding::Der => {
            <E as pkcs1::DecodeRsaPrivateKey>::from_pkcs1_der(input)
                .context("invalid pkcs1 der private key")?
        }
    })
}

fn private_pkcs1_to_bytes<E>(input: E, encoding: KeyEncoding) -> Result<Vec<u8>>
where
    E: pkcs1::EncodeRsaPrivateKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => input
            .to_pkcs1_pem(base64ct::LineEnding::LF)
            .context("invalid pkcs1 pem private key")?
            .as_bytes()
            .to_vec(),
        KeyEncoding::Der => input
            .to_pkcs1_der()
            .context("invalid pkcs1 der key")?
            .as_bytes()
            .to_vec(),
    })
}

fn public_pkcs1_to_bytes<E>(input: E, encoding: KeyEncoding) -> Result<Vec<u8>>
where
    E: pkcs1::EncodeRsaPublicKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => input
            .to_pkcs1_pem(base64ct::LineEnding::LF)
            .context("invalid pkcs1 pem public key")?
            .as_bytes()
            .to_vec(),
        KeyEncoding::Der => input
            .to_pkcs1_der()
            .context("invalid pkcs1 der key")?
            .as_bytes()
            .to_vec(),
    })
}
// =================================== pkcs1 end
// =================================== =================================== sec1
// start ===================================

fn private_bytes_to_sec1<E>(input: &[u8], encoding: KeyEncoding) -> Result<E>
where
    E: sec1::DecodeEcPrivateKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_sec1_pem(&key_string)
                .context("invalid sec1 pem public key")?
        }
        KeyEncoding::Der => {
            E::from_sec1_der(input).context("invalid sec1 der public key")?
        }
    })
}

fn public_bytes_to_sec1<E>(input: &[u8], encoding: KeyEncoding) -> Result<E>
where
    E: spki::DecodePublicKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_public_key_pem(&key_string)
                .context("invalid sec1 pem public key")?
        }
        KeyEncoding::Der => E::from_public_key_der(input)
            .context("invalid sec1 der public key")?,
    })
}

fn private_sec1_to_bytes<E>(input: E, encoding: KeyEncoding) -> Result<Vec<u8>>
where
    E: sec1::EncodeEcPrivateKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => input
            .to_sec1_pem(base64ct::LineEnding::LF)
            .context("to sec1 pem private key failed")?
            .as_bytes()
            .to_vec(),
        KeyEncoding::Der => input
            .to_sec1_der()
            .context("to sec1 der private key failed")?
            .as_bytes()
            .to_vec(),
    })
}

fn public_sec1_to_bytes<E>(input: E, encoding: KeyEncoding) -> Result<Vec<u8>>
where
    E: spki::EncodePublicKey,
{
    Ok(match encoding {
        KeyEncoding::Pem => input
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("to sec1 pem public key failed")?
            .as_bytes()
            .to_vec(),
        KeyEncoding::Der => input
            .to_public_key_der()
            .context("to sec1 der public key failed")?
            .as_bytes()
            .to_vec(),
    })
}
