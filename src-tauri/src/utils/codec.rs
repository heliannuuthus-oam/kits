use anyhow::Context;
use base64ct::{
    Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding,
};
use elliptic_curve::{
    point::PointCompression,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, FieldBytesSize,
};
use sec1::point::ModulusSize;

use super::{
    enums::{EccCurveName, KeyFormat, TextEncoding},
    errors::{Error, Result},
};
use crate::utils::enums::Pkcs;

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

pub fn pkcs8_sec1_converter(
    curve_name: EccCurveName,
    input: &[u8],
    from: PkcsDto,
    to: PkcsDto,
    is_public: bool,
) -> Result<Vec<u8>> {
    match curve_name {
        EccCurveName::NistP256 => pkcs8_sec1_converter_inner::<p256::NistP256>(
            input, from, to, is_public,
        ),
        EccCurveName::NistP384 => pkcs8_sec1_converter_inner::<p384::NistP384>(
            input, from, to, is_public,
        ),
        EccCurveName::NistP521 => pkcs8_sec1_converter_inner::<p521::NistP521>(
            input, from, to, is_public,
        ),
        EccCurveName::Secp256k1 => {
            pkcs8_sec1_converter_inner::<k256::Secp256k1>(
                input, from, to, is_public,
            )
        }
        EccCurveName::SM2 => {
            pkcs8_sec1_converter_inner::<sm2::Sm2>(input, from, to, is_public)
        }
    }
}

fn pkcs8_sec1_converter_inner<C>(
    input: &[u8],
    from: PkcsDto,
    to: PkcsDto,
    is_public: bool,
) -> Result<Vec<u8>>
where
    C: pkcs8::AssociatedOid
        + elliptic_curve::CurveArithmetic
        + PointCompression,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    match from.pkcs {
        Pkcs::Pkcs8 => {
            if is_public {
                let key = public_bytes_to_pkcs8::<elliptic_curve::PublicKey<C>>(
                    input,
                    from.format,
                )?;
                match to.pkcs {
                    Pkcs::Pkcs8 => public_pkcs8_to_bytes(key, to.format),
                    Pkcs::Sec1 => public_sec1_to_bytes::<C>(key),
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            } else {
                let key = private_bytes_to_pkcs8::<elliptic_curve::SecretKey<C>>(
                    input,
                    from.format,
                )?;
                match to.pkcs {
                    Pkcs::Pkcs8 => private_pkcs8_to_bytes(key, to.format),
                    Pkcs::Sec1 => private_sec1_to_bytes(key, to.format),
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            }
        }
        Pkcs::Sec1 => {
            if is_public {
                let key = public_bytes_to_sec1::<C>(input)?;
                match to.pkcs {
                    Pkcs::Pkcs8 => public_pkcs8_to_bytes(key, to.format),
                    Pkcs::Sec1 => public_sec1_to_bytes::<C>(key),
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            } else {
                let key = private_bytes_to_sec1::<elliptic_curve::SecretKey<C>>(
                    input,
                    from.format,
                )?;
                match to.pkcs {
                    Pkcs::Pkcs8 => private_pkcs8_to_bytes(key, to.format),
                    Pkcs::Sec1 => private_sec1_to_bytes(key, to.format),
                    _ => Err(Error::Unsupported(
                        "only supported ecc key".to_string(),
                    )),
                }
            }
        }
        _ => Err(Error::Unsupported("only supported ecc key".to_string())),
    }
}

pub(crate) fn pkcs8_pkcs1_converter_inner(
    input: &[u8],
    from: PkcsDto,
    to: PkcsDto,
    is_public: bool,
) -> Result<Vec<u8>> {
    match from.pkcs {
        Pkcs::Pkcs8 => {
            if is_public {
                let key = public_bytes_to_pkcs8::<rsa::RsaPublicKey>(
                    input,
                    from.format,
                )?;
                match to.pkcs {
                    Pkcs::Pkcs8 => public_pkcs8_to_bytes(key, to.format),
                    Pkcs::Pkcs1 => public_pkcs1_to_bytes(key, to.format),
                    _ => Err(Error::Unsupported(
                        "only supported rsa key".to_string(),
                    )),
                }
            } else {
                let key = private_bytes_to_pkcs8::<rsa::RsaPrivateKey>(
                    input,
                    from.format,
                )?;
                match to.pkcs {
                    Pkcs::Pkcs8 => private_pkcs8_to_bytes(key, to.format),
                    Pkcs::Pkcs1 => private_pkcs1_to_bytes(key, to.format),
                    _ => Err(Error::Unsupported(
                        "only supported rsa key".to_string(),
                    )),
                }
            }
        }
        Pkcs::Pkcs1 => {
            if is_public {
                let key = public_bytes_to_pkcs1::<rsa::RsaPublicKey>(
                    input,
                    from.format,
                )?;
                match to.pkcs {
                    Pkcs::Pkcs8 => public_pkcs8_to_bytes(key, to.format),
                    Pkcs::Pkcs1 => public_pkcs1_to_bytes(key, to.format),
                    _ => Err(Error::Unsupported(
                        "only supported rsa key".to_string(),
                    )),
                }
            } else {
                let key = private_bytes_to_pkcs1::<rsa::RsaPrivateKey>(
                    input,
                    from.format,
                )?;
                match to.pkcs {
                    Pkcs::Pkcs8 => private_pkcs8_to_bytes(key, to.format),
                    Pkcs::Pkcs1 => private_pkcs1_to_bytes(key, to.format),
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
                .context("invalid sec1 pem private key")?
        }
        KeyFormat::Der => {
            E::from_pkcs8_der(input).context("invalid sec1 der private key")?
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
            .context("invalid pkcs8 pem private key")?
            .as_bytes()
            .to_vec(),
        KeyFormat::Der => input
            .to_pkcs8_der()
            .context("invalid pkcs8 der private key")?
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
            .context("invalid pkcs8 pem public key")?
            .into_bytes(),
        KeyFormat::Der => input
            .to_public_key_der()
            .context("invalid pkcs8 der public key")?
            .to_vec(),
    })
}
// =================================== pkcs8 end
// ===================================

// =================================== pkcs1 start
// ===================================
pub(crate) fn public_bytes_to_pkcs1<E>(
    input: &[u8],
    encoding: KeyFormat,
) -> Result<E>
where
    E: pkcs1::DecodeRsaPublicKey,
{
    Ok(match encoding {
        KeyFormat::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_pkcs1_pem(&key_string)
                .context("invalid pkcs1 pem public key")?
        }
        KeyFormat::Der => {
            E::from_pkcs1_der(input).context("invalid pkcs1 der public key")?
        }
    })
}

pub(crate) fn private_bytes_to_pkcs1<E>(
    input: &[u8],
    format: KeyFormat,
) -> Result<E>
where
    E: pkcs1::DecodeRsaPrivateKey,
{
    Ok(match format {
        KeyFormat::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            <E as pkcs1::DecodeRsaPrivateKey>::from_pkcs1_pem(&key_string)
                .context("invalid pkcs1 pem private key")?
        }
        KeyFormat::Der => {
            <E as pkcs1::DecodeRsaPrivateKey>::from_pkcs1_der(input)
                .context("invalid pkcs1 der private key")?
        }
    })
}

pub(crate) fn private_pkcs1_to_bytes<E>(
    input: E,
    format: KeyFormat,
) -> Result<Vec<u8>>
where
    E: pkcs1::EncodeRsaPrivateKey,
{
    Ok(match format {
        KeyFormat::Pem => input
            .to_pkcs1_pem(base64ct::LineEnding::LF)
            .context("invalid pkcs1 pem key")?
            .as_bytes()
            .to_vec(),
        KeyFormat::Der => input
            .to_pkcs1_der()
            .context("invalid pkcs1 der key")?
            .as_bytes()
            .to_vec(),
    })
}

pub(crate) fn public_pkcs1_to_bytes<E>(
    input: E,
    encoding: KeyFormat,
) -> Result<Vec<u8>>
where
    E: pkcs1::EncodeRsaPublicKey,
{
    Ok(match encoding {
        KeyFormat::Pem => input
            .to_pkcs1_pem(base64ct::LineEnding::LF)
            .context("invalid pkcs1 pem public key")?
            .as_bytes()
            .to_vec(),
        KeyFormat::Der => input
            .to_pkcs1_der()
            .context("invalid pkcs1 der key")?
            .as_bytes()
            .to_vec(),
    })
}
// =================================== pkcs1 end
// =================================== =================================== sec1
// start ===================================

pub(crate) fn private_bytes_to_sec1<E>(
    input: &[u8],
    encoding: KeyFormat,
) -> Result<E>
where
    E: sec1::DecodeEcPrivateKey,
{
    Ok(match encoding {
        KeyFormat::Pem => {
            let key_string = String::from_utf8(input.to_vec())
                .context("invalid utf-8 key")?;
            E::from_sec1_pem(&key_string)
                .context("invalid sec1 pem private key")?
        }
        KeyFormat::Der => {
            E::from_sec1_der(input).context("invalid sec1 der private key")?
        }
    })
}

pub(crate) fn public_bytes_to_sec1<C>(
    input: &[u8],
) -> Result<elliptic_curve::PublicKey<C>>
where
    C: PointCompression + elliptic_curve::CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    Ok(elliptic_curve::PublicKey::<C>::from_sec1_bytes(input)
        .context("invalid sec1 pem public key")?)
}

pub(crate) fn private_sec1_to_bytes<E>(
    input: E,
    encoding: KeyFormat,
) -> Result<Vec<u8>>
where
    E: sec1::EncodeEcPrivateKey,
{
    Ok(match encoding {
        KeyFormat::Pem => input
            .to_sec1_pem(base64ct::LineEnding::LF)
            .context("to sec1 pem private key failed")?
            .as_bytes()
            .to_vec(),
        KeyFormat::Der => input
            .to_sec1_der()
            .context("to sec1 der private key failed")?
            .as_bytes()
            .to_vec(),
    })
}

pub(crate) fn public_sec1_to_bytes<C>(
    input: elliptic_curve::PublicKey<C>,
) -> Result<Vec<u8>>
where
    C: PointCompression + elliptic_curve::CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    Ok(input.to_sec1_bytes().to_vec())
}
