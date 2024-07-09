use anyhow::Context;
use elliptic_curve::{
    point::PointCompression,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, FieldBytesSize,
};
use k256::Secp256k1;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pem_rfc7468::PemLabel;
use pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
};
use sec1::point::ModulusSize;
use serde::{Deserialize, Serialize};
use sm2::Sm2;
use tracing::info;

use crate::{
    codec::{
        private_bytes_to_pkcs8, private_pkcs8_to_bytes, public_bytes_to_pkcs8,
        public_pkcs8_to_bytes, PkcsDto,
    },
    enums::{EccCurveName, KeyFormat, Pkcs, TextEncoding},
    errors::{Error, Result},
    utils::KeyTuple,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct EccKeyInfo {
    curve_name: EccCurveName,
    encoding: TextEncoding,
    format: KeyFormat,
    pkcs: Pkcs,
}

#[tauri::command]
pub fn generate_ecc(
    curve_name: EccCurveName,
    pkcs: Pkcs,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<KeyTuple> {
    info!(
        "generate ecc key, curve_name: {:?}, pkcs: {:?}, format: {:?}, \
         encoding: {:?}",
        curve_name, pkcs, format, encoding
    );
    let (private_key_bytes, public_key_bytes) = (match curve_name {
        EccCurveName::NistP256 => {
            generate_ecc_key::<p256::NistP256>(pkcs, format)
        }
        EccCurveName::NistP384 => {
            generate_ecc_key::<p384::NistP384>(pkcs, format)
        }
        EccCurveName::NistP521 => {
            generate_ecc_key::<p521::NistP521>(pkcs, format)
        }
        EccCurveName::Secp256k1 => {
            generate_ecc_key::<k256::Secp256k1>(pkcs, format)
        }
        EccCurveName::SM2 => generate_ecc_key::<sm2::Sm2>(pkcs, format),
    })?;

    Ok(KeyTuple::new(
        encoding.encode(&private_key_bytes)?,
        encoding.encode(&public_key_bytes)?,
    ))
}

#[tauri::command]
pub fn derive_ecc(
    curve_name: EccCurveName,
    input: String,
    pkcs: Pkcs,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<String> {
    let key_bytes = encoding.decode(&input)?;
    let public_key_bytes = (match curve_name {
        EccCurveName::NistP256 => {
            derive_ecc_inner::<NistP256>(&key_bytes, pkcs, format)
        }
        EccCurveName::NistP384 => {
            derive_ecc_inner::<p384::NistP384>(&key_bytes, pkcs, format)
        }
        EccCurveName::NistP521 => {
            derive_ecc_inner::<p521::NistP521>(&key_bytes, pkcs, format)
        }
        EccCurveName::Secp256k1 => {
            derive_ecc_inner::<k256::Secp256k1>(&key_bytes, pkcs, format)
        }
        EccCurveName::SM2 => {
            derive_ecc_inner::<sm2::Sm2>(&key_bytes, pkcs, format)
        }
    })?;
    encoding.encode(&public_key_bytes)
}

#[tauri::command]
pub async fn transfer_ecc_key(
    curve_name: EccCurveName,
    private_key: Option<String>,
    public_key: Option<String>,
    from: PkcsDto,
    to: PkcsDto,
) -> Result<KeyTuple> {
    info!(
        "ecc key format transfer, curve_name: {:?}, {:?} to {:?}. \
         private->{}, public->{}",
        curve_name,
        from,
        to,
        private_key.is_some(),
        public_key.is_some()
    );

    let mut tuple = KeyTuple::empty();

    tuple
        .private(if let Some(key) = private_key {
            if !key.trim().is_empty() {
                let key_bytes = from.encoding.decode(&key)?;
                let private_bytes = pkcs8_sec1_converter(
                    curve_name,
                    key_bytes.as_slice(),
                    from,
                    to,
                    false,
                )?;
                Some(to.encoding.encode(&private_bytes)?)
            } else {
                None
            }
        } else {
            None
        })
        .public(if let Some(key) = public_key {
            if !key.trim().is_empty() {
                let key_bytes = from.encoding.decode(&key)?;
                let public_bytes = pkcs8_sec1_converter(
                    curve_name,
                    key_bytes.as_slice(),
                    from,
                    to,
                    true,
                )?;
                Some(to.encoding.encode(&public_bytes)?)
            } else {
                None
            }
        } else {
            None
        });
    Ok(tuple)
}

fn generate_ecc_key<C>(
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<(Vec<u8>, Vec<u8>)>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let mut rng = rand::thread_rng();
    let secret_key = elliptic_curve::SecretKey::<C>::random(&mut rng);
    let private_key = export_ecc_private_key(&secret_key, pkcs, format)?;
    let public_secret_key = secret_key.public_key();
    let public_key = export_ecc_public_key(public_secret_key, format)?;
    Ok((private_key, public_key))
}

fn derive_ecc_inner<C>(
    input: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let ecc_private_key = import_ecc_private_key::<C>(input, pkcs, format)?;
    export_ecc_public_key(ecc_private_key.public_key(), format)
}

#[tauri::command]
pub fn parse_ecc(input: String) -> Result<EccKeyInfo> {
    info!("parse ecc: {}", input.len());
    let pem_decodor = |(input, format): (&str, KeyFormat)| {
        let (label, _) =
            pem_rfc7468::decode_vec(input.as_bytes()).context("invalid pem")?;

        let pkcs = match label {
            sec1::EcPrivateKey::PEM_LABEL => Pkcs::Sec1,
            pkcs8::PrivateKeyInfo::PEM_LABEL => Pkcs::Pkcs8,
            spki::SubjectPublicKeyInfoOwned::PEM_LABEL => Pkcs::Spki,
            _ => return Err(Error::Unsupported(label.to_string())),
        };

        let curve_name = parse_curve_name(input.as_bytes(), pkcs, format)?;
        Ok((pkcs, curve_name))
    };

    let (key, encoding) = if let Ok(key) = TextEncoding::Base64.decode(&input) {
        (key, TextEncoding::Base64)
    } else if let Ok(key) = TextEncoding::Utf8.decode(&input) {
        (key, TextEncoding::Utf8)
    } else {
        return Err(Error::Unsupported("key content".to_string()));
    };

    let format = if let Ok(key) = TextEncoding::Utf8.encode(&key) {
        if key.starts_with("-----BEGIN ") {
            KeyFormat::Pem
        } else {
            return Err(Error::Unsupported("unknown key content".to_string()));
        }
    } else {
        KeyFormat::Der
    };
    let (pkcs, curve_name) = match format {
        KeyFormat::Pem => {
            pem_decodor((TextEncoding::Utf8.encode(&key)?.as_ref(), format))?
        }
        KeyFormat::Der => {
            if let Ok(curve_name) = parse_curve_name(&key, Pkcs::Pkcs8, format)
            {
                (Pkcs::Pkcs8, curve_name)
            } else if let Ok(key_size) =
                parse_curve_name(&key, Pkcs::Pkcs1, format)
            {
                (Pkcs::Sec1, key_size)
            } else if let Ok(key_size) =
                parse_curve_name(&key, Pkcs::Spki, format)
            {
                (Pkcs::Spki, key_size)
            } else {
                return Err(Error::Unsupported("pkcs".to_string()));
            }
        }
    };
    Ok(EccKeyInfo {
        curve_name,
        encoding,
        format,
        pkcs,
    })
}

fn parse_curve_name(
    key: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<EccCurveName> {
    Ok(match pkcs {
        Pkcs::Pkcs8 | Pkcs::Sec1 => {
            if import_ecc_private_key::<NistP256>(key, pkcs, format).is_ok() {
                EccCurveName::NistP256
            } else if import_ecc_private_key::<NistP384>(key, pkcs, format)
                .is_ok()
            {
                EccCurveName::NistP384
            } else if import_ecc_private_key::<NistP521>(key, pkcs, format)
                .is_ok()
            {
                EccCurveName::NistP521
            } else if import_ecc_private_key::<Secp256k1>(key, pkcs, format)
                .is_ok()
            {
                EccCurveName::Secp256k1
            } else if import_ecc_private_key::<Sm2>(key, pkcs, format).is_ok() {
                EccCurveName::SM2
            } else {
                return Err(Error::Unsupported(
                    "informal ecc key type".to_string(),
                ));
            }
        }
        Pkcs::Spki => {
            if import_ecc_public_key::<NistP256>(key, format).is_ok() {
                EccCurveName::NistP256
            } else if import_ecc_public_key::<NistP384>(key, format).is_ok() {
                EccCurveName::NistP384
            } else if import_ecc_public_key::<NistP521>(key, format).is_ok() {
                EccCurveName::NistP521
            } else if import_ecc_public_key::<Secp256k1>(key, format).is_ok() {
                EccCurveName::Secp256k1
            } else if import_ecc_public_key::<Sm2>(key, format).is_ok() {
                EccCurveName::SM2
            } else {
                return Err(Error::Unsupported(
                    "informal ecc key type".to_string(),
                ));
            }
        }
        _ => {
            return Err(Error::Unsupported(
                "informal ecc key type".to_string(),
            ));
        }
    })
}

pub(crate) fn import_ecc_private_key<C>(
    input: &[u8],
    pkcs: Pkcs,
    encoding: KeyFormat,
) -> Result<elliptic_curve::SecretKey<C>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    Ok(match (pkcs, encoding) {
        (Pkcs::Pkcs8, KeyFormat::Pem) => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc pkcs8 private key")?;

            elliptic_curve::SecretKey::<C>::from_pkcs8_pem(&public_key_str)
                .context("informal ecc pkcs8 pem private key")?
        }
        (Pkcs::Pkcs8, KeyFormat::Der) => {
            elliptic_curve::SecretKey::<C>::from_pkcs8_der(input)
                .context("informal ecc pkcs8 der private key")?
        }
        (Pkcs::Sec1, KeyFormat::Pem) => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc pkcs8 private key")?;

            elliptic_curve::SecretKey::<C>::from_sec1_pem(&public_key_str)
                .context("informal ecc sec1 pem private key")?
        }
        (Pkcs::Sec1, KeyFormat::Der) => {
            elliptic_curve::SecretKey::<C>::from_sec1_der(input)
                .context("informal ecc sec1 der private key")?
        }
        _ => {
            return Err(Error::Unsupported(
                "unsupported rsa pkcs1 key".to_string(),
            ));
        }
    })
}

pub(crate) fn import_ecc_public_key<C>(
    input: &[u8],
    format: KeyFormat,
) -> Result<elliptic_curve::PublicKey<C>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    Ok(match format {
        KeyFormat::Pem => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc public key")?;
            elliptic_curve::PublicKey::from_public_key_pem(&public_key_str)
                .context("informal pem public key")?
        }
        KeyFormat::Der => elliptic_curve::PublicKey::from_public_key_der(input)
            .context("informal der public key")?,
    })
}

pub(crate) fn export_ecc_private_key<C>(
    secret_key: &elliptic_curve::SecretKey<C>,
    pkcs_encoding: Pkcs,
    codec: KeyFormat,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve
        + elliptic_curve::CurveArithmetic
        + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    Ok(match pkcs_encoding {
        Pkcs::Pkcs8 => match codec {
            KeyFormat::Pem => secret_key
                .to_pkcs8_pem(base64ct::LineEnding::LF)
                .context("export ecc pkcs8 pem private key failed")?
                .as_bytes()
                .to_vec(),
            KeyFormat::Der => secret_key
                .to_pkcs8_der()
                .context("export ecc pkcs8 der private key failed")?
                .as_bytes()
                .to_vec(),
        },
        Pkcs::Sec1 => match codec {
            KeyFormat::Pem => secret_key
                .to_sec1_pem(base64ct::LineEnding::LF)
                .context("export ecc pkcs8 sec1 private key failed")?
                .as_bytes()
                .to_vec(),
            KeyFormat::Der => secret_key
                .to_sec1_der()
                .context("export ecc pkcs8 sec1 private key failed")?
                .to_vec(),
        },
        _ => {
            return Err(Error::Unsupported(
                "unsupported pkcs1 rsa encoding".to_string(),
            ));
        }
    })
}

fn export_ecc_public_key<C>(
    public_key: elliptic_curve::PublicKey<C>,
    encoding: KeyFormat,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::PublicKey<C>: EncodePublicKey,
{
    Ok(match encoding {
        KeyFormat::Pem => public_key
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("init pem private key failed")?
            .as_bytes()
            .to_vec(),
        KeyFormat::Der => public_key
            .to_public_key_der()
            .context("init der private key failed")?
            .to_vec(),
    })
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
                    Pkcs::Sec1 => public_sec1_to_bytes::<C>(key, to.format),
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
                let key = public_bytes_to_sec1::<C>(input, from.format)?;
                match to.pkcs {
                    Pkcs::Pkcs8 => public_pkcs8_to_bytes(key, to.format),
                    Pkcs::Sec1 => public_sec1_to_bytes::<C>(key, to.format),
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
    format: KeyFormat,
) -> Result<elliptic_curve::PublicKey<C>>
where
    C: PointCompression + elliptic_curve::CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    elliptic_curve::PublicKey<C>: pkcs8::DecodePublicKey,
{
    Ok(match format {
        KeyFormat::Pem => {
            let key =
                String::from_utf8(input.to_vec()).context("".to_string())?;
            elliptic_curve::PublicKey::<C>::from_public_key_pem(&key)
        }
        KeyFormat::Der => {
            elliptic_curve::PublicKey::<C>::from_public_key_der(input)
        }
    }
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
    format: KeyFormat,
) -> Result<Vec<u8>>
where
    C: PointCompression + elliptic_curve::CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    elliptic_curve::PublicKey<C>: pkcs8::EncodePublicKey,
{
    Ok(match format {
        KeyFormat::Pem => elliptic_curve::PublicKey::<C>::to_public_key_pem(
            &input,
            base64ct::LineEnding::LF,
        )
        .context("sec1 pem public key to bytes failed")?
        .as_bytes()
        .to_vec(),
        KeyFormat::Der => {
            elliptic_curve::PublicKey::<C>::to_public_key_der(&input)
                .context("sec1 der public key to bytes failed")?
                .to_vec()
        }
    })
}
