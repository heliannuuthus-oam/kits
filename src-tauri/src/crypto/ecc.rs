use anyhow::Context;
use elliptic_curve::{AffinePoint, SecretKey};
use pkcs8::EncodePrivateKey;
use serde_bytes::ByteBuf;

use crate::helper::{
    enums::{AsymmetricKeyFormat, EccCurveName},
    errors::{Error, Result},
};

#[tauri::command]
pub fn generate_ecc(
    curve_name: EccCurveName,
    format: AsymmetricKeyFormat,
) -> Result<ByteBuf> {
    let mut rng = rand::thread_rng();

    Ok(ByteBuf::from(match curve_name {
        EccCurveName::NistP256 => {
            export_ecc_private_key(p256::SecretKey::random(&mut rng), format)
        }
        EccCurveName::NistP384 => {
            export_ecc_private_key(p384::SecretKey::random(&mut rng), format)
        }
        EccCurveName::NistP521 => {
            export_ecc_private_key(p521::SecretKey::random(&mut rng), format)
        }
        EccCurveName::Secp256k1 => {
            export_ecc_private_key(k256::SecretKey::random(&mut rng), format)
        }
        EccCurveName::Curve25519 => Ok(match format {
            AsymmetricKeyFormat::Pkcs8Pem => {
                ed25519_dalek::SigningKey::generate(&mut rng)
                    .to_pkcs8_pem(pkcs8::LineEnding::LF)
                    .context(
                        "init curve 25519 private key to pkcs8 pem failed",
                    )?
                    .as_bytes()
                    .to_vec()
            }
            AsymmetricKeyFormat::Pkcs8Der => {
                // just random bytes, length 32
                ed25519_dalek::SigningKey::generate(&mut rng)
                    .to_pkcs8_der()
                    .context(
                        "init curve 25519 private key to pkcs8 der failed",
                    )?
                    .to_bytes()
                    .to_vec()
            }
            _ => {
                return Err(Error::Unsupported(format!(
                    "curve 25519 private key format {:?}",
                    format
                )))
            }
        }),
    }?))
}

fn import_ecc_private_key(
    key: ByteBuf,
    format: AsymmetricKeyFormat,
) -> Result<elliptic_curve::SecretKey<dyn elliptic_curve::Curve>> {
    Ok(match format {
        AsymmetricKeyFormat::Pkcs8Pem => {
            let key_str = String::from_utf8(key.to_vec())
                .context("key to utf8 failed")?;
            elliptic_curve::SecretKey::from_sec1_pem(&key_str)
                .context("init pkcs8 pem secret key failed");
        }
        AsymmetricKeyFormat::Pkcs8Der => {
            elliptic_curve::SecretKey::from_sec1_der(&key)
                .context("init pkcs der private key failed")?
                .to_vec()
        }
        _ => {
            return Err(Error::Unsupported(format!(
                "ec private key format {:?}",
                format
            )))
        }
    })
}

fn export_ecc_private_key<C>(
    secret_key: elliptic_curve::SecretKey<C>,
    format: AsymmetricKeyFormat,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    Ok(match format {
        AsymmetricKeyFormat::Pkcs8Pem => secret_key
            .to_sec1_pem(pkcs8::LineEnding::LF)
            .context("init pkcs8 pem private key failed")?
            .as_bytes()
            .to_vec(),
        AsymmetricKeyFormat::Pkcs8Der => secret_key
            .to_sec1_der()
            .context("init pkcs der private key failed")?
            .to_vec(),
        _ => {
            return Err(Error::Unsupported(format!(
                "ec private key format {:?}",
                format
            )))
        }
    })
}

fn export_ecc_public_key<C>(
    secret_key: elliptic_curve::SecretKey<C>,
    format: AsymmetricKeyFormat,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    Ok(match format {
        AsymmetricKeyFormat::Pkcs8Pem => secret_key
            .to_sec1_pem(pkcs8::LineEnding::LF)
            .context("init pkcs8 pem private key failed")?
            .as_bytes()
            .to_vec(),
        AsymmetricKeyFormat::Pkcs8Der => secret_key
            .to_sec1_der()
            .context("init pkcs der private key failed")?
            .to_vec(),
        _ => {
            return Err(Error::Unsupported(format!(
                "ec private key format {:?}",
                format
            )))
        }
    })
}
