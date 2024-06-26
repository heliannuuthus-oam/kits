use std::fmt::Debug;

use anyhow::Context;
use elliptic_curve::{
    sec1::{EncodedPoint, ToEncodedPoint},
    AffinePoint,
};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use self::key::{import_ecc_private_key, import_ecc_public_key};
use super::kdf;
use crate::{
    add_encryption_trait_impl,
    crypto::{self, EncryptionDto},
    utils::{
        enums::{
            AesEncryptionPadding, Digest, EccCurveName,
            EciesEncryptionAlgorithm, Kdf, KeyFormat, Pkcs, TextEncoding,
        },
        errors::{Error, Result},
    },
};

pub mod key;

add_encryption_trait_impl!(EciesDto {
    curve_name: EccCurveName,
    pkcs: Pkcs,
    format: KeyFormat,
    kdf: Kdf,
    kdf_digest: Digest,
    salt: Option<String>,
    salt_encoding: Option<TextEncoding>,
    info: Option<String>,
    info_encoding: Option<TextEncoding>,
    encryption_alg: EciesEncryptionAlgorithm,
    for_encryption: bool
});

impl EciesDto {
    pub fn get_salt(&self) -> Result<Option<Vec<u8>>> {
        if let Some(s) = self.salt.as_ref() {
            self.salt_encoding
                .ok_or(Error::Unsupported(
                    "salt encoding is required".to_string(),
                ))
                .and_then(|encoding| encoding.decode(s))
                .map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn get_info(&self) -> Result<Option<Vec<u8>>> {
        if let Some(s) = self.info.as_ref() {
            self.info_encoding
                .ok_or(Error::Unsupported(
                    "info encoding is required".to_string(),
                ))
                .and_then(|encoding| encoding.decode(s))
                .map(Some)
        } else {
            Ok(None)
        }
    }
}

impl Debug for EciesDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EciesDto")
            .field("input_encoding", &self.input_encoding)
            .field("key_encoding", &self.key_encoding)
            .field("output_encoding", &self.output_encoding)
            .field("curve_name", &self.curve_name)
            .field("pkcs", &self.pkcs)
            .field("key_format", &self.format)
            .field("kdf", &self.kdf)
            .field("kdf_digest", &self.kdf_digest)
            .field("encryption_alg", &self.encryption_alg)
            .field("for_encryption", &self.for_encryption)
            .finish()
    }
}

#[tauri::command]
pub fn ecies(data: EciesDto) -> Result<String> {
    info!("ecies :{:?} ", data);
    let output_encoding = data.output_encoding;
    let cipher_bytes = (match data.curve_name {
        EccCurveName::NistP256 => ecies_inner::<NistP256>(data),
        EccCurveName::NistP384 => ecies_inner::<p384::NistP384>(data),
        EccCurveName::NistP521 => ecies_inner::<p521::NistP521>(data),
        EccCurveName::Secp256k1 => ecies_inner::<k256::Secp256k1>(data),
        EccCurveName::SM2 => ecies_inner::<sm2::Sm2>(data),
    })?;
    output_encoding.encode(&cipher_bytes)
}

pub fn ecies_inner<C>(data: EciesDto) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve
        + elliptic_curve::CurveArithmetic
        + pkcs8::AssociatedOid
        + elliptic_curve::point::PointCompression,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let key = data.key_encoding.decode(&data.key)?;
    let input = data.input_encoding.decode(&data.input)?;
    let EciesDto {
        pkcs,
        format,
        kdf,
        encryption_alg,
        for_encryption,
        ..
    } = data;
    let salt = data.get_salt()?;
    let info = data.get_info()?;
    Ok(if for_encryption {
        let mut result = Vec::new();
        let (receiver_public_key_bytes, shared_secret) =
            generate_secret::<C>(&key, format)?;
        result.extend_from_slice(&receiver_public_key_bytes);

        debug!(
            "encryption shared_secret: {}",
            TextEncoding::Base64.encode(&shared_secret)?
        );

        let pkf_key = kdf::kdf_inner_digest(
            kdf,
            Digest::Sha256,
            &shared_secret,
            salt,
            info,
            44,
        )?;
        debug!(
            "encryption pkf_key: {}",
            TextEncoding::Base64.encode(&pkf_key)?
        );

        let (secret, iv) = pkf_key.split_at(32);
        let encrypted = crypto::aes::encrypt_or_decrypt_aes(
            encryption_alg.as_encryption_mode(),
            &input,
            secret,
            Some(iv.to_vec()),
            None,
            AesEncryptionPadding::NoPadding,
            for_encryption,
        )?;

        result.extend_from_slice(&encrypted);
        result
    } else {
        let (input, shared_secret) =
            parse_secret::<C>(&input, &key, pkcs, format)?;

        debug!(
            "decryption shared_secret: {}",
            TextEncoding::Base64.encode(&shared_secret)?
        );

        let pkf_key = kdf::kdf_inner_digest(
            kdf,
            Digest::Sha256,
            &shared_secret,
            salt,
            info,
            44,
        )?;
        debug!(
            "decryption pkf_key: {}",
            TextEncoding::Base64.encode(&pkf_key)?
        );

        let (secret, iv) = pkf_key.split_at(32);

        crypto::aes::encrypt_or_decrypt_aes(
            encryption_alg.as_encryption_mode(),
            &input,
            secret,
            Some(iv.to_vec()),
            None,
            AesEncryptionPadding::NoPadding,
            for_encryption,
        )?
    })
}

fn generate_secret<C>(
    key: &[u8],
    format: KeyFormat,
) -> Result<(Vec<u8>, Vec<u8>)>
where
    C: elliptic_curve::Curve
        + elliptic_curve::CurveArithmetic
        + pkcs8::AssociatedOid
        + elliptic_curve::point::PointCompression,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let mut rng = rand::thread_rng();
    let receiver_secret_key = elliptic_curve::SecretKey::<C>::random(&mut rng);
    let receiver_public_key = receiver_secret_key.public_key();
    let receiver_public_key_bytes = receiver_public_key.to_encoded_point(true);
    let public_key = import_ecc_public_key::<C>(key, format)?;
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        receiver_secret_key.to_nonzero_scalar(),
        public_key.as_affine(),
    );
    Ok((
        receiver_public_key_bytes.to_bytes().to_vec(),
        shared_secret.raw_secret_bytes().to_vec(),
    ))
}

fn parse_secret<C>(
    input: &[u8],
    key: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<(Vec<u8>, Vec<u8>)>
where
    C: elliptic_curve::Curve
        + elliptic_curve::CurveArithmetic
        + pkcs8::AssociatedOid
        + elliptic_curve::point::PointCompression,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let private_key = import_ecc_private_key::<C>(key, pkcs, format)?;
    let public_key = private_key.public_key();
    let public_key_encode_point = public_key.to_encoded_point(true);
    let public_key_len = public_key_encode_point.len();
    let mut receiver_public_secret = Vec::with_capacity(public_key_len);
    let (receiver_public_secret_bytes, input) = input.split_at(public_key_len);
    receiver_public_secret.extend_from_slice(receiver_public_secret_bytes);
    let receiver_public_key_ep =
        EncodedPoint::<C>::from_bytes(receiver_public_secret)
            .context("informat receiver key".to_string())?;
    let receiver_public_secret =
        elliptic_curve::PublicKey::<C>::try_from(&receiver_public_key_ep)
            .context("build receiver key failed")?;
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        private_key.to_nonzero_scalar(),
        receiver_public_secret.as_affine(),
    );
    Ok((input.to_vec(), shared_secret.raw_secret_bytes().to_vec()))
}

#[cfg(test)]
mod test {
    use strum::IntoEnumIterator;
    use tracing::info;
    use tracing_test::traced_test;

    use crate::{
        crypto::ecc::{ecies, key::generate_ecc, EciesDto},
        utils::{
            self,
            enums::{
                Digest, EccCurveName, EciesEncryptionAlgorithm, Kdf, KeyFormat,
                Pkcs, TextEncoding,
            },
        },
    };

    #[test]
    #[traced_test]
    fn test_generate_and_encryption() {
        for curve_name in [
            EccCurveName::NistP256,
            EccCurveName::NistP384,
            EccCurveName::NistP521,
            EccCurveName::Secp256k1,
            EccCurveName::SM2,
        ] {
            info!("start test curve_name: {:?}", curve_name);
            let encoding = TextEncoding::Base64;
            let salt = utils::common::random_bytes(12).unwrap();
            let salt = encoding.encode(&salt).unwrap();
            for pkcs in [Pkcs::Pkcs8, Pkcs::Sec1] {
                for format in [KeyFormat::Pem, KeyFormat::Der] {
                    for kdf in Kdf::iter() {
                        for kdf_digest in Digest::iter() {
                            let key = generate_ecc(
                                curve_name, pkcs, format, encoding,
                            )
                            .unwrap();
                            let plaintext = "plaintext";
                            let ciphertext = ecies(EciesDto {
                                curve_name,
                                key: key.1.unwrap(),
                                key_encoding: encoding,
                                input: plaintext.to_string(),
                                input_encoding: TextEncoding::Utf8,
                                output_encoding: encoding,
                                pkcs,
                                kdf,
                                kdf_digest,
                                salt: Some(salt.to_string()),
                                salt_encoding: Some(TextEncoding::Base64),
                                info: Some("info".to_string()),
                                info_encoding: Some(TextEncoding::Utf8),
                                format,
                                encryption_alg:
                                    EciesEncryptionAlgorithm::AesGcm,
                                for_encryption: true,
                            })
                            .unwrap();

                            assert_eq!(
                                ecies(EciesDto {
                                    curve_name,
                                    key: key.0.unwrap(),
                                    key_encoding: encoding,
                                    input: ciphertext,
                                    input_encoding: encoding,
                                    output_encoding: TextEncoding::Utf8,
                                    pkcs,
                                    kdf,
                                    kdf_digest,
                                    salt: Some(salt.to_string()),
                                    salt_encoding: Some(TextEncoding::Base64),
                                    info: Some("info".to_string()),
                                    info_encoding: Some(TextEncoding::Utf8),
                                    format,
                                    encryption_alg:
                                        EciesEncryptionAlgorithm::AesGcm,
                                    for_encryption: false,
                                })
                                .unwrap(),
                                plaintext
                            );
                        }
                    }
                }
            }
        }
    }
}
