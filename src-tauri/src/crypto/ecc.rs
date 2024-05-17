use std::fmt::Debug;

use anyhow::Context;
use elliptic_curve::{
    sec1::{EncodedPoint, ToEncodedPoint},
    AffinePoint,
};
use p256::NistP256;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use spki::DecodePublicKey;
use tracing::info;

use crate::{
    add_encryption_trait_impl,
    crypto::{self, kdf::SALT, EncryptionDto},
    utils::{
        codec::{pkcs8_sec1_converter, PkcsDto},
        common::KeyTuple,
        enums::{
            AesEncryptionPadding, EccCurveName, EciesEncryptionAlgorithm,
            EncryptionMode, KeyFormat, Pkcs, TextEncoding,
        },
        errors::{Error, Result},
    },
};

add_encryption_trait_impl!(EciesDto {
    curve_name: EccCurveName,
    pkcs: Pkcs,
    key_format: KeyFormat,
    encryption_alg: EciesEncryptionAlgorithm,
    for_encryption: bool
});

impl Debug for EciesDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EciesDto")
            .field("input_encoding", &self.input_encoding)
            .field("key_encoding", &self.key_encoding)
            .field("output_encoding", &self.output_encoding)
            .field("curve_name", &self.curve_name)
            .field("pkcs", &self.pkcs)
            .field("key_format", &self.key_format)
            .field("encryption_alg", &self.encryption_alg)
            .field("for_encryption", &self.for_encryption)
            .finish()
    }
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
        EccCurveName::NistP256 => generate_ecc_key::<NistP256>(pkcs, format),
        EccCurveName::NistP384 => {
            generate_ecc_key::<p384::NistP384>(pkcs, format)
        }
        EccCurveName::NistP521 => {
            generate_ecc_key::<p521::NistP521>(pkcs, format)
        }
        EccCurveName::Secp256k1 => {
            generate_ecc_key::<k256::Secp256k1>(pkcs, format)
        }
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
    })?;
    encoding.encode(&public_key_bytes)
}

pub fn derive_ecc_inner<C>(
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

#[tauri::command]
pub fn ecies(data: EciesDto) -> Result<String> {
    let key = data.key_encoding.decode(&data.key)?;
    let input = data.input_encoding.decode(&data.input)?;

    let cipher_bytes = (match data.curve_name {
        EccCurveName::NistP256 => ecies_inner::<NistP256>(
            &input,
            &key,
            data.pkcs,
            data.key_format,
            data.encryption_alg,
            data.for_encryption,
        ),
        EccCurveName::NistP384 => ecies_inner::<p384::NistP384>(
            &input,
            &key,
            data.pkcs,
            data.key_format,
            data.encryption_alg,
            data.for_encryption,
        ),
        EccCurveName::NistP521 => ecies_inner::<p521::NistP521>(
            &input,
            &key,
            data.pkcs,
            data.key_format,
            data.encryption_alg,
            data.for_encryption,
        ),
        EccCurveName::Secp256k1 => ecies_inner::<k256::Secp256k1>(
            &input,
            &key,
            data.pkcs,
            data.key_format,
            data.encryption_alg,
            data.for_encryption,
        ),
    })?;
    data.output_encoding.encode(&cipher_bytes)
}

pub fn ecies_inner<C>(
    input: &[u8],
    key: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
    _ea: EciesEncryptionAlgorithm,
    for_encryption: bool,
) -> Result<Vec<u8>>
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
    Ok(if for_encryption {
        let mut result: Vec<u8> = Vec::new();
        let receiver_secret_key =
            elliptic_curve::SecretKey::<C>::random(&mut rng);
        let receiver_public_key = receiver_secret_key.public_key();
        let receiver_public_key_bytes =
            receiver_public_key.to_encoded_point(true);
        result.extend_from_slice(receiver_public_key_bytes.as_bytes());
        let public_key = import_ecc_public_key::<C>(key, format)?;
        let shared_secret = elliptic_curve::ecdh::diffie_hellman(
            receiver_secret_key.to_nonzero_scalar(),
            public_key.as_affine(),
        );
        let _shared_secret_bytes = shared_secret.raw_secret_bytes();
        let pkf_key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 44>(
            shared_secret.raw_secret_bytes(),
            SALT.as_bytes(),
            210_000,
        );
        let (secret, iv) = pkf_key.split_at(32);
        let encrypted = crypto::aes::encrypt_or_decrypt_aes(
            EncryptionMode::Gcm,
            input,
            secret,
            Some(iv.to_vec()),
            None,
            AesEncryptionPadding::NoPadding,
            for_encryption,
        )?;
        result.extend_from_slice(&encrypted);
        result
    } else {
        let private_key = import_ecc_private_key::<C>(key, pkcs, format)?;
        let public_key = private_key.public_key();
        let public_key_encode_point = public_key.to_encoded_point(true);
        let public_key_len = public_key_encode_point.len();
        let mut receiver_public_secret = Vec::with_capacity(public_key_len);
        let (receiver_public_secret_bytes, input) =
            input.split_at(public_key_len);
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
        let pkf_key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 44>(
            shared_secret.raw_secret_bytes(),
            SALT.as_bytes(),
            210_000,
        );

        let (secret, iv) = pkf_key.split_at(32);
        crypto::aes::encrypt_or_decrypt_aes(
            EncryptionMode::Gcm,
            input,
            secret,
            Some(iv.to_vec()),
            None,
            AesEncryptionPadding::NoPadding,
            for_encryption,
        )?
    })
}

fn generate_ecc_key<C>(
    pkcs_encoding: Pkcs,
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

    let private_key =
        export_ecc_private_key(&secret_key, pkcs_encoding, format)?;
    let public_secret_key = secret_key.public_key();
    let public_key = export_ecc_public_key(public_secret_key, format)?;
    Ok((private_key, public_key))
}

fn import_ecc_private_key<C>(
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

fn import_ecc_public_key<C>(
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

fn export_ecc_private_key<C>(
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

#[cfg(test)]
mod test {
    use tracing::info;
    use tracing_test::traced_test;

    use crate::{
        crypto::ecc::{ecies, generate_ecc, EciesDto},
        utils::enums::{
            EccCurveName, EciesEncryptionAlgorithm, KeyFormat, Pkcs,
            TextEncoding,
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
        ] {
            info!("start test curve_name: {:?}", curve_name);
            let encoding = TextEncoding::Base64;
            for pkcs in [Pkcs::Pkcs8, Pkcs::Sec1] {
                for format in [KeyFormat::Pem, KeyFormat::Der] {
                    let key = generate_ecc(curve_name, pkcs, format, encoding)
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
                        encryption_alg: EciesEncryptionAlgorithm::Aes256Gcm,
                        key_format: format,
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
                            key_format: format,
                            encryption_alg: EciesEncryptionAlgorithm::Aes256Gcm,
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
