use anyhow::Context;
use base64ct::Encoding;
use elliptic_curve::AffinePoint;
use p256::NistP256;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde_bytes::ByteBuf;
use spki::DecodePublicKey;
use tracing::debug;

use super::curve_25519;
use crate::{
    crypto::{self, kdf::SALT},
    helper::{
        common::KeyTuple,
        enums::{
            AesEncryptionPadding, EccCurveName, EccKeyFormat,
            EciesEncryptionAlgorithm, EncryptionMode, KeyEncoding,
        },
        errors::Result,
    },
};

#[tauri::command]
pub fn generate_ecc(
    curve_name: EccCurveName,
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<KeyTuple> {
    match curve_name {
        EccCurveName::NistP256 => {
            generate_ecc_key::<NistP256>(format, encoding)
        }
        EccCurveName::NistP384 => {
            generate_ecc_key::<p384::NistP384>(format, encoding)
        }
        EccCurveName::NistP521 => {
            generate_ecc_key::<p521::NistP521>(format, encoding)
        }
        EccCurveName::Secp256k1 => {
            generate_ecc_key::<k256::Secp256k1>(format, encoding)
        }
        EccCurveName::Curve25519 => {
            curve_25519::generate_curve_25519_key(format, encoding)
        }
    }
}

#[tauri::command]
pub fn ecies(
    curve_name: EccCurveName,
    key: ByteBuf,
    plaintext: ByteBuf,
    format: EccKeyFormat,
    encoding: KeyEncoding,
    ea: EciesEncryptionAlgorithm,
    for_encryption: bool,
) -> Result<ByteBuf> {
    let key = key.as_slice();
    let plaintext = plaintext.as_slice();

    match curve_name {
        EccCurveName::NistP256 => ecies_inner::<NistP256>(
            plaintext,
            key,
            format,
            encoding,
            ea,
            for_encryption,
        ),
        EccCurveName::NistP384 => ecies_inner::<p384::NistP384>(
            plaintext,
            key,
            format,
            encoding,
            ea,
            for_encryption,
        ),
        EccCurveName::NistP521 => ecies_inner::<p521::NistP521>(
            plaintext,
            key,
            format,
            encoding,
            ea,
            for_encryption,
        ),
        EccCurveName::Secp256k1 => ecies_inner::<k256::Secp256k1>(
            plaintext,
            key,
            format,
            encoding,
            ea,
            for_encryption,
        ),
        EccCurveName::Curve25519 => curve_25519::curve_25519_ecies_inner(
            plaintext,
            key,
            format,
            encoding,
            ea,
            for_encryption,
        ),
    }
}

pub fn ecies_inner<C>(
    input: &[u8],
    key: &[u8],
    format: EccKeyFormat,
    encoding: KeyEncoding,
    _ea: EciesEncryptionAlgorithm,
    for_encryption: bool,
) -> Result<ByteBuf>
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
    Ok(ByteBuf::from(if for_encryption {
        let mut result: Vec<u8> = Vec::new();
        let receiver_secret_key =
            elliptic_curve::SecretKey::<C>::random(&mut rng);
        let receiver_public_key = receiver_secret_key.public_key();
        let receiver_public_key_bytes = receiver_public_key.to_sec1_bytes();
        result.push(receiver_public_key_bytes.len() as u8);
        result.extend_from_slice(&receiver_public_key_bytes);
        let public_key = import_ecc_public_key::<C>(key, encoding)?;
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
        debug!(
            "encryption secret: {}",
            base64ct::Base64::encode_string(secret)
        );
        debug!("decryption iv: {}", base64ct::Base64::encode_string(iv));

        let encrypted = crypto::aes::encrypt_or_decrypt_aes(
            EncryptionMode::Gcm,
            secret,
            input,
            AesEncryptionPadding::NoPadding,
            Some(iv.to_vec()),
            None,
            for_encryption,
        )?;
        debug!("cipher text: {}", base64ct::Base64::encode_string(&encrypted));
        result.extend_from_slice(&encrypted);
        result
    } else {
        let (public_key_len, input) = input.split_at(1);
        let public_key_len = public_key_len[0] as usize;
        let mut receiver_public_secret = Vec::with_capacity(public_key_len);
        let (receiver_public_secret_bytes, input) =
            input.split_at(public_key_len);
        receiver_public_secret.extend_from_slice(receiver_public_secret_bytes);
        let private_key = import_ecc_private_key::<C>(key, format, encoding)?;
        let receiver_public_secret =
            elliptic_curve::PublicKey::<C>::from_sec1_bytes(
                &receiver_public_secret,
            )
            .context("build receiver secret failed")?;
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
        debug!(
            "decryption secret: {}",
            base64ct::Base64::encode_string(secret)
        );
        debug!("decryption iv: {}", base64ct::Base64::encode_string(iv));
        debug!("cipher text: {}", base64ct::Base64::encode_string(input));
        crypto::aes::encrypt_or_decrypt_aes(
            EncryptionMode::Gcm,
            secret,
            input,
            AesEncryptionPadding::NoPadding,
            Some(iv.to_vec()),
            None,
            for_encryption,
        )?
    }))
}

fn generate_ecc_key<C>(
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<KeyTuple>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let mut rng = rand::thread_rng();
    let secret_key = elliptic_curve::SecretKey::<C>::random(&mut rng);

    let private_key = export_ecc_private_key(&secret_key, format, encoding)?;
    let public_secret_key = secret_key.public_key();
    let public_key = export_ecc_public_key(public_secret_key, encoding)?;
    Ok(KeyTuple(
        ByteBuf::from(private_key),
        ByteBuf::from(public_key),
    ))
}

fn import_ecc_private_key<C>(
    input: &[u8],
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<elliptic_curve::SecretKey<C>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    Ok(match (format, encoding) {
        (EccKeyFormat::BaseKeyFormat(_), KeyEncoding::Pem) => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc pkcs8 private key")?;

            elliptic_curve::SecretKey::<C>::from_pkcs8_pem(&public_key_str)
                .context("informal ecc pkcs8 pem private key")?
        }
        (EccKeyFormat::BaseKeyFormat(_), KeyEncoding::Der) => {
            elliptic_curve::SecretKey::<C>::from_pkcs8_der(input)
                .context("informal ecc pkcs8 der private key")?
        }
        (EccKeyFormat::Sec1, KeyEncoding::Pem) => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc pkcs8 private key")?;

            elliptic_curve::SecretKey::<C>::from_sec1_pem(&public_key_str)
                .context("informal ecc sec1 pem private key")?
        }
        (EccKeyFormat::Sec1, KeyEncoding::Der) => {
            elliptic_curve::SecretKey::<C>::from_sec1_der(input)
                .context("informal ecc sec1 der private key")?
        }
    })
}

fn import_ecc_public_key<C>(
    input: &[u8],
    from: KeyEncoding,
) -> Result<elliptic_curve::PublicKey<C>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    Ok(match from {
        KeyEncoding::Pem => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc public key")?;
            elliptic_curve::PublicKey::from_public_key_pem(&public_key_str)
                .context("informal pem public key")?
        }
        KeyEncoding::Der => {
            elliptic_curve::PublicKey::from_public_key_der(input)
                .context("informal der public key")?
        }
    })
}

fn export_ecc_private_key<C>(
    secret_key: &elliptic_curve::SecretKey<C>,
    format: EccKeyFormat,
    codec: KeyEncoding,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve
        + elliptic_curve::CurveArithmetic
        + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    Ok(match format {
        EccKeyFormat::BaseKeyFormat(_) => match codec {
            KeyEncoding::Pem => secret_key
                .to_pkcs8_pem(base64ct::LineEnding::LF)
                .context("export ecc pkcs8 pem private key failed")?
                .as_bytes()
                .to_vec(),
            KeyEncoding::Der => secret_key
                .to_pkcs8_der()
                .context("export ecc pkcs8 der private key failed")?
                .as_bytes()
                .to_vec(),
        },
        EccKeyFormat::Sec1 => match codec {
            KeyEncoding::Pem => secret_key
                .to_sec1_pem(base64ct::LineEnding::LF)
                .context("export ecc pkcs8 sec1 private key failed")?
                .as_bytes()
                .to_vec(),
            KeyEncoding::Der => secret_key
                .to_sec1_der()
                .context("export ecc pkcs8 sec1 private key failed")?
                .to_vec(),
        },
    })
}

fn export_ecc_public_key<C>(
    public_key: elliptic_curve::PublicKey<C>,
    codec: KeyEncoding,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::PublicKey<C>: EncodePublicKey,
{
    Ok(match codec {
        KeyEncoding::Pem => public_key
            .to_public_key_pem(base64ct::LineEnding::LF)
            .context("init pem private key failed")?
            .as_bytes()
            .to_vec(),
        KeyEncoding::Der => public_key
            .to_public_key_der()
            .context("init der private key failed")?
            .to_vec(),
    })
}

#[cfg(test)]
mod test {
    use pkcs8::EncodePublicKey;
    use serde_bytes::ByteBuf;
    use tracing::info;
    use tracing_test::traced_test;

    use crate::{
        crypto::ecc::{ecies, generate_ecc},
        helper::enums::{
            EccCurveName, EccKeyFormat, EciesEncryptionAlgorithm, KeyEncoding,
        },
    };

    #[test]
    #[traced_test]
    fn test_generate_ecc_and_encryption() {
        let mut rng = rand::thread_rng();

        let secret_key = p256::SecretKey::random(&mut rng);
        let secret_key_pem = secret_key
            .to_sec1_pem(base64ct::LineEnding::LF)
            .expect("secret key to sec1 pem failed")
            .to_string();
        info!(
            "\n ================== secret key ============== \n{}",
            secret_key_pem
        );

        let public_key = secret_key.public_key();

        let public_key_pem = public_key
            .to_public_key_pem(base64ct::LineEnding::LF)
            .expect("public key to pkcs1");

        info!(
            "\n ================== public key ============== \n{}",
            public_key_pem
        );

        let shared_key = elliptic_curve::ecdh::diffie_hellman(
            secret_key.to_nonzero_scalar(),
            public_key.as_affine(),
        );
        let shared_key_bytes = shared_key.raw_secret_bytes();

        info!(
            "\n ================== shared key ============== \n{:?}",
            shared_key_bytes
        );
        info!(
            "\n ================== shared key len ============== \n{:?}",
            shared_key_bytes.len()
        );
    }

    #[test]
    #[traced_test]
    fn test_generate_and_encryption() {
        for curve_name in [
            EccCurveName::NistP256,
            EccCurveName::NistP384,
            EccCurveName::NistP521,
            EccCurveName::Secp256k1,
            EccCurveName::Curve25519,
        ] {
            info!("start test curve_name: {:?}", curve_name);
            for key_format in [
                EccKeyFormat::BaseKeyFormat(
                    crate::helper::enums::BaseKeyFormat::Pkcs8,
                ),
                EccKeyFormat::Sec1,
            ] {
                for key_encoding in [KeyEncoding::Pem, KeyEncoding::Der] {
                    let key =
                        generate_ecc(curve_name, key_format, key_encoding)
                            .unwrap();
                    let plaintext = b"plaintext";
                    let ciphertext = ecies(
                        curve_name,
                        key.1,
                        ByteBuf::from(plaintext),
                        key_format,
                        key_encoding,
                        EciesEncryptionAlgorithm::Aes256Gcm,
                        true,
                    )
                    .unwrap();

                    assert_eq!(
                        ecies(
                            curve_name,
                            key.0,
                            ciphertext,
                            key_format,
                            key_encoding,
                            EciesEncryptionAlgorithm::Aes256Gcm,
                            false,
                        )
                        .unwrap(),
                        b"plaintext"
                    )
                }
            }
        }
    }
}
