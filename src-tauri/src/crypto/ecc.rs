use aes_gcm::{
    aead::{Aead, AeadMutInPlace},
    AeadCore, Aes256Gcm,
};
use anyhow::Context;
use der::{pem::PemLabel, Encode};
use digest::KeyInit;
use elliptic_curve::{zeroize::Zeroizing, AffinePoint, SecretKey};
use p256::NistP256;
use p384::NistP384;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use sec1::EncodeEcPrivateKey;
use serde_bytes::ByteBuf;
use spki::{der::EncodePem, DecodePublicKey};

use crate::helper::{
    common::KeyTuple,
    enums::{
        BaseKeyFormat, EccCurveName, EccKeyFormat, EciesEncryptionAlgorithm,
        KeyEncoding,
    },
    errors::{Error, Result},
};

#[tauri::command]
pub fn generate_ecc(
    curve_name: EccCurveName,
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<KeyTuple> {
    let mut rng = rand::thread_rng();

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
        EccCurveName::Curve25519 => todo!(),
    }
    //     EccCurveName::Curve25519 => match format {
    //         KeyFormat::Pkcs8 => {
    //             match encoding {
    //                 KeyEncoding::Pem => {
    //                     let secret_key =
    //                         ed25519_dalek::SigningKey::generate(&mut rng);
    //                     let private_key = secret_key
    //                         .to_pkcs8_pem(base64ct::LineEnding::LF)
    //                         .context(
    //                             "init curve 25519 private key to pkcs8 pem \
    //                              failed",
    //                         )?
    //                         .as_bytes()
    //                         .to_vec();
    //                     let verifying_key = secret_key.verifying_key();
    //                     let public_key = verifying_key
    //                         .to_public_key_pem(base64ct::LineEnding::LF)
    //                         .context(
    //                             "init curve 25519 public key to spki pem \
    //                              failed",
    //                         )?
    //                         .as_bytes()
    //                         .to_vec();
    //                     (private_key, public_key)
    //                 }

    //                 KeyEncoding::Der =>
    //                 // just random bytes, length 32
    //                 {
    //                     let signing_key =
    //                         ed25519_dalek::SigningKey::generate(&mut rng);
    //                     let private_key = signing_key
    //                         .to_pkcs8_der()
    //                         .context(
    //                             "init curve 25519 private key to pkcs8 der \
    //                              failed",
    //                         )?
    //                         .to_bytes()
    //                         .to_vec();

    //                     let verifying_key = signing_key.verifying_key();
    //                     let public_key = verifying_key
    //                         .to_public_key_der()
    //                         .context(
    //                             "init curve 25519 public key to spki der \
    //                              failed",
    //                         )?
    //                         .to_vec();
    //                     (private_key, public_key)
    //                 }
    //             }
    //         }

    //         _ => {
    //             return Err(Error::Unsupported(format!(
    //                 "curve 25519 private key format {:?}",
    //                 format
    //             )))
    //         }
    //     },
    // }
}

pub fn ecies<C>(
    plaintext: ByteBuf,
    input: ByteBuf,
    format: EccKeyFormat,
    encoding: KeyEncoding,
    ea: EciesEncryptionAlgorithm,
    for_encryption: bool,
) -> Result<ByteBuf>
where
    C: elliptic_curve::Curve,
    C: elliptic_curve::CurveArithmetic + pkcs8::AssociatedOid,
    AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let mut rng = rand::thread_rng();
    let secret_key = elliptic_curve::SecretKey::<C>::random(&mut rng);
    let shared_secret = if for_encryption {
        let public_key = import_ecc_public_key::<C>(&input, encoding)?;
        elliptic_curve::ecdh::diffie_hellman(
            secret_key.to_nonzero_scalar(),
            public_key.as_affine(),
        )
    } else {
        let private_key =
            import_ecc_private_key::<C>(&input, format, encoding)?;
        elliptic_curve::ecdh::diffie_hellman(
            private_key.to_nonzero_scalar(),
            secret_key.public_key().as_affine(),
        )
    };
    let shared_secret_bytes = shared_secret.raw_secret_bytes();
    Ok(ByteBuf::from(match ea {
        EciesEncryptionAlgorithm::Aes256Gcm => {
            let mut cipher =
                Aes256Gcm::new_from_slice(shared_secret_bytes).context("")?;
            let nonce = Aes256Gcm::generate_nonce(&mut rng);
            let mut payload = plaintext.to_vec();
            cipher
                .encrypt_in_place(&nonce, b"", &mut payload)
                .context("encrypt failed")?;
            payload
        }
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

fn import_curve_25519_private_key(
    input: &[u8],
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<ed25519_dalek::SigningKey> {
    let transfer = |der_bytes| {
        return sec1::EcPrivateKey::try_from(der_bytes)?
            .try_into()
            .context("unprocessed error");
    };

    Ok(match (format, encoding) {
        (EccKeyFormat::BaseKeyFormat(_), KeyEncoding::Pem) => {
            let private_key_str = String::from_utf8(input.to_vec())
                .context("informal curve 25519 private key")?;
            ed25519_dalek::SigningKey::from_pkcs8_pem(&private_key_str)
                .context("informal curve 25519 pkcs8 pem private key")?
        }
        (EccKeyFormat::BaseKeyFormat(_), KeyEncoding::Der) => {
            ed25519_dalek::SigningKey::from_pkcs8_der(input)
                .context("informal ecc pkcs8 der private key")?
        }
        (EccKeyFormat::Sec1, KeyEncoding::Pem) => {
            let private_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc pkcs8 private key")?;

            let private_key_pem = pem::parse(&private_key_str)
                .context("pem parse private key failed")?;

            if private_key_pem.tag() != sec1::EcPrivateKey::PEM_LABEL {
                return Err(Error::Unsupported(
                    "unsuppoted sec1 tag".to_string(),
                ));
            }
            let private_key: sec1::EcPrivateKey =
                transfer(private_key_pem.contents())?;

            ed25519_dalek::SigningKey::from_sec1_pem(&private_key_str)
                .context("informal ecc sec1 pem private key")?
        }
        (EccKeyFormat::Sec1, KeyEncoding::Der) => {
            ed25519_dalek::SigningKey::from_sec1_der(input)
                .context("informal ecc sec1 der private key")?
        }
    })
}

fn import_curve_25519_public_key<C>(
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

fn export_curve_25519_private_key<C>(
    secret_key: &ed25519_dalek::SigningKey,
    format: EccKeyFormat,
    codec: KeyEncoding,
) -> Result<Vec<u8>> {
    let transfer = |secret_key: &ed25519_dalek::SigningKey| {
        let private_key_bytes = Zeroizing::new(secret_key.to_bytes());
        let public_key_bytes = secret_key.verifying_key();

        Ok::<Zeroizing<Vec<u8>>>(Zeroizing::new(
            sec1::EcPrivateKey {
                private_key: private_key_bytes.as_ref(),
                parameters: None,
                public_key: Some(public_key_bytes.as_bytes()),
            }
            .to_der()
            .context("curve_25519 to sec1 private key der failed")?,
        ))
    };

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
            KeyEncoding::Pem => {
                let ec_private_key: Zeroizing<Vec<u8>> = transfer(secret_key)?;
                let pem = pem::Pem::new(
                    sec1::EcPrivateKey::PEM_LABEL,
                    ec_private_key.as_ref(),
                );
                pem::encode(&pem).as_bytes().to_vec()
            }
            KeyEncoding::Der => transfer(secret_key)?.to_vec(),
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

fn export_curve_25519_public_key<C>(
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

fn pem_to_der<E>(input: E, is_public: bool) -> Result<ByteBuf>
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

fn der_to_pem<E>(input: E, is_public: bool) -> Result<ByteBuf>
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

#[cfg(test)]
mod test {
    use der::{pem::PemLabel, Encode};
    use pkcs8::EncodePublicKey;
    use tracing::info;
    use tracing_test::traced_test;
    use zeroize::Zeroizing;

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
    fn test_generate_curve_25519_and_encryption() {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let private_key_bytes = Zeroizing::new(signing_key.to_bytes());
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.as_bytes();

        let cc = private_key_bytes.to_vec();
        let ec_private_key: Zeroizing<Vec<u8>> = Zeroizing::new(
            sec1::EcPrivateKey {
                private_key: &cc,
                parameters: None,
                public_key: Some(public_key_bytes),
            }
            .to_der()
            .expect("init sec1 ec private key failed"),
        );
        let cc = pem::Pem::new(
            sec1::EcPrivateKey::PEM_LABEL,
            ec_private_key.to_vec(),
        );

        info!(
            "\n ================== secret key ============== \n{}",
            cc.to_string()
        );
    }
}
