use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Nonce};
use anyhow::Context;
use base64ct::Encoding;
use der::{pem::PemLabel, Encode};
use digest::KeyInit;
use elliptic_curve::{zeroize::Zeroizing, AffinePoint};
use p256::NistP256;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde_bytes::ByteBuf;
use spki::DecodePublicKey;
use tracing::info;

use crate::helper::{
    common::KeyTuple,
    enums::{
        EccCurveName, EccKeyFormat, EciesEncryptionAlgorithm, KeyEncoding,
    },
    errors::{Error, Result},
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
        EccCurveName::Curve25519 => generate_curve_25519_key(format, encoding),
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
        EccCurveName::Curve25519 => curve_25519_ecies_inner(
            &plaintext,
            &key,
            format,
            encoding,
            ea,
            for_encryption,
        ),
    }
}

pub fn ecies_inner<C>(
    input: ByteBuf,
    key: ByteBuf,
    format: EccKeyFormat,
    encoding: KeyEncoding,
    ea: EciesEncryptionAlgorithm,
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
        let mut result = Vec::new();
        let recevicer_secret_key =
            elliptic_curve::SecretKey::<C>::random(&mut rng);
        let recevicer_public_key = recevicer_secret_key.public_key();
        let octet_string = recevicer_public_key.to_sec1_bytes();

        info!("octet string length: {}", octet_string.len());
        let public_key = import_ecc_public_key::<C>(&key, encoding)?;
        let shared_secret = elliptic_curve::ecdh::diffie_hellman(
            recevicer_secret_key.to_nonzero_scalar(),
            public_key.as_affine(),
        );
        let shared_secret_bytes = shared_secret.raw_secret_bytes();
        let cipher = Aes256Gcm::new_from_slice(shared_secret_bytes)
            .context("init aes 256 gcm cipher failed")?;
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        result.extend_from_slice(nonce.as_slice());
        let mut payload = input.to_vec();
        cipher
            .encrypt_in_place(&nonce, b"", &mut payload)
            .context("encrypt failed")?;
        result.extend_from_slice(&payload);
        result
    } else {
        let mut receiver_public_secret_bytes = [0; 32];
        receiver_public_secret_bytes.copy_from_slice(&input[.. 32]);
        let private_key = import_ecc_private_key::<C>(&key, format, encoding)?;

        let receiver_public_secret = import_ecc_public_key::<C>(
            &receiver_public_secret_bytes,
            encoding,
        )?;

        let shared_secret = elliptic_curve::ecdh::diffie_hellman(
            private_key.to_nonzero_scalar(),
            receiver_public_secret.as_affine(),
        );
        let shared_secret_bytes = shared_secret.raw_secret_bytes();
        let cipher = Aes256Gcm::new_from_slice(shared_secret_bytes)
            .context("init aes 256 gcm cipher failed")?;
        let mut nonce_bytes: [u8; 12] = [0; 12];
        nonce_bytes.copy_from_slice(&input[32 .. 32 + 12]);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext: Vec<u8> = vec![0; input[32 + 12 ..].len()];
        ciphertext.copy_from_slice(&input[32 + 12 ..]);
        cipher
            .decrypt_in_place(nonce, b"", &mut ciphertext)
            .context("decrypt failed")?;
        ciphertext
    }))
}

pub fn curve_25519_ecies_inner(
    input: &[u8],
    key: &[u8],
    format: EccKeyFormat,
    encoding: KeyEncoding,
    ea: EciesEncryptionAlgorithm,
    for_encryption: bool,
) -> Result<ByteBuf> {
    let mut rng = rand::thread_rng();
    let result = if for_encryption {
        let mut result = Vec::new();
        let receiver_secret_key =
            x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
        let verifying_key = import_curve_25519_public_key(key, encoding)?;
        let public_key = x25519_dalek::PublicKey::from(
            verifying_key.to_montgomery().to_bytes(),
        );
        let receiver_public_key =
            x25519_dalek::PublicKey::from(&receiver_secret_key);
        result.extend_from_slice(receiver_public_key.as_bytes());
        let shared_secret = receiver_secret_key.diffie_hellman(&public_key);
        let shared_secret_bytes = shared_secret.as_bytes();
        let cipher = Aes256Gcm::new_from_slice(shared_secret_bytes)
            .context("init aes 256 gcm cipher failed")?;
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        result.extend_from_slice(nonce.as_slice());
        let mut payload = input.to_vec();
        cipher
            .encrypt_in_place(&nonce, b"", &mut payload)
            .context("encrypt failed")?;
        result.extend_from_slice(&payload);
        result
    } else {
        let mut receiver_secret = [0; 32];
        receiver_secret.copy_from_slice(&input[.. 32]);
        let signing_key =
            import_curve_25519_private_key(key, format, encoding)?;
        let private_key =
            x25519_dalek::StaticSecret::from(signing_key.to_scalar_bytes());
        let public_key = x25519_dalek::PublicKey::from(receiver_secret);
        let shared_secret = private_key.diffie_hellman(&public_key);
        let shared_secret_bytes = shared_secret.as_bytes();
        info!(
            "decryption shared_secret_bytes: {}",
            base64ct::Base64::encode_string(shared_secret_bytes)
        );
        let cipher = Aes256Gcm::new_from_slice(shared_secret_bytes)
            .context("init aes 256 gcm cipher failed")?;
        let mut nonce_bytes: [u8; 12] = [0; 12];
        nonce_bytes.copy_from_slice(&input[32 .. 32 + 12]);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext: Vec<u8> = vec![0; input[32 + 12 ..].len()];
        ciphertext.copy_from_slice(&input[32 + 12 ..]);
        cipher
            .decrypt_in_place(nonce, b"", &mut ciphertext)
            .context("decrypt failed")?;
        ciphertext
    };
    Ok(ByteBuf::from(result))
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

fn generate_curve_25519_key(
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<KeyTuple> {
    let mut rng = rand::thread_rng();
    let secret_key = ed25519_dalek::SigningKey::generate(&mut rng);

    let private_key =
        export_curve_25519_private_key(&secret_key, format, encoding)?;
    let public_secret_key = secret_key.verifying_key();
    let public_key =
        export_curve_25519_public_key(public_secret_key, encoding)?;
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

fn import_curve_25519_private_key(
    input: &[u8],
    format: EccKeyFormat,
    encoding: KeyEncoding,
) -> Result<ed25519_dalek::SigningKey> {
    let transfer = |der_bytes| {
        sec1::EcPrivateKey::try_from(der_bytes).context("unprocessed error")
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

            let private_key_pem = pem::parse(private_key_str)
                .context("pem parse private key failed")?;

            if private_key_pem.tag() != sec1::EcPrivateKey::PEM_LABEL {
                return Err(Error::Unsupported(
                    "unsuppoted sec1 tag".to_string(),
                ));
            }
            let sec1_private_key: sec1::EcPrivateKey =
                transfer(private_key_pem.contents())?;
            let mut private_key: ed25519_dalek::SecretKey = [0; 32];
            private_key[.. 32].clone_from_slice(sec1_private_key.private_key);
            ed25519_dalek::SigningKey::from_bytes(&private_key)
        }
        (EccKeyFormat::Sec1, KeyEncoding::Der) => {
            let sec1_private_key = transfer(input)?;
            let mut private_key: ed25519_dalek::SecretKey = [0; 32];
            private_key[.. 32].clone_from_slice(sec1_private_key.private_key);
            ed25519_dalek::SigningKey::from_bytes(&private_key)
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

fn import_curve_25519_public_key(
    input: &[u8],
    from: KeyEncoding,
) -> Result<ed25519_dalek::VerifyingKey> {
    Ok(match from {
        KeyEncoding::Pem => {
            let public_key_str = String::from_utf8(input.to_vec())
                .context("informal ecc public key")?;
            info!("curve 25519 public key: {}", public_key_str);
            ed25519_dalek::VerifyingKey::from_public_key_pem(&public_key_str)
                .context("informal pem public key")?
        }
        KeyEncoding::Der => {
            ed25519_dalek::VerifyingKey::from_public_key_der(input)
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

fn export_curve_25519_private_key(
    secret_key: &ed25519_dalek::SigningKey,
    format: EccKeyFormat,
    codec: KeyEncoding,
) -> Result<Vec<u8>> {
    let transfer = |secret_key: &ed25519_dalek::SigningKey| {
        let private_key_bytes = Zeroizing::new(secret_key.to_bytes());
        let public_key_bytes = secret_key.verifying_key();
        let cc = Zeroizing::new(
            sec1::EcPrivateKey {
                private_key: private_key_bytes.as_ref(),
                parameters: None,
                public_key: Some(public_key_bytes.as_bytes()),
            }
            .to_der()
            .context("curve_25519 to sec1 private key der failed")?,
        );
        Ok(cc)
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
                let ec_private_key_res: Result<Zeroizing<Vec<u8>>> =
                    transfer(secret_key);
                let ec_private_key_res = ec_private_key_res?;
                let ec_private_key: &[u8] = ec_private_key_res.as_ref();
                let pem = pem::Pem::new(
                    sec1::EcPrivateKey::PEM_LABEL,
                    ec_private_key,
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

fn export_curve_25519_public_key(
    public_key: ed25519_dalek::VerifyingKey,
    codec: KeyEncoding,
) -> Result<Vec<u8>> {
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
                            .unwrap_or_else(|_| {
                                panic!("generate {:?} key failed", curve_name)
                            });

                    let cipher = ecies(
                        curve_name,
                        key.1,
                        ByteBuf::from(b"plaintext"),
                        key_format,
                        key_encoding,
                        EciesEncryptionAlgorithm::Aes256Gcm,
                        true,
                    )
                    .unwrap_or_else(|_| {
                        panic!("{:?} ecies encryption failed", curve_name)
                    });

                    let plaintext = ecies(
                        curve_name,
                        key.0,
                        cipher,
                        EccKeyFormat::Sec1,
                        key_encoding,
                        EciesEncryptionAlgorithm::Aes256Gcm,
                        false,
                    )
                    .unwrap_or_else(|_| {
                        panic!("{:?} ecies decryption failed", curve_name)
                    });
                    let result = String::from_utf8_lossy(&plaintext);
                    assert_eq!(result, "plaintext")
                }
            }
        }
    }
}
