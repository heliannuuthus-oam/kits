use anyhow::Context;
use pem_rfc7468::PemLabel;
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    codec::{
        private_bytes_to_pkcs8, private_pkcs8_to_bytes, public_bytes_to_pkcs8,
        public_pkcs8_to_bytes, PkcsDto,
    },
    enums::{KeyFormat, Pkcs, TextEncoding},
    errors::{Error, Result},
    utils::KeyTuple,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaKeyInfo {
    key_size: usize,
    encoding: TextEncoding,
    pkcs: Pkcs,
    format: KeyFormat,
}

#[tauri::command]
pub async fn generate_rsa(
    key_size: usize,
    pkcs: Pkcs,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<KeyTuple> {
    info!(
        "generate rsa key, key_size: {}, pkcs_encoding: {:?}, encoding: {:?}",
        key_size, pkcs, format
    );
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, key_size)
        .expect("generate rsa key failed");
    let public_key = private_key.to_public_key();
    let private_key_bytes = private_key_to_bytes(private_key, pkcs, format)?;
    let public_key_bytes = public_key_to_bytes(public_key, pkcs, format)?;
    Ok(KeyTuple::new(
        encoding.encode(&private_key_bytes)?,
        encoding.encode(&public_key_bytes)?,
    ))
}

#[tauri::command]
pub async fn derive_rsa(
    key: String,
    pkcs: Pkcs,
    format: KeyFormat,
    encoding: TextEncoding,
) -> Result<String> {
    info!(
        "generate rsa public key, pkcs_encoding: {:?}, key_encoding: {:?}",
        pkcs, format
    );
    let key_bytes = encoding.decode(&key)?;
    let private_key = bytes_to_private_key(&key_bytes, pkcs, format)?;
    let public_key = RsaPublicKey::from(private_key);
    encoding.encode(&public_key_to_bytes(public_key, pkcs, format)?)
}

#[tauri::command]
pub async fn transfer_rsa_key(
    private_key: Option<String>,
    public_key: Option<String>,
    from: PkcsDto,
    to: PkcsDto,
) -> Result<KeyTuple> {
    info!(
        "rsa key format transfer,  {:?} to {:?}. private->{}, public->{}",
        from,
        to,
        private_key.is_some(),
        public_key.is_some()
    );

    Ok(KeyTuple::new(
        if let Some(key) = private_key {
            let key_bytes = from.encoding.decode(&key)?;
            let private_bytes = pkcs8_pkcs1_converter_inner(
                key_bytes.as_slice(),
                from,
                to,
                false,
            )?;
            to.encoding.encode(&private_bytes)?
        } else {
            "".to_string()
        },
        if let Some(key) = public_key {
            let key_bytes = from.encoding.decode(&key)?;
            let public_bytes = pkcs8_pkcs1_converter_inner(
                key_bytes.as_slice(),
                from,
                to,
                true,
            )?;
            to.encoding.encode(&public_bytes)?
        } else {
            "".to_string()
        },
    ))
}

#[tauri::command]
pub fn parse_rsa(input: String) -> Result<RsaKeyInfo> {
    info!("parse rsa key: {}", input.len());
    let pem_decodor = |(input, format): (&str, KeyFormat)| {
        let (label, _) =
            pem_rfc7468::decode_vec(input.as_bytes()).context("invalid pem")?;

        let pkcs = match label {
            pkcs1::RsaPrivateKey::PEM_LABEL => Pkcs::Pkcs1,
            pkcs1::RsaPublicKey::PEM_LABEL => Pkcs::Pkcs1,
            pkcs8::PrivateKeyInfo::PEM_LABEL => Pkcs::Pkcs8,
            spki::SubjectPublicKeyInfoOwned::PEM_LABEL => Pkcs::Spki,
            _ => return Err(Error::Unsupported(label.to_string())),
        };

        let key_size = parse_key_size(input.as_bytes(), pkcs, format)?;
        Ok((pkcs, key_size))
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
    let (pkcs, key_size) = match format {
        KeyFormat::Pem => {
            pem_decodor((TextEncoding::Utf8.encode(&key)?.as_ref(), format))?
        }
        KeyFormat::Der => {
            if let Ok(key_size) = parse_key_size(&key, Pkcs::Pkcs8, format) {
                (Pkcs::Pkcs8, key_size)
            } else if let Ok(key_size) =
                parse_key_size(&key, Pkcs::Pkcs1, format)
            {
                (Pkcs::Pkcs1, key_size)
            } else if let Ok(key_size) =
                parse_key_size(&key, Pkcs::Spki, format)
            {
                (Pkcs::Spki, key_size)
            } else {
                return Err(Error::Unsupported("pkcs".to_string()));
            }
        }
    };

    Ok(RsaKeyInfo {
        key_size,
        encoding,
        format,
        pkcs,
    })
}

pub(crate) fn parse_key_size(
    key: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<usize> {
    Ok(
        if let Ok(private_key) = bytes_to_private_key(key, pkcs, format) {
            private_key.size() * 8
        } else if let Ok(public_key) = bytes_to_public_key(key, pkcs, format) {
            public_key.size() * 8
        } else {
            return Err(Error::Unsupported("rsa key content".to_string()));
        },
    )
}

pub(crate) fn bytes_to_private_key(
    input: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<RsaPrivateKey> {
    match pkcs {
        Pkcs::Pkcs8 => {
            private_bytes_to_pkcs8::<rsa::RsaPrivateKey>(input, format)
        }
        Pkcs::Pkcs1 => {
            private_bytes_to_pkcs1::<rsa::RsaPrivateKey>(input, format)
        }
        _ => Err(Error::Unsupported("unsupported rsa secret".to_string())),
    }
}

pub(crate) fn private_key_to_bytes(
    input: RsaPrivateKey,
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<Vec<u8>> {
    match pkcs {
        Pkcs::Pkcs8 => {
            private_pkcs8_to_bytes::<rsa::RsaPrivateKey>(input, format)
        }
        Pkcs::Pkcs1 => {
            private_pkcs1_to_bytes::<rsa::RsaPrivateKey>(input, format)
        }
        _ => Err(Error::Unsupported("unsupported rsa secret".to_string())),
    }
}

pub(crate) fn bytes_to_public_key(
    input: &[u8],
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<RsaPublicKey> {
    match pkcs {
        Pkcs::Pkcs8 => {
            public_bytes_to_pkcs8::<rsa::RsaPublicKey>(input, format)
        }
        Pkcs::Pkcs1 => {
            public_bytes_to_pkcs1::<rsa::RsaPublicKey>(input, format)
        }
        _ => Err(Error::Unsupported("unsupported rsa secret".to_string())),
    }
}

pub(crate) fn public_key_to_bytes(
    input: RsaPublicKey,
    pkcs: Pkcs,
    format: KeyFormat,
) -> Result<Vec<u8>> {
    match pkcs {
        Pkcs::Pkcs8 => {
            public_pkcs8_to_bytes::<rsa::RsaPublicKey>(input, format)
        }
        Pkcs::Pkcs1 => {
            public_pkcs1_to_bytes::<rsa::RsaPublicKey>(input, format)
        }
        _ => Err(Error::Unsupported("unsupported rsa secret".to_string())),
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
