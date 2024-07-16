use anyhow::Context;
use jose_jwk::OkpCurves;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::JwkeyType;
use crate::{
    enums::{self, JwkAlgorithm, RsaKeySize},
    errors::Result,
    utils::{random_bytes, random_id},
};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JwkGenerate {
    pub key_id: Option<String>,
    pub key_type: JwkeyType,
    pub algorithm: enums::JwkAlgorithm,
}

#[tauri::command]
pub(crate) async fn generate_jwk(data: JwkGenerate) -> Result<String> {
    let mut value = generate_jwk_inner(data.algorithm).await?;
    value["kid"] =
        serde_json::Value::String(data.key_id.unwrap_or(random_id()?));
    value["alg"] = json!(data.algorithm);
    Ok(value.to_string())
}

pub(crate) async fn generate_jwk_inner(
    algorithm: enums::JwkAlgorithm,
) -> Result<serde_json::Value> {
    let mut rng = rand::thread_rng();

    let key = match algorithm {
        JwkAlgorithm::Dir
        | JwkAlgorithm::HS256
        | JwkAlgorithm::A128GCM
        | JwkAlgorithm::A128GCMKW
        | JwkAlgorithm::A128KW
        | JwkAlgorithm::A128cbcHs256 => {
            let key = random_bytes(32)?;
            jose_jwk::Key::Oct(jose_jwk::Oct { k: key.into() })
        }
        JwkAlgorithm::HS384
        | JwkAlgorithm::A192GCM
        | JwkAlgorithm::A192GCMKW
        | JwkAlgorithm::A192KW
        | JwkAlgorithm::A192cbcHs384 => {
            let key = random_bytes(48)?;
            jose_jwk::Key::Oct(jose_jwk::Oct { k: key.into() })
        }
        JwkAlgorithm::HS512
        | JwkAlgorithm::A256GCM
        | JwkAlgorithm::A256GCMKW
        | JwkAlgorithm::A256KW
        | JwkAlgorithm::A256cbcHs512 => {
            let key = random_bytes(64)?;
            jose_jwk::Key::Oct(jose_jwk::Oct { k: key.into() })
        }
        JwkAlgorithm::ES256 => {
            let secret_key =
                elliptic_curve::SecretKey::<p256::NistP256>::random(&mut rng);
            jose_jwk::Key::Ec(jose_jwk::Ec::from(secret_key))
        }
        JwkAlgorithm::ES384 => {
            let secret_key =
                elliptic_curve::SecretKey::<p384::NistP384>::random(&mut rng);
            jose_jwk::Key::Ec(jose_jwk::Ec::from(secret_key))
        }
        JwkAlgorithm::ES521 => {
            let secret_key =
                elliptic_curve::SecretKey::<p521::NistP521>::random(&mut rng);
            jose_jwk::Key::Ec(jose_jwk::Ec::from(secret_key))
        }
        JwkAlgorithm::ES256K => {
            let secret_key =
                elliptic_curve::SecretKey::<k256::Secp256k1>::random(&mut rng);
            jose_jwk::Key::Ec(jose_jwk::Ec::from(secret_key))
        }
        JwkAlgorithm::RS256
        | JwkAlgorithm::PS256
        | JwkAlgorithm::RS384
        | JwkAlgorithm::PS384
        | JwkAlgorithm::RS512
        | JwkAlgorithm::PS512
        | JwkAlgorithm::Rsa1_5
        | JwkAlgorithm::RsaOaep
        | JwkAlgorithm::RsaOaep256
        | JwkAlgorithm::RsaOaep384
        | JwkAlgorithm::RsaOaep521 => {
            let private_key =
                RsaPrivateKey::new(&mut rng, RsaKeySize::Rsa2048 as usize)
                    .context("generate rsa 2048 key failed")?;
            jose_jwk::Key::Rsa(jose_jwk::Rsa::from(private_key))
        }

        JwkAlgorithm::EdDSA => {
            let ed = ed25519_dalek::SigningKey::generate(&mut rng);
            let ed_verify_key = ed.verifying_key();
            jose_jwk::Key::Okp(jose_jwk::Okp {
                crv: OkpCurves::Ed25519,
                x: ed_verify_key.to_bytes().to_vec().into(),
                d: Some(ed.as_bytes().to_vec().into()),
            })
        }
        JwkAlgorithm::EcdhEs
        | JwkAlgorithm::EcdhEsA128kw
        | JwkAlgorithm::EcdhEsA192kw
        | JwkAlgorithm::EcdhEsA256kw => {
            let x25519_key =
                x25519_dalek::StaticSecret::random_from_rng(&mut rng);
            let x25519_pub_key = x25519_dalek::PublicKey::from(&x25519_key);
            jose_jwk::Key::Okp(jose_jwk::Okp {
                crv: OkpCurves::X25519,
                x: x25519_pub_key.as_bytes().to_vec().into(),
                d: Some(x25519_key.as_bytes().to_vec().into()),
            })
        }
    };
    Ok(serde_json::to_value(&key).context("serilize jwk failed")?)
}

#[cfg(test)]
mod test {
    use num_bigint::BigInt;
    
    
    use strum::IntoEnumIterator;
    use tracing::info;
    use tracing_test::traced_test;

    use crate::{
        enums::JwkAlgorithm,
        jwt::{
            jwk::{generate_jwk, JwkGenerate},
            JwkeyType,
        },
        utils::random_bytes,
    };

    #[tokio::test]
    #[traced_test]
    async fn test_generate_jwk() {
        for kty in JwkeyType::iter() {
            for alg in JwkAlgorithm::iter() {
                info!(
                    "{}",
                    generate_jwk(JwkGenerate {
                        key_id: Option::None,
                        key_type: kty,
                        algorithm: alg
                    })
                    .await
                    .unwrap()
                )
            }
        }
    }
    #[tokio::test]
    #[traced_test]
    async fn test_generate_kid() {
        let random_bytes = random_bytes(16).unwrap();
        let b_int =
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &random_bytes);
        info!("output: {}", b_int.to_str_radix(36));
    }
}
