use anyhow::Context;
use jose_jwk::OkpCurves;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

use crate::{
    enums::{self, JwkAlgorithm, RsaKeySize},
    errors::Result,
    utils::random_bytes,
};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JwkGenerate {
    pub algorithm: enums::JwkAlgorithm,
}

#[tauri::command]
pub(crate) async fn generate_jwk(
    algorithm: enums::JwkAlgorithm,
) -> Result<String> {
    let mut rng = rand::thread_rng();

    let key = match algorithm {
        JwkAlgorithm::HS256 => {
            let key = random_bytes(32)?;
            jose_jwk::Key::Oct(jose_jwk::Oct { k: key.into() })
        }
        JwkAlgorithm::HS384 => {
            let key = random_bytes(48)?;
            jose_jwk::Key::Oct(jose_jwk::Oct { k: key.into() })
        }
        JwkAlgorithm::HS512 => {
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
        JwkAlgorithm::RS256 | JwkAlgorithm::PS256 => {
            let private_key =
                RsaPrivateKey::new(&mut rng, RsaKeySize::Rsa2048 as usize)
                    .context("generate rsa 2048 key failed")?;
            jose_jwk::Key::Rsa(jose_jwk::Rsa::from(private_key))
        }
        JwkAlgorithm::RS384 | JwkAlgorithm::PS384 => {
            let private_key =
                RsaPrivateKey::new(&mut rng, RsaKeySize::Rsa3072 as usize)
                    .context("generate rsa 3072 key failed")?;
            jose_jwk::Key::Rsa(jose_jwk::Rsa::from(private_key))
        }
        JwkAlgorithm::RS512 | JwkAlgorithm::PS512 => {
            let private_key =
                RsaPrivateKey::new(&mut rng, RsaKeySize::Rsa4096 as usize)
                    .context("generate rsa 4096 key failed")?;
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
    };
    Ok(serde_json::to_string(&key).context("serilize jwk failed")?)
}

#[tauri::command]
pub(crate) fn jwk_algorithm() -> Vec<JwkAlgorithm> {
    JwkAlgorithm::iter().collect::<Vec<JwkAlgorithm>>()
}

#[cfg(test)]
mod test {
    use strum::IntoEnumIterator;
    use tracing::info;
    use tracing_test::traced_test;

    use crate::{enums::JwkAlgorithm, jwt::jwk::generate_jwk};

    #[tokio::test]
    #[traced_test]
    async fn test_generate_jwk() {
        for alg in JwkAlgorithm::iter() {
            info!("{}", generate_jwk(alg).await.unwrap())
        }
    }
}
