use anyhow::{anyhow, Context};

use crate::helper::errors::{Error, Result};

#[tauri::command]
pub fn generate_ecc(curve_name: &str) -> Result<String> {
    let mut rng = rand::thread_rng();
    Ok(match curve_name {
        "p256" => {
            p256::SecretKey::random(&mut rng).to_sec1_pem(pkcs8::LineEnding::LF)
        }
        "p384" => {
            p384::SecretKey::random(&mut rng).to_sec1_pem(pkcs8::LineEnding::LF)
        }
        "p521" => {
            p521::SecretKey::random(&mut rng).to_sec1_pem(pkcs8::LineEnding::LF)
        }
        "p256k" => {
            k256::SecretKey::random(&mut rng).to_sec1_pem(pkcs8::LineEnding::LF)
        }

        cc => {
            return Err(Error::Internal(anyhow!(
                "unsupport curve name: {}",
                cc
            )))
        }
    }
    .context(format!("export {} key failed", curve_name))
    .unwrap()
    .to_string())
}
