use anyhow::Context;
use pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;

use crate::helper::errors::Result;

#[tauri::command]
pub fn generate_rsa(key_size: usize) -> Result<String> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, key_size)
        .expect("failed to generate a key");
    let secret = priv_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .context("export rsa key failed")?;
    Ok(secret.to_string())
}
