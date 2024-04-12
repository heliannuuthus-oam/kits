use anyhow::Context;
use pkcs8::EncodePrivateKey;

use crate::helper::errors::Result;

#[tauri::command]
pub fn generate_ed25519() -> Result<String> {
    let mut rng = rand::thread_rng();
    Ok(ed25519_dalek::SigningKey::generate(&mut rng)
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .context("export ed25519 key failed")?
        .to_string())
}
