use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

use super::errors::Result;
#[derive(Serialize, Deserialize)]
pub struct KeyTuple(pub String, pub String);

impl KeyTuple {
    pub fn new(private_key: String, public_key: String) -> Self {
        KeyTuple(private_key, public_key)
    }
}

#[tauri::command]
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    Ok(rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .collect())
}
