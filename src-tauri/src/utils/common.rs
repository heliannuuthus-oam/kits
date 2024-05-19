use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

use super::errors::Result;
#[derive(Serialize, Deserialize)]
pub struct KeyTuple(pub Option<String>, pub Option<String>);

impl KeyTuple {
    pub fn new(private_key: String, public_key: String) -> Self {
        KeyTuple(Some(private_key), Some(public_key))
    }

    pub fn empty() -> Self {
        KeyTuple(None, None)
    }

    pub fn private(&mut self, key: Option<String>) -> &mut Self {
        self.0 = key;
        self
    }

    pub fn public(&mut self, key: Option<String>) -> &mut Self {
        self.1 = key;
        self
    }
}

#[tauri::command]
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    Ok(rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .collect())
}
