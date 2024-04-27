use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::errors::Result;
#[derive(Serialize, Deserialize)]
pub struct KeyTuple(pub ByteBuf, pub ByteBuf);

#[tauri::command]
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    Ok(rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .collect())
}
