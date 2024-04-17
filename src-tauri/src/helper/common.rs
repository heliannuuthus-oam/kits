use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::errors::Result;
#[derive(Serialize, Deserialize)]
pub struct KeyTuple(pub ByteBuf, pub ByteBuf);

#[tauri::command]
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut iv: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut iv);
    Ok(iv)
}
