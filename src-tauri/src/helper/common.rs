use rand::RngCore;

use super::errors::Result;

#[tauri::command]
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut iv: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut iv);
    Ok(iv)
}
