// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod helper;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            crypto::aes::generate_aes,
            crypto::aes::generate_iv,
            crypto::ed25519::generate_ed25519,
            crypto::ecc::generate_ecc,
            crypto::rsa::generate_rsa,
            crypto::aes::encrypt_aes,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
