// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod helper;

fn main() {
    let file_appender = tracing_appender::rolling::hourly("./log", "app.log");

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .compact()
        .with_writer(non_blocking)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber)
        .expect("initial tracing subscriber failed");

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            crypto::aes::generate_aes,
            crypto::aes::generate_iv,
            crypto::ed25519::generate_ed25519,
            crypto::ecc::generate_ecc,
            crypto::rsa::generate_rsa,
            crypto::aes::encrypt_aes,
            crypto::aes::decrypt_aes,
            helper::codec::base64_encode,
            helper::codec::base64_decode,
            helper::codec::hex_encode,
            helper::codec::hex_decode,
            helper::codec::string_encode,
            helper::codec::string_decode
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
