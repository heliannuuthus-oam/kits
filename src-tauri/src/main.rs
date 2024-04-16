// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Context;
use helper::errors::Result;
use tracing_subscriber::fmt::writer::MakeWriterExt;

mod crypto;
mod helper;

fn main() -> Result<()> {
    let file_appender = tracing_appender::rolling::daily("./log", "app.log");

    let (std_writer, _guard) =
        tracing_appender::non_blocking(std::io::stdout());
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
        .compact()
        .with_writer(std_writer.and(file_writer))
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber)
        .context("initial tracing subscriber failed")?;

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            // key generator
            crypto::aes::generate_aes,
            crypto::aes::generate_iv,
            crypto::ed25519::generate_ed25519,
            crypto::ecc::generate_ecc,
            crypto::rsa::generate_rsa,
            // encrytion
            crypto::aes::encrypt_aes,
            crypto::aes::decrypt_aes,
            crypto::rsa::encrypt_rsa,
            crypto::rsa::decrypt_rsa,
            // format
            helper::codec::base64_encode,
            helper::codec::base64_decode,
            helper::codec::hex_encode,
            helper::codec::hex_decode,
            helper::codec::string_encode,
            helper::codec::string_decode
        ])
        .run(tauri::generate_context!())
        .context("error while running tauri application")?;
    Ok(())
}
