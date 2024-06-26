// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Context;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use utils::errors::Result;

pub mod crypto;
pub mod utils;

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
            crypto::rsa::key::generate_rsa,
            crypto::rsa::key::derive_rsa,
            crypto::ecc::key::generate_ecc,
            crypto::ecc::key::derive_ecc,
            crypto::ecc::key::parse_ecc,
            crypto::ecc::ecies,
            crypto::edwards::key::generate_edwards,
            crypto::edwards::key::derive_edwards,
            crypto::edwards::ecies_edwards,
            // encrytion
            crypto::aes::crypto_aes,
            crypto::rsa::crypto_rsa,
            crypto::ecc::ecies,
            // format
            crypto::rsa::key::transfer_rsa_key,
            crypto::ecc::key::transfer_ecc_key,
            crypto::edwards::key::transfer_edwards_key,
            // kdf
            crypto::kdf::kdf,
            // common
            utils::codec::convert_encoding,
            utils::common::digests,
            utils::common::elliptic_curve,
            utils::common::edwards,
            utils::common::kdfs,
            utils::common::ecies_enc_alg,
        ])
        .run(tauri::generate_context!())
        .context("error while running tauri application")?;
    Ok(())
}
