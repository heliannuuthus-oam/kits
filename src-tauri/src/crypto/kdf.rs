use std::{fmt::Debug, vec};

use anyhow::Context;
use crypto_common::BlockSizeUser;
use digest::{
    block_buffer::Eager,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore},
    generic_array::typenum::{IsLess, Le, NonZero, U256},
    FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser,
};
use hkdf::hmac::Hmac;
use serde::{Deserialize, Serialize};

use super::EncryptionDto;
use crate::utils::{
    enums::{Digest, Kdf, TextEncoding},
    errors::{Error, Result},
};

pub(crate) const SALT: &str = "VSPDJrx1Pj1zqVGN";

#[derive(Serialize, Deserialize)]
pub struct KdfDto {
    pub kdf: Kdf,
    pub digest: Digest,
    pub input: String,
    pub input_encoding: TextEncoding,
    pub salt: Option<String>,
    pub salt_encoding: Option<TextEncoding>,
    pub info: Option<String>,
    pub info_encoding: Option<TextEncoding>,
    pub output_encoding: TextEncoding,
    pub key_length: usize,
}

impl Debug for KdfDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdfDto")
            .field("kdf", &self.kdf)
            .field("digest", &self.digest)
            .field("input", &self.input.len())
            .field("input_encoding", &self.input_encoding)
            .field("salt_encoding", &self.salt_encoding)
            .field("info_encoding", &self.info_encoding)
            .field("output_encoding", &self.output_encoding)
            .field("key_length", &self.key_length)
            .finish()
    }
}

impl EncryptionDto for KdfDto {
    fn get_input(&self) -> Result<Vec<u8>> {
        self.input_encoding.decode(&self.input)
    }

    fn get_key(&self) -> Result<Vec<u8>> {
        unimplemented!()
    }

    fn get_output_encoding(&self) -> TextEncoding {
        self.output_encoding
    }
}

#[tauri::command]
pub fn kdf(data: KdfDto) -> Result<String> {
    let input = data.get_input()?;
    let salt_encoding = data.salt_encoding;
    let info_encoding = data.info_encoding;
    let salt = data.salt.and_then(|s| {
        salt_encoding.and_then(|encoding| encoding.decode(&s).ok())
    });
    let info = data.info.and_then(|s| {
        info_encoding.and_then(|encoding| encoding.decode(&s).ok())
    });

    let output = kdf_inner_digest(
        data.kdf,
        data.digest,
        &input,
        salt,
        info,
        data.key_length,
    )?;

    data.output_encoding.encode(&output)
}

pub(crate) fn kdf_inner_digest(
    kdf: Kdf,
    digest: Digest,
    input: &[u8],
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    key_size: usize,
) -> Result<Vec<u8>> {
    match digest {
        Digest::Sha1 => {
            kdf_inner::<sha1::Sha1>(kdf, input, salt, info, key_size)
        }
        Digest::Sha256 => {
            kdf_inner::<sha2::Sha256>(kdf, input, salt, info, key_size)
        }
        Digest::Sha384 => {
            kdf_inner::<sha2::Sha384>(kdf, input, salt, info, key_size)
        }
        Digest::Sha512 => {
            kdf_inner::<sha2::Sha512>(kdf, input, salt, info, key_size)
        }
        Digest::Sha3_256 => {
            kdf_inner::<sha3::Sha3_256>(kdf, input, salt, info, key_size)
        }
        Digest::Sha3_384 => {
            kdf_inner::<sha3::Sha3_384>(kdf, input, salt, info, key_size)
        }
        Digest::Sha3_512 => {
            kdf_inner::<sha3::Sha3_512>(kdf, input, salt, info, key_size)
        }
    }
}

fn kdf_inner<D>(
    kdf: Kdf,
    input: &[u8],
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    key_size: usize,
) -> Result<Vec<u8>>
where
    D: CoreProxy
        + OutputSizeUser
        + FixedOutput
        + Clone
        + std::marker::Sync
        + FixedOutputReset
        + Default
        + digest::Digest,
    D::Core: HashMarker
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone
        + Sync,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut okm = vec![0; key_size];

    Ok(match kdf {
        Kdf::HKdf => {
            let c: hkdf::Hkdf<D, Hmac<D>> =
                hkdf::Hkdf::<D, Hmac<D>>::new(salt.as_deref(), input);
            let info = info.unwrap_or_default();
            c.expand(&info, &mut okm).context("hkdf derive key faild")?;
            okm
        }
        Kdf::Concatenation => {
            let info = info.unwrap_or_default();
            concat_kdf::derive_key_into::<D>(input, &info, &mut okm)
                .context("concatenation derive key faild")?;
            okm
        }
        Kdf::PbKdf2 => {
            let salt = salt.ok_or(Error::Unsupported(
                "pbkdf2 salt is required".to_string(),
            ))?;
            pbkdf2::pbkdf2::<Hmac<D>>(input, &salt, 600_000, &mut okm)
                .context("pbkdf2 derive key failed".to_string())?;
            okm
        }
        Kdf::Scrypt => {
            let salt = salt.ok_or(Error::Unsupported(
                "scrypt salt is required".to_string(),
            ))?;
            let params = scrypt::Params::recommended();
            scrypt::scrypt(input, &salt, &params, &mut okm)
                .context("scrypt failed")?;
            okm
        }
    })
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use pbkdf2::pbkdf2_hmac_array;
    use tracing::info;
    use tracing_test::traced_test;

    use crate::utils::common::random_bytes;

    #[test]
    #[traced_test]
    fn test_pbkdf_as_the_same_as_salt_usage() {
        let salt = "VSPDJrx1Pj1zqVGN";
        for length in [16, 32, 48, 64] {
            let start = Instant::now();
            let secret_bytes = random_bytes(length).unwrap();
            let first_result = pbkdf2_hmac_array::<sha2::Sha512, 48>(
                &secret_bytes,
                salt.as_bytes(),
                210_000,
            );
            info!("secret_bytes: {}", first_result.len());
            let second_result = pbkdf2_hmac_array::<sha2::Sha512, 48>(
                &secret_bytes,
                salt.as_bytes(),
                210_000,
            );
            assert_eq!(first_result, second_result);
            let duration = start.elapsed();
            info!("Time elapsed in expensive_function() is: {:?}", duration);
        }
    }
}
