use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EncryptionMode {
    Ecb,
    Cbc,
    Gcm,
}
#[derive(Serialize, Deserialize, Debug)]
pub enum AesEncryptionPadding {
    Pkcs7Padding,
    NoPadding,
}
