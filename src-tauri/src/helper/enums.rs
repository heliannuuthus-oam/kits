use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum EncryptionMode {
    ECB,
    CBC,
    GCM,
}
#[derive(Serialize, Deserialize, Debug)]
pub enum AesEncryptionPadding {
    Pkcs7Padding,
    NoPadding,
}
