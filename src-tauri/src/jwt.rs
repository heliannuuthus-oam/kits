use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

pub mod jwe;
pub mod jwk;
pub mod jws;

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "lowercase")]
pub enum JwkeyType {
    RSA,
    EcDSA,
    Ed25519,
    X25519,
    Symmetric,
}
