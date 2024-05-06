use crate::utils::{enums::TextEncoding, errors::Result};

pub mod aes;
pub mod ecc;
pub mod edwards;
pub mod kdf;
pub mod rsa;

pub trait EncryptionDto {
    fn get_input(&self) -> Result<Vec<u8>>;
    fn get_key(&self) -> Result<Vec<u8>>;
    fn get_output_encoding(&self) -> TextEncoding;
}

#[macro_export]
macro_rules! add_encryption_trait_impl {
  ($struct_name:ident { $($field_name:ident : $field_type:ty),* }) => {
      #[derive(Clone, Serialize, Deserialize)]
      #[serde(rename_all = "camelCase")]
      pub struct $struct_name {
          pub input: String,
          pub input_encoding: TextEncoding,
          pub key: String,
          pub key_encoding: TextEncoding,
          pub output_encoding: TextEncoding,
          $($field_name : $field_type,)*

      }

      impl EncryptionDto for $struct_name {
          fn get_input(&self) -> Result<Vec<u8>> {
            self.input_encoding.decode(&self.input)
          }
          fn get_key(&self) -> Result<Vec<u8>> {
            self.key_encoding.decode(&self.key)
          }
          fn get_output_encoding(&self) -> TextEncoding {
            self.output_encoding
          }
      }
  }
}
