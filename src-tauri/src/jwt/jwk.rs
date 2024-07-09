use crate::errors::Result;

#[tauri::command]
pub(crate) fn generate_jwk() -> Result<String> {
    Ok("".to_string())
}
