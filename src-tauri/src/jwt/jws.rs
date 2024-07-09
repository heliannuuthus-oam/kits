use crate::errors::Result;

#[tauri::command]
pub(crate) fn generate_jws() -> Result<String> {
    Ok("".to_string())
}
