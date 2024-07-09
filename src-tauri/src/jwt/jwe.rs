use crate::errors::Result;

#[tauri::command]
pub(crate) fn generate_jwe() -> Result<String> {
    Ok("".to_string())
}
