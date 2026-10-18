//! Development-only scheduling at the final Consent/private delivery CAS.
//! The probe neither supplies authority material nor overrides the writer.

use super::{AppError, AppState};

pub(super) async fn pause(
    state: &AppState,
    holder: &arkret_wire::AccountId,
    invite: &arkret_identifiers::InviteId,
) -> Result<(), AppError> {
    if !state.config().development_mode {
        return Ok(());
    }
    let Some(path) = std::env::var_os("COLAND_CONFORMANCE_INVITE_DELIVERY_PAUSE_FILE") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let selected = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(AppError::internal(error.to_string())),
    };
    let selected: (arkret_wire::AccountId, arkret_identifiers::InviteId) =
        serde_json::from_slice(&selected).map_err(|error| AppError::internal(error.to_string()))?;
    if &selected.0 != holder || &selected.1 != invite {
        return Ok(());
    }
    tokio::fs::write(path.with_extension("reached"), b"ready")
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match tokio::fs::metadata(&path).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(AppError::internal(error.to_string())),
            Ok(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AppError::internal("invite scheduling probe deadline"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
