//! Development-only scheduling immediately before the actual token final cut.
//! Only request digests and a readiness marker leave this function.

use super::{AppError, AppState, CallMediaTokenExchangeRequestBody};

pub(super) async fn pause(
    state: &AppState,
    request: &CallMediaTokenExchangeRequestBody,
) -> Result<(), AppError> {
    if !state.config().development_mode {
        return Ok(());
    }
    let Some(path) = std::env::var_os("COLAND_CONFORMANCE_MEDIA_TOKEN_RELEASE_PAUSE_FILE") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(AppError::internal(error.to_string())),
    };
    let expected: arkret_wire::Hash =
        serde_json::from_slice(&bytes).map_err(|error| AppError::internal(error.to_string()))?;
    if expected.as_str()
        != arkret_canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(error.to_string()))?
    {
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
            return Err(AppError::internal("token final cut probe deadline"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
