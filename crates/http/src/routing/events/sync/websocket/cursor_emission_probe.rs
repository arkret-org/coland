//! Conformance-only scheduling at the physical cursor delivery boundary.
//! This probe cannot alter a frame or bypass current authorization.

use super::*;

pub(super) async fn pause(
    state: &AppState,
    parameters: &WebSocketOpenParameters,
    frame: &WebSocketServerFrame,
) -> Result<(), ErrorCode> {
    if !state.config().development_mode {
        return Ok(());
    }
    let WebSocketOpenParameters::Account(parameters) = parameters else {
        return Ok(());
    };
    let Some(after) = parameters.after.as_deref() else {
        return Ok(());
    };
    if !matches!(
        frame,
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Account(_),
            ..
        }
    ) {
        return Ok(());
    }
    let Some(path) = std::env::var_os("COLAND_CONFORMANCE_CURSOR_EMISSION_PAUSE_FILE") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let selected = match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice::<Vec<arkret_wire::Hash>>(&bytes)
            .map_err(|_| ErrorCode::TemporarilyUnavailable)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ErrorCode::TemporarilyUnavailable),
    };
    let digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(after.as_bytes()))
        .map_err(|_| ErrorCode::InternalError)?;
    if !selected.contains(&digest) {
        return Ok(());
    }
    let pause = path.with_extension("pause");
    if !tokio::fs::try_exists(&pause)
        .await
        .map_err(|_| ErrorCode::TemporarilyUnavailable)?
    {
        return Ok(());
    }
    tokio::fs::write(
        path.with_extension("reached.json"),
        arkret_canonical::canonical_json_bytes(frame).map_err(|_| ErrorCode::InternalError)?,
    )
    .await
    .map_err(|_| ErrorCode::TemporarilyUnavailable)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::fs::try_exists(&pause)
        .await
        .map_err(|_| ErrorCode::TemporarilyUnavailable)?
    {
        if tokio::time::Instant::now() >= deadline {
            return Err(ErrorCode::TemporarilyUnavailable);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}
