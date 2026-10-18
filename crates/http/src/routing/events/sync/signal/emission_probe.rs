//! Development-only scheduling probe at the shared HTTP/WebSocket frame gate.
//! This has no wire surface and cannot override any admission decision.

use std::path::{Path, PathBuf};

use super::{AppError, AppState, SignalEnvelope, signal_rail_unavailable};

pub(super) async fn pause(
    state: &AppState,
    envelope: &SignalEnvelope,
    recipient: &arkret_wire::AccountId,
) -> Result<Option<PathBuf>, AppError> {
    if !state.config().development_mode {
        return Ok(None);
    }
    let Some(path) = std::env::var_os("COLAND_CONFORMANCE_SIGNAL_EMISSION_PAUSE_FILE") else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let selected = match tokio::fs::read(&path).await {
        Ok(selected) => selected,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(signal_rail_unavailable("read emission scheduling probe")),
    };
    // Local scheduling input reuses SDK identifiers; it is not a wire carrier.
    let selected: Vec<(arkret_wire::AccountId, arkret_wire::Hash)> =
        serde_json::from_slice(&selected)
            .map_err(|_| signal_rail_unavailable("decode emission scheduling probe"))?;
    let Some(index) = selected.iter().position(|(account, digest)| {
        account == recipient && digest == &envelope.proof.envelope_digest
    }) else {
        return Ok(None);
    };
    let path = path.with_extension(format!("{index}.pause"));
    if !tokio::fs::try_exists(&path)
        .await
        .map_err(|_| signal_rail_unavailable("read recipient emission scheduling probe"))?
    {
        return Ok(None);
    }
    // A WebSocket frame enters this gate once before queueing and again at
    // physical output. A local one-shot marker selects the latter pass.
    match tokio::fs::remove_file(path.with_extension("skip")).await {
        Ok(()) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(signal_rail_unavailable("select physical emission probe")),
    }
    let bytes = arkret_canonical::canonical_json_bytes(envelope)
        .map_err(|_| signal_rail_unavailable("encode emission scheduling probe"))?;
    tokio::fs::write(path.with_extension("reached.json"), bytes)
        .await
        .map_err(|_| signal_rail_unavailable("observe emission scheduling probe"))?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match tokio::fs::metadata(&path).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(signal_rail_unavailable("read emission scheduling probe")),
            Ok(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(signal_rail_unavailable(
                "emission scheduling probe deadline",
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Ok(Some(path))
}

pub(super) fn record(
    path: Option<&Path>,
    envelope: &SignalEnvelope,
    decision: &Result<(), AppError>,
    call_invitation: bool,
) -> Result<(), AppError> {
    let Some(path) = path else { return Ok(()) };
    let observed = serde_json::json!({
        "envelope_digest": envelope.proof.envelope_digest,
        "admitted": decision.is_ok(),
        "call_invitation": call_invitation,
        "error_code": decision.as_ref().err().map(|error| error.wire_code()),
        "observed_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
    });
    // Do not add an asynchronous hop after the final admission decision.
    std::fs::write(path.with_extension("outcome.json"), observed.to_string())
        .map_err(|_| signal_rail_unavailable("observe emission admission result"))
}
