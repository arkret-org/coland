use super::*;

/// Revoke every active bearer session for an actor.
pub async fn revoke_sessions_for_actor(state: &AppState, actor: &str) -> Result<usize, String> {
    state
        .sessions()
        .revoke_actor_sessions(actor, now())
        .await
        .map_err(|error| error.to_string())
}

/// Revoke every active device record for an actor.
pub async fn revoke_devices_for_actor(state: &AppState, actor: &str) -> Result<usize, String> {
    state
        .persistence()
        .revoke_local_devices(actor, now())
        .await
        .map_err(|error| error.to_string())
}

// ── Development Session Credential Derivation ───────────────────────────────

#[derive(Default)]
pub(crate) struct DeviceDeliveryPurgeOutcome {
    pub to_device_messages_dropped: usize,
    pub push_registrations_removed: usize,
}

pub(crate) async fn purge_device_delivery_state(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> DeviceDeliveryPurgeOutcome {
    let result = match state
        .deliveries()
        .purge_device_delivery(actor, device_id)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, actor, device_id, "failed to purge device delivery state");
            return DeviceDeliveryPurgeOutcome::default();
        }
    };
    DeviceDeliveryPurgeOutcome {
        to_device_messages_dropped: result.to_device_messages_dropped,
        push_registrations_removed: result.push_registrations_removed,
    }
}

/// Derive a single-use development session credential. The credential is opaque
/// to the client; what the server stores is its `session_credential_hash`.
#[cfg(any(test, feature = "conformance-harness"))]
pub fn token_for(actor: &str, device_id: &str, expires_ms: i64) -> String {
    let nonce = ids::generate("session");
    let mut hasher = Sha256::new();
    hasher.update(actor.as_bytes());
    hasher.update(b":");
    hasher.update(device_id.as_bytes());
    hasher.update(b":");
    hasher.update(expires_ms.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(nonce.as_bytes());
    hasher.update(b":coland-dev-session");
    format!("sx_{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Service-ID bound hash of a session credential, used as the persistence key
/// so cross-service credentials can never collide.
pub fn session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}
