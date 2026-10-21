//! Current MLS admission gates for locally authored messages.
use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::{Event, ScopeRef};
/// Why the current MLS send gate refuses one application body; the gate is
/// shared by self Event submit and the accepting
/// transaction, so every surface answers the same state with the same
/// registered identity (encryption-and-audit §2.5.2, decision 0100).
pub(crate) use coland_storage::MlsSendGateRefusal;

use crate::state::AppState;

/// Failure of the current MLS send gate.
#[derive(Debug)]
pub(crate) enum MlsSendGateError {
    Refused(MlsSendGateRefusal),
    CurrentUnavailable,
}

/// Evaluate the current MLS send gate for one application body.
///
/// `envelopes` is `None` for a plaintext body and otherwise every encrypted
/// envelope the body carries (content, then optional metadata). The gate only
/// reads: it never writes or reserves anything, so the same state gives the
/// same answer. Precedence follows §2.5.2: an uncovered key-access checkpoint
/// wins over a stale frozen epoch.
pub(crate) async fn mls_send_gate(
    state: &AppState,
    scope: &ScopeRef,
    envelopes: Option<&[&EncryptedEnvelope]>,
) -> Result<(), MlsSendGateError> {
    let current = state
        .mls_groups()
        .current(scope)
        .await
        .map_err(|_| MlsSendGateError::CurrentUnavailable)?;
    coland_storage::decide_mls_send_gate(
        current.as_ref().map(|current| &current.value),
        scope,
        envelopes,
    )
    .map_err(MlsSendGateError::Refused)
}

/// Apply the current MLS send gate to one self-submitted `ak.message.create`.
///
/// Runs before the authority transaction is prepared, so every refusal leaves
/// no Commit, idempotency record or projection behind. The refusal travels as
/// a typed [`coland_storage::ConflictCode`] so the HTTP layer renders its
/// registered identity without reading diagnostic text.
pub(crate) async fn message_create_send_gate(
    state: &AppState,
    event: &Event,
) -> Result<(), coland_services::ServiceError> {
    use coland_services::ServiceError;
    use coland_storage::ConflictCode;
    let envelopes = coland_storage::message_create_envelopes(&event.payload)
        .map_err(ServiceError::SchemaViolation)?;
    let envelopes = envelopes
        .as_ref()
        .map(|envelopes| envelopes.iter().collect::<Vec<_>>());
    mls_send_gate(state, &event.scope_ref, envelopes.as_deref())
        .await
        .map_err(|error| match error {
            MlsSendGateError::CurrentUnavailable => ServiceError::Conflict(format!(
                "{}: current MLS group is temporarily unavailable",
                ConflictCode::TemporarilyUnavailable
            )),
            MlsSendGateError::Refused(refusal) => {
                ServiceError::Conflict(format!("{}: {}", refusal.conflict_code(), refusal.detail()))
            }
        })
}
