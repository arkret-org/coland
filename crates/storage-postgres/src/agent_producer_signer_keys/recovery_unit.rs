//! Freeze replacement-key history only inside the exact native recovery unit.
//! Neither a self-signed authorization alone nor later current state is a source.

use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_wire::{ActorId, Base64UrlString, CommittedEventRef, CurrentRevision};
use coland_storage::{PersistenceError, PersistenceResult, RecoveryUnitCommitWrite};

use super::{
    AsyncPgConnection, HistoricalSignerKeyQuerySender, PreparedSelfHistoricalFact,
    ResolvedSignerKey, SignerKeyQuerySelector, SignerKeyResolution,
    retain_self_outcome_in_connection,
};

fn rejected(reason: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("native recovery historical source: {reason}"))
}

/// The caller owns the terminal unit's PCR locks and PostgreSQL transaction.
/// Terminal validation/consumption follows on this same connection: any failure
/// rolls back both originals, their history facts and all other unit effects.
pub(crate) async fn retain_recovery_unit_in_connection(
    conn: &mut AsyncPgConnection,
    write: &RecoveryUnitCommitWrite,
) -> PersistenceResult<()> {
    write.validate()?;
    let resource = &write.transaction.resource;
    let plan = resource
        .recovery_plan()
        .ok_or_else(|| rejected("original recovery plan is absent"))?;
    let [reanchor, authorize] = &write.commits;
    let account = &resource.account_id;
    let payload: DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&authorize.event.payload).map_err(rejected)?)
            .map_err(rejected)?;
    arkret_signatures::verify_device_authorize_possession(&payload, account).map_err(rejected)?;
    let multibase = payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| rejected("replacement key is not did:key"))?;
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    let raw_key = arkret_canonical::decode_ed25519_multibase(multibase).map_err(rejected)?;
    let public_key =
        Base64UrlString::new(arkret_canonical::base64url_encode(raw_key)).map_err(rejected)?;
    let reference = |transaction: &coland_storage::AuthorityCommitTransaction| CommittedEventRef {
        event_id: transaction.event.event_id.clone(),
        commit_id: transaction.commit.commit_id.clone(),
        stream_ref: transaction.commit.stream_ref.clone(),
        stream_position: transaction.commit.stream_position,
    };
    let authorization_ref = reference(authorize);
    let key = ResolvedSignerKey {
        public_key_base64url: public_key,
        authorization_ref: authorization_ref.clone(),
        revision: CurrentRevision {
            commit_id: authorize.commit.commit_id.clone(),
            stream_position: authorize.commit.stream_position,
        },
        governance_generation: authorize.commit.governance_generation,
    };
    key.validate().map_err(rejected)?;
    let provenance = serde_json::json!({
        "accepted_pcr_realm_id": authorize.event.realm_id,
        "recovery_transaction_id": resource.transaction_id,
        "recovery_session_id": plan.binding.recovery_session_id,
        "reanchor_event_ref": reference(reanchor),
        "device_authorization_event_ref": authorization_ref,
    });
    for transaction in &write.commits {
        let event = &transaction.event;
        let suite = event.realm_id.digest_suite_code().digest_suite();
        let producer = event
            .verify_producer_proof_self_consistency(suite)
            .map_err(rejected)?
            .ok_or_else(|| rejected("original has no actual Human Device producer"))?;
        if event.actor_id != ActorId::account(account.clone())
            || producer.account_id != *account
            || producer.device_id != payload.device_id
            || event.executed_by.is_some()
        {
            return Err(rejected(
                "original is not self-signed by the exact replacement",
            ));
        }
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| rejected("original producer proof is absent"))?;
        let bytes = arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(rejected)?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &bytes,
            &event.actor_id,
            &material,
            suite,
        )
        .map_err(rejected)?;
        // This key is admitted by the complete recovery unit. In particular,
        // the Reanchor precedes its authorization in the same atomic unit; an
        // ordinary business-event authorization-at-target-time gate is wrong.
        let outcome = SignerKeyResolution::HistoricalResolved {
            selector: SignerKeyQuerySelector::HistoricalEvent {
                sender: HistoricalSignerKeyQuerySender::AccountDevice {
                    actor: event.actual_signer().clone(),
                    device_id: payload.device_id.clone(),
                    verification_method: proof.verification_method.clone(),
                    committed_event_ref: reference(transaction),
                },
            },
            key: key.clone(),
            accepted_at: authorize.commit.committed_at,
        };
        outcome.validate(&event.realm_id).map_err(rejected)?;
        retain_self_outcome_in_connection(
            conn,
            event,
            &transaction.commit,
            PreparedSelfHistoricalFact {
                outcome,
                kind: "own_pcr",
                provenance: provenance.clone(),
            },
        )
        .await?;
    }
    Ok(())
}
