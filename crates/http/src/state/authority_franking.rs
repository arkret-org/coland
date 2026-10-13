//! Durable publication of a receiving Station's existing franking carrier.

use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyDirectory, verify_realm_authority_bundle,
};
use arkret_models_collaboration::events_payloads::moderation::FrankingProof;
use arkret_wire::{ActorId, Base64UrlString, EventKind};
use coland_services::committed_receipt::{
    CommitContinuity, ReceivedProducer, verify_committed_event_receipt_with_source,
};
use coland_services::{ServiceError, ServiceResult};
use ed25519_dalek::Signer as _;

use super::AppState;

fn refused(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::protocol(
        arkret_wire::ErrorCode::SignatureInvalid,
        format!("franking: {detail}"),
    )
}

#[derive(Default)]
struct HistoricalAuthorityKeys {
    keys: std::collections::BTreeMap<
        (arkret_wire::DidUrl, chrono::DateTime<chrono::Utc>),
        arkret_signatures::PublicKeyMaterial,
    >,
}
impl RealmAuthorityKeyDirectory for HistoricalAuthorityKeys {
    fn public_key(&self, _: &arkret_wire::DidUrl) -> Option<arkret_signatures::PublicKeyMaterial> {
        None
    }
    fn public_key_at(
        &self,
        method: &arkret_wire::DidUrl,
        signed_at: chrono::DateTime<chrono::Utc>,
    ) -> Option<arkret_signatures::PublicKeyMaterial> {
        self.keys.get(&(method.clone(), signed_at)).cloned()
    }
}

/// The history resolver checks the method at the signature's own time. A
/// later removal of that method is not a rejection of a historical receipt.
async fn historical_key(
    state: &AppState,
    signature: &arkret_wire::DetachedObjectSignature,
    keys: &mut HistoricalAuthorityKeys,
) -> ServiceResult<()> {
    let key = crate::jws_verify::resolve_ed25519_pubkey_at(
        state,
        signature.verification_method.as_str(),
        signature.created_at,
    )
    .await
    .map_err(refused)?;
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: key.as_bytes().to_vec(),
    };
    let coordinate = (signature.verification_method.clone(), signature.created_at);
    if keys
        .keys
        .get(&coordinate)
        .is_some_and(|previous| previous != &material)
    {
        return Err(refused(
            "one method names conflicting keys at the same historical time",
        ));
    }
    keys.keys.insert(coordinate, material);
    Ok(())
}

/// Reuse the ordinary accepted receipt verifier; never readmit the target or
/// use a current device-revocation verdict to reject its historical proof.
pub(crate) async fn verify_franking_committed_pair(
    state: &AppState,
    record: &coland_services::events::AcceptedEvent,
    pair: &coland_storage::CommittedEventRecord,
) -> ServiceResult<()> {
    let realm = &pair.event.realm_id;
    crate::routing::validate_franking_covering_commit(record, pair, realm).map_err(refused)?;
    let authority = state
        .authority_commits()
        .current_authority(realm)
        .await?
        .ok_or_else(|| refused("Realm authority is unavailable"))?;
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode(
        rand::random::<[u8; 32]>(),
    ))
    .map_err(refused)?;
    let bundle = if authority.service_id == state.service_core_id() {
        crate::routing::realm_join::local_authority_bundle(state, realm, &nonce)
            .await
            .map_err(refused)?
    } else {
        crate::routing::realm_join::fetch_authority_bundle_of_service(
            state,
            realm,
            &authority.service_id,
            &nonce,
        )
        .await
        .map_err(refused)?
    };
    let mut keys = HistoricalAuthorityKeys::default();
    historical_key(state, &bundle.genesis_commit.signature, &mut keys).await?;
    for transition in &bundle.authority_transitions {
        historical_key(state, &transition.change_commit.signature, &mut keys).await?;
        historical_key(
            state,
            &transition.handoff.old_authority_signature,
            &mut keys,
        )
        .await?;
        historical_key(
            state,
            &transition.handoff.new_authority_acceptance_signature,
            &mut keys,
        )
        .await?;
    }
    historical_key(state, &bundle.current_assertion.signature, &mut keys).await?;
    historical_key(state, &pair.commit.signature, &mut keys).await?;
    let verified = verify_realm_authority_bundle(
        &bundle,
        &RealmAuthorityFreshness::new(chrono::Utc::now(), nonce),
        &keys,
    )
    .map_err(refused)?;
    if verified.current_service_id() != &authority.service_id
        || verified.current_generation() != authority.generation
    {
        return Err(refused(
            "verified authority differs from the accepted current tenure",
        ));
    }
    let producer_signer_fact = state
        .authority_commits()
        .producer_signer_fact(&pair.event, &pair.commit)
        .await?;
    let received = verify_committed_event_receipt_with_source(
        state.persistence(),
        &pair.event,
        &pair.commit,
        CommitContinuity::Standalone,
        &verified,
        &keys,
        &state.service_core_id(),
        record.digest_suite,
        producer_signer_fact.as_ref(),
    )
    .await?;
    if received == ReceivedProducer::OtherSigner {
        let producer = pair
            .event
            .producer_proof
            .as_ref()
            .ok_or_else(|| refused("producer proof is absent"))?;
        let key_bytes = if pair.event.actual_signer().as_account_id().is_some() {
            // Runtime methods are authorized by an Agent PCR Event, rather
            // than by a DID document method. Use the original accepting cut.
            let selector = arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
                sender: arkret_models_identity::HistoricalSignerKeyQuerySender::Agent {
                    actor: pair.event.actual_signer().clone(),
                    verification_method: producer.verification_method.clone(),
                    committed_event_ref: arkret_wire::CommittedEventRef {
                        event_id: pair.event.event_id.clone(),
                        commit_id: pair.commit.commit_id.clone(),
                        stream_ref: pair.commit.stream_ref.clone(),
                        stream_position: pair.commit.stream_position,
                    },
                },
            };
            let result = state
                .authority_commits()
                .historical_producer_signer_key(realm, &selector)
                .await?;
            let Some(arkret_models_identity::SignerKeyQueryOutcome::HistoricalResolved {
                selector: actual,
                key,
                ..
            }) = result
            else {
                return Err(refused(
                    "exact historical Agent authorization is unavailable",
                ));
            };
            if actual != selector {
                return Err(refused("historical Agent selector differs"));
            }
            key.validate().map_err(refused)?;
            arkret_canonical::base64url_decode(key.public_key_b64u.as_str().as_bytes())
                .map_err(refused)?
        } else {
            crate::jws_verify::resolve_ed25519_pubkey_at(
                state,
                producer.verification_method.as_str(),
                pair.event.created_at,
            )
            .await
            .map_err(refused)?
            .as_bytes()
            .to_vec()
        };
        let bytes = arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(&pair.event)
            .map_err(refused)?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            producer,
            &bytes,
            &pair.event.actor_id,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: key_bytes },
            record.digest_suite,
        )
        .map_err(refused)?;
    }
    Ok(())
}

async fn author_proof(
    state: &AppState,
    job: &coland_storage::PendingFrankingProof,
    target: &coland_services::events::AcceptedEvent,
) -> ServiceResult<coland_storage::PreparedFrankingProof> {
    if job.received_by != state.service_core_id() {
        return Err(refused("this Station did not record the target receipt"));
    }
    let method = state
        .service_verification_method("notary-key")
        .map_err(refused)?;
    let historical =
        crate::jws_verify::resolve_ed25519_pubkey_at(state, method.as_str(), job.received_at)
            .await
            .map_err(refused)?;
    let signing = state.notary_signing_key();
    if historical.as_bytes() != signing.verifying_key().as_bytes() {
        return Err(refused(
            "the historical receiving method is not the installed signing key",
        ));
    }
    let mut proof = FrankingProof {
        realm_id: job.realm_id.clone(),
        event_id: job.target_event_id.clone(),
        received_by: job.received_by.clone(),
        verification_method: method.clone(),
        received_at: job.received_at,
        replay_nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 24]>()),
        signature: String::new(),
    };
    proof.signature = arkret_canonical::base64url_encode(
        signing
            .sign(&proof.canonical_signing_bytes().map_err(refused)?)
            .to_bytes(),
    );
    let created_at = chrono::Utc::now();
    let publishing_key =
        crate::jws_verify::resolve_ed25519_pubkey_at(state, method.as_str(), created_at)
            .await
            .map_err(refused)?;
    if publishing_key.as_bytes() != historical.as_bytes() {
        return Err(refused(
            "receiving method cannot sign the proof Event at publication time",
        ));
    }
    let mut draft = arkret_event_draft::TypedEventDraft::<
        arkret_wire::event_spec::ModerationFrankingProof,
    >::new(
        arkret_wire::ScopeRef::Realm {
            realm_id: job.realm_id.clone(),
        },
        ActorId::service(job.received_by.clone()),
        proof,
    )
    .map_err(refused)?
    .author_with_digest_suite(created_at, target.digest_suite)
    .map_err(refused)?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        signing.as_ref().clone(),
        state.service_did().clone(),
        method,
    );
    arkret_signatures::sign_event(
        &mut draft,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .map_err(refused)?;
    Ok(coland_storage::PreparedFrankingProof {
        realm_id: job.realm_id.clone(),
        target_event_id: job.target_event_id.clone(),
        received_by: job.received_by.clone(),
        event: draft.event().clone(),
        verification_key: historical.as_bytes().to_vec(),
    })
}

async fn publish_one(
    state: &AppState,
    job: coland_storage::PendingFrankingProof,
) -> ServiceResult<()> {
    let target = state
        .event_queries()
        .canonical_event(job.target_event_id.as_str())
        .await?
        .ok_or_else(|| refused("accepted target bytes are unavailable"))?;
    let pair = state
        .authority_commits()
        .committed_event(&job.target_event_id)
        .await?
        .ok_or_else(|| refused("accepted target Commit is unavailable"))?;
    if pair.event.realm_id != job.realm_id
        || pair.event.event_id != job.target_event_id
        || !matches!(
            pair.event.kind,
            EventKind::MessageCreate | EventKind::MessageRevise
        )
        || !pair
            .event
            .payload
            .get("encrypted_content")
            .is_some_and(serde_json::Value::is_object)
    {
        return Err(refused("job target is not the accepted encrypted Message"));
    }
    verify_franking_committed_pair(state, &target, &pair).await?;
    let event = match job.prepared_event.clone() {
        Some(event) => event,
        None => {
            let prepared = author_proof(state, &job, &target).await?;
            state
                .authority_commits()
                .fix_franking_proof(&prepared)
                .await?
        }
    };
    if let Some(existing) = state
        .authority_commits()
        .committed_event(&event.event_id)
        .await?
    {
        if existing.event != event {
            return Err(refused("fixed proof id has different accepted bytes"));
        }
        return state
            .authority_commits()
            .complete_franking_proof(&job.realm_id, &job.target_event_id, &event.event_id)
            .await;
    }
    let at = chrono::Utc::now();
    let method = state
        .service_verification_method("notary-key")
        .map_err(refused)?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            &event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            at,
        )
        .await?;
    let preimage =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(refused)?)
            .map_err(refused)?;
    let envelope = serde_json::to_value(&event).map_err(refused)?;
    state
        .events()
        .commit_accepted_event(coland_services::events::CommitAcceptedEventCommand {
            authority_commit: transaction,
            self_producer_guard: None,
            applet_producer_guard: None,
            widget_token_gate: None,
            agent_grant_scope_evidence: None,
            forwarded_producer_evidence: None,
            forwarded_agent_producer: None,
            agent_deployment_ceiling: arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
            event: coland_storage::CanonicalEventRecord {
                event_id: event.event_id.to_string(),
                actor_id: event.actor_id.to_string(),
                realm_id: Some(event.realm_id.to_string()),
                kind: event.kind.as_str().to_owned(),
                schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
                digest_suite: target.digest_suite,
                canonical_digest: event
                    .event_digest_with_digest_suite(target.digest_suite)
                    .map_err(refused)?,
                canonical_bytes: preimage,
                envelope,
                received_at: at,
            },
            parent_membership_admission: None,
            contact_projection: None,
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: Vec::new(),
            idempotency: None,
            deliveries: Vec::new(),
            realm_fanout_source: Some(arkret_wire::EventAdmissionSubmission::new(event)),
        })
        .await
        .map(|_| ())
}

/// One durable sweep; failures preserve exact pending work for the next pass.
pub(crate) async fn sweep_pending_franking(state: &AppState) -> ServiceResult<()> {
    for job in state
        .authority_commits()
        .pending_franking_proofs(&state.service_core_id())
        .await?
    {
        let target = job.target_event_id.clone();
        if let Err(error) = publish_one(state, job).await {
            tracing::warn!(%target, %error, "franking proof publication remains pending");
        }
    }
    Ok(())
}

pub fn spawn_pending_franking_sweeper(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(error) = sweep_pending_franking(&state).await {
                tracing::warn!(%error, "franking proof durable sweep unavailable");
            }
        }
    })
}
