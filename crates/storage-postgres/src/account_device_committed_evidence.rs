//! Original native Account Device roots, frozen with their acceptance Commit.
use arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact;
use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestationCore, DeviceStatus,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{DidCoreId, DidKey, Event, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

fn rejected(message: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: original native Account Device evidence: {message}"
    ))
}
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct Archived {
    #[diesel(sql_type=Text)]
    evidence_ref: String,
    #[diesel(sql_type=Text)]
    authorization_commit_id: String,
    #[diesel(sql_type=Jsonb)]
    evidence_json: Value,
    #[diesel(sql_type=Jsonb)]
    producer_source_fact: Value,
}

pub(crate) async fn prepare_core(
    conn: &mut AsyncPgConnection,
    event: &Event,
    fact: &HumanHistoricalSignerFact,
    at: chrono::DateTime<chrono::Utc>,
    station: &DidCoreId,
) -> PersistenceResult<DeviceProjectionAttestationCore> {
    let producer = event
        .human_device_producer()
        .map_err(rejected)?
        .ok_or_else(|| rejected("not an Account Device producer"))?;
    if &producer.account_id.station_id != station {
        return Err(rejected(
            "foreign Account requires its own native regular evidence; this Station cannot issue it",
        ));
    }
    // prepare_local_human_source already re-proved this exact authorization
    // under its PCR lock; fetch its immutable payload on the same connection.
    let row = sql_query("SELECT e.envelope->'payload' AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND c.commit_id=$2 AND e.state='committed' AND e.kind='ak.device.authorize'")
        .bind::<Text,_>(fact.key.authorization_ref.event_id.as_str()).bind::<Text,_>(fact.key.authorization_ref.commit_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let payload: DeviceAuthorizePayload = serde_json::from_value(row.value).map_err(rejected)?;
    if payload.device_id != producer.device_id {
        return Err(rejected("source authorization addresses another Device"));
    }
    Ok(DeviceProjectionAttestationCore {
        account_id: producer.account_id,
        device_id: producer.device_id,
        device_signing_key_did: DidKey::new(payload.device_public_key_did.as_str())
            .map_err(rejected)?,
        hpke_key: payload.hpke_key,
        device_authorize_event_id: fact.key.authorization_ref.event_id.clone(),
        authorized_generation_ref: payload.authorized_generation_ref,
        device_status: DeviceStatus::Active,
        authorization_window: DeviceAuthorizationWindow {
            not_before: payload.not_before,
            expires_at: payload.expires_at.flatten(),
        },
        attested_at: at,
        expires_at: (at + chrono::Duration::minutes(5)).min(
            payload
                .expires_at
                .flatten()
                .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        ),
    })
}

pub(crate) fn validate(
    event: &Event,
    commit: &RealmCommit,
    fact: Option<&HumanHistoricalSignerFact>,
    evidence: Option<&AccountDeviceSignerEvidence>,
) -> PersistenceResult<()> {
    let producer = event.human_device_producer().map_err(rejected)?;
    let (Some(producer), Some(fact), Some(evidence)) = (producer, fact, evidence) else {
        if event.human_device_producer().map_err(rejected)?.is_none()
            && fact.is_none()
            && evidence.is_none()
        {
            return Ok(());
        }
        return Err(rejected("missing or surplus original regular root"));
    };
    crate::agent_producer_signer_keys::validate_human_fact_binding(event, commit, Some(fact))?;
    arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(evidence, &producer.account_id, &producer.device_id).map_err(rejected)?;
    let core = &evidence.device_projection_attestation.attestation;
    let key = core
        .device_signing_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| rejected("Device key is not did:key"))?;
    let key = arkret_canonical::decode_ed25519_multibase(key).map_err(rejected)?;
    if core.device_authorize_event_id != fact.key.authorization_ref.event_id
        || arkret_canonical::base64url_encode(key) != fact.key.public_key_b64u.as_str()
        || !core.device_status.is_active()
        || core.attested_at > commit.committed_at
        || commit.committed_at >= core.expires_at
        || [
            event.created_at,
            event
                .producer_proof
                .as_ref()
                .ok_or_else(|| rejected("producer proof absent"))?
                .created_at,
            commit.committed_at,
        ]
        .into_iter()
        .any(|instant| {
            instant < core.authorization_window.not_before
                || core
                    .authorization_window
                    .expires_at
                    .is_some_and(|end| instant >= end)
        })
    {
        return Err(rejected(
            "regular root does not cover the original Commit and signer source",
        ));
    }
    Ok(())
}

pub(crate) async fn retain(
    conn: &mut AsyncPgConnection,
    commit: &RealmCommit,
    fact: &HumanHistoricalSignerFact,
    evidence: &AccountDeviceSignerEvidence,
) -> PersistenceResult<()> {
    let core = &evidence.device_projection_attestation.attestation;
    let source = sql_query("SELECT e.envelope->'payload' AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND c.commit_id=$2 AND e.kind='ak.device.authorize' AND e.state='committed'")
        .bind::<Text,_>(fact.key.authorization_ref.event_id.as_str()).bind::<Text,_>(fact.key.authorization_ref.commit_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let source: DeviceAuthorizePayload = serde_json::from_value(source.value).map_err(rejected)?;
    if source.device_id != core.device_id
        || source.device_public_key_did.as_str() != core.device_signing_key_did.as_str()
        || source.hpke_key != core.hpke_key
        || source.authorized_generation_ref != core.authorized_generation_ref
        || source.not_before != core.authorization_window.not_before
        || source.expires_at.flatten() != core.authorization_window.expires_at
    {
        return Err(rejected(
            "original root differs from accepted Device authorization",
        ));
    }
    let reference = evidence.signer_evidence_ref().map_err(rejected)?;
    let body = serde_json::to_value(evidence).map_err(rejected)?;
    sql_query("INSERT INTO account_device_signer_evidence(evidence_ref,principal_id,station_id,device_id,authorization_event_id,authorization_commit_id,attested_at,evidence_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(evidence_ref) DO NOTHING")
        .bind::<Text,_>(reference.as_ref()).bind::<Text,_>(core.account_id.principal_id.as_str()).bind::<Text,_>(core.account_id.station_id.as_str()).bind::<Text,_>(core.device_id.as_str()).bind::<Text,_>(core.device_authorize_event_id.as_str()).bind::<Text,_>(fact.key.authorization_ref.commit_id.as_str()).bind::<Timestamptz,_>(core.attested_at).bind::<Jsonb,_>(&body).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let stored = sql_query("SELECT evidence_json AS value FROM account_device_signer_evidence WHERE evidence_ref=$1 AND authorization_commit_id=$2")
        .bind::<Text,_>(reference.as_ref()).bind::<Text,_>(fact.key.authorization_ref.commit_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if stored.value != body {
        return Err(rejected(
            "immutable root conflicts with its content address",
        ));
    }
    sql_query(
        "INSERT INTO account_device_committed_evidence(commit_id,evidence_ref) VALUES($1,$2)",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(reference.as_ref())
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn read(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<Option<AccountDeviceSignerEvidence>> {
    let row = sql_query("SELECT e.evidence_ref,e.authorization_commit_id,e.evidence_json,k.producer_source_fact FROM account_device_committed_evidence a JOIN account_device_signer_evidence e ON e.evidence_ref=a.evidence_ref JOIN agent_producer_signer_keys k ON k.commit_id=a.commit_id WHERE a.commit_id=$1")
        .bind::<Text,_>(commit.commit_id.as_str()).get_result::<Archived>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    match row {
        Some(row) => {
            let evidence: AccountDeviceSignerEvidence =
                serde_json::from_value(row.evidence_json).map_err(rejected)?;
            let fact: HumanHistoricalSignerFact =
                serde_json::from_value(row.producer_source_fact).map_err(rejected)?;
            if evidence.signer_evidence_ref().map_err(rejected)?.as_ref() != row.evidence_ref
                || fact.key.authorization_ref.commit_id.as_str() != row.authorization_commit_id
            {
                return Err(rejected(
                    "immutable root or original authorization address differs",
                ));
            }
            validate(event, commit, Some(&fact), Some(&evidence))?;
            Ok(Some(evidence))
        }
        None => {
            validate(event, commit, None, None)?;
            Ok(None)
        }
    }
}

pub(crate) async fn retain_from_guard(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    fact: &HumanHistoricalSignerFact,
    guard: Option<&coland_storage::SelfProducerCommitGuard>,
) -> PersistenceResult<()> {
    if let Some(coland_storage::SelfProducerCommitGuard::HumanDeviceEvidence {
        selector,
        evidence,
    }) = guard
    {
        if selector.authorization_ref != fact.key.authorization_ref {
            return Err(rejected("root admission guard source differs"));
        }
        validate(event, commit, Some(fact), Some(evidence))?;
        retain(conn, commit, fact, evidence).await?;
    }
    Ok(())
}
