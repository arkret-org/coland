//! Durable original issuer verification, independent of effective roster retention.
use arkret_identity::DidResolver;
use arkret_models_collaboration::events_payloads::call::{
    CallParticipantSigningKey, CallRosterCurrentValue, CallRosterDelta,
};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_signatures::media::VerifiedCallParticipant;
use arkret_wire::{CallId, DidUrl, Event, RealmCommit, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension, RunQueryDsl};

fn unavailable(e: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: original media issuer material: {e}"
    ))
}
#[derive(QueryableByName)]
struct Original {
    #[diesel(sql_type=Text)]
    issuer_kid: String,
    #[diesel(sql_type=Text)]
    public_key_base64url: String,
    #[diesel(sql_type=Nullable<Jsonb>)]
    issuer_history: Option<serde_json::Value>,
}
#[derive(QueryableByName)]
struct History {
    #[diesel(sql_type=Jsonb)]
    evidence: serde_json::Value,
}

fn native_key(
    kid: &DidUrl,
    at: chrono::DateTime<chrono::Utc>,
    history: Option<&AuthenticatedServiceResolution>,
) -> PersistenceResult<arkret_signatures::PublicKeyMaterial> {
    let did = arkret_identity::verification_method_did(kid.as_str()).map_err(unavailable)?;
    let service = arkret_wire::project_did_to_core_id(&did).map_err(unavailable)?;
    let document = if did.method() == "key" {
        arkret_identity::DidKeyResolver::new()
            .resolve_did(&did)
            .map_err(unavailable)?
            .document
    } else {
        arkret_identity::authenticated_service_document_at(
            history.ok_or_else(|| unavailable("native history is unavailable"))?,
            &service,
            at,
        )
        .map_err(unavailable)?
    };
    arkret_identity::validate_verification_method_relationship(
        &document,
        kid,
        &did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(unavailable)?;
    let key =
        arkret_identity::resolve_verification_method_key_from_document(&document, kid.as_str())
            .map_err(unavailable)?;
    key.public_key.ed25519_bytes().map_err(unavailable)?;
    Ok(key.public_key)
}

async fn original(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    call: &CallId,
    commit: &RealmCommit,
    kid: &DidUrl,
    supplied: Option<&VerifiedCallParticipant>,
) -> PersistenceResult<(
    CallParticipantSigningKey,
    Option<AuthenticatedServiceResolution>,
)> {
    let retained=sql_query("SELECT issuer_kid,public_key_base64url,issuer_history FROM call_participant_issuer_sources WHERE realm_id=$1 AND call_id=$2 AND source_commit_id=$3")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str()).bind::<Text,_>(commit.commit_id.as_str())
        .get_result::<Original>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let mut history = supplied.and_then(|v| v.issuer_history()).cloned();
    if let Some(retained) = retained {
        if retained.issuer_kid != kid.as_str() {
            return Err(unavailable("retained issuer differs"));
        }
        let history = retained
            .issuer_history
            .map(serde_json::from_value)
            .transpose()
            .map_err(unavailable)?;
        let key = native_key(kid, commit.committed_at, history.as_ref())?;
        if arkret_canonical::base64url_encode(key.ed25519_bytes().map_err(unavailable)?)
            != retained.public_key_base64url
        {
            return Err(unavailable("retained historical key differs"));
        }
        return Ok((
            CallParticipantSigningKey {
                public_key_base64url: retained.public_key_base64url,
            },
            history,
        ));
    }
    if history.is_none() {
        let did = arkret_identity::verification_method_did(kid.as_str()).map_err(unavailable)?;
        let issuer = arkret_wire::project_did_to_core_id(&did).map_err(unavailable)?;
        let candidates=sql_query("SELECT evidence FROM service_resolution_histories WHERE service_id=$1 ORDER BY verified_at DESC")
            .bind::<Text,_>(issuer.as_str()).load::<History>(&mut *conn).await.map_err(PersistenceError::database)?;
        for candidate in candidates {
            let candidate: AuthenticatedServiceResolution =
                serde_json::from_value(candidate.evidence).map_err(unavailable)?;
            if native_key(kid, commit.committed_at, Some(&candidate)).is_ok() {
                history = Some(candidate);
                break;
            }
        }
    }
    let key = native_key(kid, commit.committed_at, history.as_ref())?;
    Ok((
        CallParticipantSigningKey {
            public_key_base64url: arkret_canonical::base64url_encode(
                key.ed25519_bytes().map_err(unavailable)?,
            ),
        },
        history,
    ))
}

async fn retain(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    call: &CallId,
    commit: &RealmCommit,
    kid: &DidUrl,
    key: &CallParticipantSigningKey,
    history: Option<&AuthenticatedServiceResolution>,
) -> PersistenceResult<()> {
    let history = history
        .map(serde_json::to_value)
        .transpose()
        .map_err(unavailable)?;
    let changed=sql_query("INSERT INTO call_participant_issuer_sources(realm_id,call_id,source_commit_id,issuer_kid,public_key_base64url,issuer_history) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,call_id,source_commit_id) DO UPDATE SET source_commit_id=EXCLUDED.source_commit_id WHERE call_participant_issuer_sources.issuer_kid=EXCLUDED.issuer_kid AND call_participant_issuer_sources.public_key_base64url=EXCLUDED.public_key_base64url")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str()).bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(kid.as_str()).bind::<Text,_>(&key.public_key_base64url).bind::<Nullable<Jsonb>,_>(history)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(unavailable(
            "same original source has a different issuer key",
        ));
    }
    Ok(())
}

pub(crate) async fn for_join(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    call: &CallId,
    kid: &DidUrl,
    verified: Option<&VerifiedCallParticipant>,
) -> PersistenceResult<CallParticipantSigningKey> {
    let (key, history) = original(conn, &event.realm_id, call, commit, kid, verified).await?;
    if let Some(verified) = verified
        && verified
            .signing_key_for(event)
            .map_err(unavailable)?
            .public_key_base64url
            != key.public_key_base64url
    {
        return Err(unavailable(
            "accepted key differs from original native method",
        ));
    }
    let issuer = arkret_wire::project_did_to_core_id(
        &arkret_identity::verification_method_did(kid.as_str()).map_err(unavailable)?,
    )
    .map_err(unavailable)?;
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(&key.public_key_base64url)
            .map_err(unavailable)?,
    };
    VerifiedCallParticipant::verify(event, &issuer, &public)
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("join has no original binding"))?;
    retain(
        conn,
        &event.realm_id,
        call,
        commit,
        kid,
        &key,
        history.as_ref(),
    )
    .await?;
    Ok(key)
}

pub(crate) async fn install_roster(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    call: &CallId,
    roster: &CallRosterCurrentValue,
) -> PersistenceResult<()> {
    arkret_signatures::media::verify_call_roster_bindings(realm, call, roster)
        .map_err(unavailable)?;
    for entry in &roster.entries {
        let CallRosterDelta::Join { participant } = &entry.value else {
            return Err(unavailable("effective entry is not a join"));
        };
        if let Some(binding) = &participant.participant_binding {
            let (key, history) = original(
                conn,
                realm,
                call,
                &entry.source_commit,
                &binding.issuer_kid,
                None,
            )
            .await?;
            if entry
                .participant_signing_key
                .as_ref()
                .map(|key| &key.public_key_base64url)
                != Some(&key.public_key_base64url)
            {
                return Err(unavailable(
                    "Snapshot key differs from independent native method",
                ));
            }
            retain(
                conn,
                realm,
                call,
                &entry.source_commit,
                &binding.issuer_kid,
                &key,
                history.as_ref(),
            )
            .await?;
        }
    }
    Ok(())
}
