//! Station acceptance evidence signed under the current governing Realm lock.
use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInviteAcceptanceAttestation, ThirdPartyInviteAcceptanceAttestationOutcome,
    ThirdPartyInviteAcceptanceAttestationRequestBody, ThirdPartyInviteAttestedState,
};
use arkret_wire::{CommitStreamRef, CommittedEventRef, DidCoreId, DidUrl, PayloadProof};
use diesel::sql_types::Bool;

use super::*;

#[derive(diesel::QueryableByName)]
struct Accepted {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

#[derive(diesel::QueryableByName)]
struct Present {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(diesel::QueryableByName)]
struct Current {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn hidden() -> PersistenceError {
    PersistenceError::NotFound("third-party invite unavailable".into())
}

fn unavailable() -> PersistenceError {
    PersistenceError::Conflict(
        "revision_unavailable: accepted invite checkpoint unavailable".into(),
    )
}

pub(super) struct PendingInviteEvidence {
    event: arkret_wire::Event,
    commit: arkret_wire::RealmCommit,
    source: CommitStreamRef,
    pub(super) material: InviteThirdPartyCreatePayload,
    pub(super) observed_at: chrono::DateTime<chrono::Utc>,
}

pub(super) async fn pending_invite_evidence(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    invite_id: &InviteId,
    caller: &AccountId,
    station: &DidCoreId,
    verification_id: &DidCoreId,
    observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
) -> PersistenceResult<PendingInviteEvidence> {
    let accepted = diesel::sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.envelope->>'event_id'=$1 AND e.realm_id=$2 AND e.kind='ak.invite.third_party' \
         AND e.state='committed' AND e.envelope->'actor_id'=$3",
    )
    .bind::<Text, _>(invite_id.event_id().as_str())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(ActorId::account(caller.clone())).map_err(corrupt)?)
    .get_result::<Accepted>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(hidden)?;
    lock_realm_authorization_cut(conn, realm_id).await?;
    // Observe time at the serialized cut, after any competing writer or lock
    // wait. Request-arrival time can outlive the creator's current permission.
    let at = observe();
    // A cached replica cannot issue portable acceptance evidence. The exact
    // current governor must hold this lock through the signing callback.
    if !diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_authorities WHERE realm_id=$1 AND service_id=$2) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(station.as_str())
    .get_result::<Present>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present
    {
        return Err(unavailable());
    }
    let complete = diesel::sql_query(
        "WITH nodes AS (SELECT c.*,e.state,e.kind AS event_kind,e.realm_id AS event_realm,e.envelope, \
         ROW_NUMBER() OVER (ORDER BY c.stream_position)-1 AS expected_position, \
         LAG(c.commit_id) OVER (ORDER BY c.stream_position) AS predecessor \
         FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 \
         AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1)) \
         SELECT COALESCE(BOOL_AND(COALESCE(stream_position=expected_position \
         AND previous_commit_ref IS NOT DISTINCT FROM predecessor AND state='committed' \
         AND event_realm=$1 AND envelope->>'kind'=event_kind \
         AND commit_json->>'commit_id'=commit_id AND commit_json->>'realm_id'=$1 \
         AND commit_json->'stream_ref'=stream_ref \
         AND commit_json->>'stream_position'=stream_position::text \
         AND commit_json->>'previous_commit_ref' IS NOT DISTINCT FROM previous_commit_ref \
         AND commit_json->>'event_ref'=envelope->>'event_id' \
         AND ((stream_position=0 AND event_kind='ak.realm.create' AND NOT (envelope ? 'realm_id') \
               AND envelope->'scope_ref'=jsonb_build_object('kind','realm_genesis')) \
              OR (stream_position>0 AND envelope->>'realm_id'=$1 \
                  AND envelope->'scope_ref'=stream_ref)),false)) \
         AND BOOL_OR(stream_position=0),false) AS present FROM nodes",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<Present>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    if !complete {
        return Err(unavailable());
    }
    let event: arkret_wire::Event = serde_json::from_value(accepted.envelope).map_err(corrupt)?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(accepted.commit_json).map_err(corrupt)?;
    let source = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    if event.actor_id.as_account_id() != Some(caller)
        || event.realm_id != *realm_id
        || InviteId::from_event_id(&event.event_id) != *invite_id
        || commit.realm_id != *realm_id
        || commit.event_ref != event.event_id
        || commit.stream_ref != source
    {
        return Err(unavailable());
    }
    let material: InviteThirdPartyCreatePayload = typed_payload(&event)?;
    material.validate().map_err(corrupt)?;
    if material.third_party_invite.verification_id != *verification_id || material.expires_at <= at
    {
        return Err(hidden());
    }
    let lifecycle = diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value FROM invite_lifecycle_current_results \
         WHERE realm_id=$1 AND invite_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(invite_id.as_str())
    .get_result::<Current>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(unavailable)?;
    if lifecycle.value.as_str() != Some("pending") {
        return Err(hidden());
    }
    if lifecycle.current_commit_id != commit.commit_id.as_str()
        || lifecycle.current_stream_position != commit.stream_position as i64
        || diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
             WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) \
             AND e.state='committed' AND e.kind IN ('ak.invite.claim','ak.invite.accept','ak.invite.cancel','ak.invite.revoke') \
             AND e.envelope->'payload'->>'invite_id'=$2) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(invite_id.as_str())
        .get_result::<Present>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present
    {
        return Err(unavailable());
    }
    let latest = diesel::sql_query(
        "SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) \
         AND e.state='committed' AND e.kind='ak.realm.policy_bundle' ORDER BY c.stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<Accepted>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(unavailable)?;
    let policy_event: arkret_wire::Event =
        serde_json::from_value(latest.envelope).map_err(corrupt)?;
    let policy_commit: arkret_wire::RealmCommit =
        serde_json::from_value(latest.commit_json).map_err(corrupt)?;
    let current = diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value FROM realm_policy_bundle_current_results \
         WHERE realm_id=$1 FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<Current>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(unavailable)?;
    if current.current_commit_id != policy_commit.commit_id.as_str()
        || current.current_stream_position != policy_commit.stream_position as i64
        || current.value != serde_json::to_value(&policy_event.payload).map_err(corrupt)?
    {
        return Err(unavailable());
    }
    let policy: RealmPolicyBundlePayload =
        serde_json::from_value(current.value).map_err(corrupt)?;
    policy.validate().map_err(corrupt)?;
    if !policy
        .allowed_third_party_invite_verification_ids
        .as_ref()
        .is_some_and(|allowed| allowed.contains(verification_id))
    {
        return Err(hidden());
    }
    RealmAuthorizationCut::read(conn, realm_id, &event.actor_id)
        .await?
        .require_live_invite_creator(&event, at)
        .map_err(|_| hidden())?;
    Ok(PendingInviteEvidence {
        event,
        commit,
        source,
        material,
        observed_at: at,
    })
}

pub(super) async fn issue(
    conn: &mut AsyncPgConnection,
    request: &ThirdPartyInviteAcceptanceAttestationRequestBody,
    caller: &AccountId,
    station: &DidCoreId,
    verification_method: &DidUrl,
    observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
    sign: &coland_storage::InviteAcceptanceAttestationSigner<'_>,
) -> PersistenceResult<ThirdPartyInviteAcceptanceAttestationOutcome> {
    let PendingInviteEvidence {
        event,
        commit,
        source,
        material,
        observed_at: at,
    } = pending_invite_evidence(
        conn,
        &request.realm_id,
        &request.invite_id,
        caller,
        station,
        &request.verification_id,
        observe,
    )
    .await?;
    let mut attestation = ThirdPartyInviteAcceptanceAttestation {
        station_id: station.clone(),
        verification_id: request.verification_id.clone(),
        realm_id: request.realm_id.clone(),
        invite_id: request.invite_id.clone(),
        inviter_account_id: caller.clone(),
        provisioning_id: request.provisioning_id.clone(),
        third_party_invite: material.third_party_invite,
        invite_expires_at: material.expires_at,
        invite_state: ThirdPartyInviteAttestedState::Pending,
        accepted_commit_ref: CommittedEventRef {
            event_id: event.event_id,
            commit_id: commit.commit_id,
            stream_ref: source,
            stream_position: commit.stream_position,
        },
        observed_at: at,
        expires_at: material.expires_at.min(at + chrono::TimeDelta::seconds(60)),
        signature: PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.into(),
            verification_method: verification_method.clone(),
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .map_err(corrupt)?,
            created_at: at,
            domain: None,
            audience: Some(arkret_wire::Audience::Single(
                request.verification_id.to_string(),
            )),
            proof_purpose: None,
            jws: String::new(),
        },
    };
    // The signature is produced before this transaction releases the lock.
    attestation.signature = sign(&attestation)?;
    let outcome = ThirdPartyInviteAcceptanceAttestationOutcome {
        acceptance_attestation: attestation,
    };
    outcome.validate_for_request(request).map_err(corrupt)?;
    Ok(outcome)
}
