//! Accepted organization relationships at the Realm admission cut.
//!
//! The legacy display projection is deliberately absent from this reader.
//! `content-moderation.md` section 7 has no authenticated cross-Realm policy
//! carrier: a live accepted relationship explicitly covering moderation makes
//! a join depend on that unavailable authority, and must therefore refuse it.

use arkret_models_collaboration::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationPayload,
    RealmOrganizationStatus, SignatureMaterial,
};
use coland_storage::{PersistenceError, PersistenceResult, RealmOrganizationProofCommit};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct RelationshipRow {
    #[diesel(sql_type = Text)]
    organization_id: String,
    #[diesel(sql_type = Text)]
    relationship: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Binary)]
    organization_public_key: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
}

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("invalid accepted realm_organization: {detail}"))
}

fn payload(event: &arkret_wire::Event) -> PersistenceResult<RealmOrganizationPayload> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(corrupt)?)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))
}

fn verify_proof(
    value: &RealmOrganizationPayload,
    realm: &arkret_wire::RealmId,
    at: chrono::DateTime<chrono::Utc>,
    public_key: &[u8],
) -> PersistenceResult<()> {
    arkret_policy::verify_realm_organization_statement(
        value,
        realm,
        at,
        &arkret_policy::NoDelegationResolver,
    )
    .map_err(|error| denied(&error.to_string()))?;
    // A single detached Ed25519 signature is not a threshold or delegated
    // governance proof. Those roles need their own verified evidence carrier.
    if value.authorization.issuer_role != RealmOrganizationIssuerRole::Organization
        || value.authorization.issuer_id != value.organization_id
        || value.authorization.signed_at > at
        || value.issued_at > at
    {
        return Err(denied("organization_statement_unverified"));
    }
    let did =
        arkret_identity::verification_method_did(value.authorization.verification_method.as_str())
            .map_err(|_| denied("organization_statement_unverified"))?;
    if arkret_wire::project_did_to_core_id(&did).map_err(corrupt)? != value.organization_id {
        return Err(denied("organization_statement_unverified"));
    }
    let bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| denied("organization_statement_unverified"))?;
    if did.method() == "key" {
        use arkret_identity::DidResolver as _;
        let document = arkret_identity::DidKeyResolver::new()
            .resolve_did_document(&did)
            .map_err(|_| denied("organization_statement_unverified"))?;
        let bound_key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
            &document,
            value.authorization.verification_method.as_str(),
        )
        .map_err(|_| denied("organization_statement_unverified"))?;
        if bytes != bound_key.to_bytes() {
            return Err(denied("organization_statement_unverified"));
        }
    } else if did.method() != "webvh" {
        return Err(denied("organization historical proof is unavailable"));
    }
    let SignatureMaterial::NonEmptyString(proof) = &value.authorization.proof else {
        return Err(denied("organization_statement_unverified"));
    };
    let transcript = arkret_models_collaboration::realm_organization_statement_signing_bytes(value)
        .map_err(corrupt)?;
    arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
        &transcript,
        proof,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: bytes.to_vec(),
        },
    )
    .map_err(|_| denied("organization_statement_unverified"))
}

fn accepted_value(
    row: &RelationshipRow,
    realm: &arkret_wire::RealmId,
    before: i64,
) -> PersistenceResult<RealmOrganizationPayload> {
    let event: arkret_wire::Event =
        serde_json::from_value(row.envelope.clone()).map_err(corrupt)?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json.clone()).map_err(corrupt)?;
    if event.kind != arkret_wire::EventKind::RealmOrganization
        || &event.realm_id != realm
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            })
        || commit.event_ref != event.event_id
        || &commit.realm_id != realm
        || commit.commit_id.as_str() != row.current_commit_id
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            })
        || i64::try_from(commit.stream_position).map_err(corrupt)? != row.current_stream_position
        || row.current_stream_position >= before
        || serde_json::to_value(&event.payload).map_err(corrupt)? != row.value
    {
        return Err(corrupt("covering Event/Commit or source cut mismatch"));
    }
    let value = payload(&event)?;
    if value.organization_id.as_str() != row.organization_id
        || serde_json::to_value(value.relationship)
            .map_err(corrupt)?
            .as_str()
            != Some(row.relationship.as_str())
    {
        return Err(corrupt(
            "current selector does not match the accepted payload",
        ));
    }
    verify_proof(
        &value,
        realm,
        commit.committed_at,
        &row.organization_public_key,
    )?;
    Ok(value)
}

async fn relationships(
    conn: &mut AsyncPgConnection,
    realm: &str,
) -> PersistenceResult<Vec<RelationshipRow>> {
    diesel::sql_query(
        "SELECT r.organization_id,r.relationship,r.value,r.organization_public_key,e.envelope,c.commit_json,r.current_stream_position,r.current_commit_id \
         FROM realm_organization_current_states r \
         LEFT JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.realm_id \
             AND c.stream_position=r.current_stream_position \
         LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE r.realm_id=$1 ORDER BY r.organization_id,r.relationship FOR UPDATE OF r",
    ).bind::<Text,_>(realm).load(conn).await.map_err(PersistenceError::database)
}

pub(crate) async fn accepted_relationships_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<
    Vec<
        arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipView,
    >,
>{
    use arkret_models_collaboration::governance::realm_governance::{
        RealmOrganizationLifecyclePhase, RealmOrganizationRelationshipView,
    };
    let mut result = Vec::new();
    for row in relationships(conn, realm.as_str()).await? {
        let value = accepted_value(&row, realm, i64::MAX)?;
        let lifecycle_phase = if value.is_effective_active(at) {
            RealmOrganizationLifecyclePhase::VerifiedActive
        } else {
            RealmOrganizationLifecyclePhase::RevokedOrExpired
        };
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json).map_err(corrupt)?;
        result.push(RealmOrganizationRelationshipView {
            statement_id: value.statement_id,
            organization_id: value.organization_id,
            relationship: value.relationship,
            status: value.status,
            control_scopes: value.control_scopes,
            issued_at: value.issued_at,
            not_before: value.not_before,
            expires_at: value.expires_at,
            supersedes_statement_id: value.supersedes_statement_id,
            revokes_statement_id: value.revokes_statement_id,
            realm_commit_ref: value.realm_commit_ref,
            issuer_role: value.authorization.issuer_role,
            delegation_ref: value
                .authorization
                .delegation_ref
                .map(|reference| reference.to_string()),
            lifecycle_phase,
            updated_at: Some(commit.committed_at),
        });
    }
    Ok(result)
}

pub(crate) async fn require_organization_join_gate_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let join = match event.kind {
        arkret_wire::EventKind::InviteAccept | arkret_wire::EventKind::RealmInviteLinkAccept => {
            true
        }
        arkret_wire::EventKind::MemberState => {
            serde_json::to_value(&event.payload)
                .map_err(corrupt)?
                .get("membership")
                .and_then(Value::as_str)
                == Some("join")
        }
        _ => false,
    };
    if !join {
        return Ok(());
    }
    require_organization_moderation_authority_in_connection(
        conn,
        &event.realm_id,
        Some(commit.stream_position),
        commit.committed_at,
    )
    .await
}

pub(crate) async fn require_organization_moderation_authority_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    at_position: Option<u64>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
    let before = at_position
        .map(|position| {
            position
                .checked_add(1)
                .ok_or_else(|| corrupt("source cut overflow"))
        })
        .transpose()?
        .map(i64::try_from)
        .transpose()
        .map_err(corrupt)?
        .unwrap_or(i64::MAX);
    for row in relationships(conn, realm.as_str()).await? {
        let value = accepted_value(&row, realm, before)?;
        if value.is_effective_active(at)
            && value
                .control_scopes
                .contains(&RealmOrganizationControlScope::ModerationPolicy)
        {
            return Err(denied(
                "organization moderation policy authority is unavailable",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn commit_realm_organization_current_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    proof: Option<&RealmOrganizationProofCommit>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmOrganization {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
    {
        return Err(denied("organization statement source scope mismatch"));
    }
    let value = payload(event)?;
    let proof = proof.ok_or_else(|| denied("organization_statement_unverified"))?;
    if proof.event_id != event.event_id
        || proof.verification_method != value.authorization.verification_method
        || proof.signed_at != value.authorization.signed_at
    {
        return Err(denied("organization_statement_unverified"));
    }
    verify_proof(
        &value,
        &event.realm_id,
        commit.committed_at,
        &proof.public_key,
    )?;
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    let position = i64::try_from(commit.stream_position).map_err(corrupt)?;
    let relationship = serde_json::to_value(value.relationship).map_err(corrupt)?;
    let relationship = relationship
        .as_str()
        .ok_or_else(|| corrupt("relationship is not a string"))?;
    let previous: Option<RelationshipRow> = diesel::sql_query(
        "SELECT r.organization_id,r.relationship,r.value,r.organization_public_key,e.envelope,c.commit_json,r.current_stream_position,r.current_commit_id \
         FROM realm_organization_current_states r LEFT JOIN realm_commits c ON c.commit_id=r.current_commit_id \
         AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position \
         LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE r.realm_id=$1 AND r.organization_id=$2 AND r.relationship=$3 FOR UPDATE OF r",
    ).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(value.organization_id.as_str())
        .bind::<Text,_>(relationship).get_result(conn).await.optional().map_err(PersistenceError::database)?;
    let previous = previous
        .as_ref()
        .map(|row| accepted_value(row, &event.realm_id, position))
        .transpose()?;
    for reference in value
        .supersedes_statement_id
        .iter()
        .chain(value.revokes_statement_id.iter())
    {
        if previous
            .as_ref()
            .is_none_or(|previous| &previous.statement_id != reference)
        {
            return Err(denied(
                "organization statement reference does not name current accepted relationship",
            ));
        }
    }
    if value.status == RealmOrganizationStatus::Revoked && previous.is_none() {
        return Err(denied(
            "organization revocation has no accepted relationship",
        ));
    }
    if let Some(reference) = &value.realm_commit_ref {
        #[derive(diesel::QueryableByName)]
        struct Covered {
            #[diesel(sql_type=BigInt)]
            stream_position: i64,
        }
        let covered = diesel::sql_query("SELECT stream_position FROM realm_commits WHERE realm_id=$1 \
            AND commit_id=$2 AND stream_ref->>'kind'='realm' AND stream_ref->>'realm_id'=$1 AND stream_position<$3")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(reference.as_str()).bind::<BigInt,_>(position)
            .get_result::<Covered>(conn).await.optional().map_err(PersistenceError::database)?;
        if covered.is_none_or(|covered| covered.stream_position >= position) {
            return Err(denied(
                "organization statement realm_commit_ref is not accepted on this source cut",
            ));
        }
    }
    let serialized = serde_json::to_value(value).map_err(corrupt)?;
    diesel::sql_query("INSERT INTO realm_organization_current_states \
        (realm_id,organization_id,relationship,value,current_commit_id,current_stream_position,organization_public_key,updated_at) \
        VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(realm_id,organization_id,relationship) DO UPDATE SET \
        value=EXCLUDED.value,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position, \
        organization_public_key=EXCLUDED.organization_public_key,updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(serialized["organization_id"].as_str().unwrap())
        .bind::<Text,_>(relationship).bind::<Jsonb,_>(&serialized).bind::<Text,_>(commit.commit_id.as_str())
        .bind::<BigInt,_>(position).bind::<Binary,_>(proof.public_key.as_slice()).bind::<Timestamptz,_>(commit.committed_at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
