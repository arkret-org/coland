pub(crate) mod completion;

use arkret_identifiers::{DidCoreId, EventId, Hash};
use arkret_wire::ActorId;
use diesel::sql_types::Binary;

use super::{
    Array, AsyncPgConnection, ContactRecord, ContactStore, ContactVerifiedMirrorRecord,
    ContactVerifiedMirrorStore, InviteReceivePolicyStore, Jsonb, MimiConsentCorrelationRecord,
    MimiConsentCorrelationStore, Nullable, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz, Value, async_trait, ids, pg_conn,
    sql_query,
};
/// Encode a contact's Event reference for storage.
///
/// The `contacts` Event-reference columns hold the same 33-octet token
/// `canonical_events.id` does, so a malformed wire id is rejected at the
/// storage boundary rather than stored and discovered on read.
fn parse_contact_event_ref(event_ref: Option<&EventId>) -> PersistenceResult<Option<Vec<u8>>> {
    event_ref
        .map(|value| {
            ids::event_token_part_or_schema_violation(value.as_str(), "event")
                .map(|token| token.to_vec())
        })
        .transpose()
}

fn format_contact_event_ref(token: &[u8]) -> PersistenceResult<EventId> {
    let value = ids::format_event_id(
        &<[u8; ids::EVENT_ID_BYTES]>::try_from(token)
            .expect("contacts Event reference is a 33-octet Event id"),
    );
    EventId::new(value).map_err(|_| {
        PersistenceError::SchemaViolation(
            "stored Contact Event reference is not a canonical EventId".to_owned(),
        )
    })
}
// ── Pg-backed contact projection store ───────────────────────────────────
// Durable backing for the holder↔peer `ContactStore`. Mirrors the
// `MemoryContactStore` query shape onto the `contacts` table. Column order
// matches `state::ContactRecord`.
pub struct PgContactStore {
    pub pool: PgPool,
}

pub struct PgContactVerifiedMirrorStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct ContactVerifiedMirrorRow {
    #[diesel(sql_type = Text)]
    target_holder_principal_id: String,
    #[diesel(sql_type = Text)]
    request_event_id: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_event_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    source_receipt: Value,
    #[diesel(sql_type = Text)]
    issuer_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Timestamptz)]
    verified_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<ContactVerifiedMirrorRow> for ContactVerifiedMirrorRecord {
    type Error = PersistenceError;

    fn try_from(row: ContactVerifiedMirrorRow) -> Result<Self, Self::Error> {
        Ok(Self {
            target_holder_principal_id: row.target_holder_principal_id,
            request_event_id: row.request_event_id,
            request_digest: row.request_digest,
            canonical_event_bytes: row.canonical_event_bytes,
            source_receipt: serde_json::from_value(row.source_receipt).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored Contact request receipt is invalid: {error}"
                ))
            })?,
            issuer_id: row.issuer_id.into_string(),
            verified_at: row.verified_at,
        })
    }
}

const CONTACT_VERIFIED_MIRROR_COLUMNS: &str = "target_holder_principal_id, request_event_id, request_digest, canonical_event_bytes, source_receipt, issuer_id, verified_at";

#[async_trait]
impl ContactVerifiedMirrorStore for PgContactVerifiedMirrorStore {
    async fn get(
        &self,
        target_holder_principal_id: &str,
        request_event_id: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONTACT_VERIFIED_MIRROR_COLUMNS} FROM contact_verified_mirrors WHERE target_holder_principal_id = $1 AND request_event_id = $2"
        ))
        .bind::<Text, _>(target_holder_principal_id)
        .bind::<Text, _>(request_event_id)
        .get_result::<ContactVerifiedMirrorRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn put_verified(&self, record: &ContactVerifiedMirrorRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let source_receipt = serde_json::to_value(&record.source_receipt).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "Contact request receipt encode failed: {error}"
            ))
        })?;
        let row = sql_query(format!(
            "INSERT INTO contact_verified_mirrors ({CONTACT_VERIFIED_MIRROR_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (target_holder_principal_id, request_event_id) DO UPDATE SET verified_at = contact_verified_mirrors.verified_at \
             WHERE contact_verified_mirrors.request_digest = EXCLUDED.request_digest \
               AND contact_verified_mirrors.canonical_event_bytes = EXCLUDED.canonical_event_bytes \
               AND contact_verified_mirrors.source_receipt = EXCLUDED.source_receipt \
               AND contact_verified_mirrors.issuer_id = EXCLUDED.issuer_id \
             RETURNING {CONTACT_VERIFIED_MIRROR_COLUMNS}"
        ))
        .bind::<Text, _>(&record.target_holder_principal_id)
        .bind::<Text, _>(&record.request_event_id)
        .bind::<Text, _>(&record.request_digest)
        .bind::<Binary, _>(&record.canonical_event_bytes)
        .bind::<Jsonb, _>(&source_receipt)
        .bind::<Text, _>(&record.issuer_id)
        .bind::<Timestamptz, _>(record.verified_at)
        .get_result::<ContactVerifiedMirrorRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if row.is_none() {
            return Err(PersistenceError::Internal(
                "cas_conflict: Contact verified mirror binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}
#[derive(QueryableByName)]
struct ContactRow {
    #[diesel(sql_type = Text)]
    requester_id: String,
    #[diesel(sql_type = Text)]
    target_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    contact_round_id: Option<Hash>,
    #[diesel(sql_type = Array<Text>)]
    granted_to_target_scopes: Vec<String>,
    #[diesel(sql_type = Array<Text>)]
    granted_to_requester_scopes: Vec<String>,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pending_incoming_admitted: bool,
    #[diesel(sql_type = Nullable<Binary>)]
    request_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Jsonb)]
    request_slot_states: Value,
    #[diesel(sql_type = Jsonb)]
    request_receipts: Value,
    #[diesel(sql_type = Jsonb)]
    request_mirror_receipts: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    contact_round_evidence: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    current_state: Value,
    #[diesel(sql_type = Nullable<Binary>)]
    response_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Binary>)]
    tombstone_event_ref: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    message: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    peer_host_id: Option<DidCoreId>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    peer_service_resolution: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
fn decode_contact_json<T: serde::de::DeserializeOwned>(
    value: Value,
    field: &str,
) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(|error| {
        PersistenceError::Internal(format!("invalid contacts.{field} JSONB: {error}"))
    })
}

fn encode_contact_json<T: serde::Serialize + ?Sized>(
    value: &T,
    field: &str,
) -> PersistenceResult<Value> {
    serde_json::to_value(value).map_err(|error| {
        PersistenceError::Internal(format!("cannot encode contacts.{field} JSONB: {error}"))
    })
}

fn contact_record_from_row(row: ContactRow) -> PersistenceResult<ContactRecord> {
    Ok(ContactRecord {
        requester_id: serde_json::from_str(&row.requester_id).map_err(|error| {
            PersistenceError::Internal(format!("invalid contacts.requester_id ActorId: {error}"))
        })?,
        target_id: serde_json::from_str(&row.target_id).map_err(|error| {
            PersistenceError::Internal(format!("invalid contacts.target_id ActorId: {error}"))
        })?,
        contact_round_id: row.contact_round_id,
        granted_to_target_scopes: row.granted_to_target_scopes,
        granted_to_requester_scopes: row.granted_to_requester_scopes,
        status: row.status,
        pending_incoming_admitted: row.pending_incoming_admitted,
        request_event_ref: row
            .request_event_ref
            .as_deref()
            .map(format_contact_event_ref)
            .transpose()?,
        request_slot_states: decode_contact_json(row.request_slot_states, "request_slot_states")?,
        request_receipts: decode_contact_json(row.request_receipts, "request_receipts")?,
        request_mirror_receipts: decode_contact_json(
            row.request_mirror_receipts,
            "request_mirror_receipts",
        )?,
        contact_round_evidence: row
            .contact_round_evidence
            .map(|value| decode_contact_json(value, "contact_round_evidence"))
            .transpose()?,
        current_state: decode_contact_json(row.current_state, "current_state")?,
        response_event_ref: row
            .response_event_ref
            .as_deref()
            .map(format_contact_event_ref)
            .transpose()?,
        tombstone_event_ref: row
            .tombstone_event_ref
            .as_deref()
            .map(format_contact_event_ref)
            .transpose()?,
        message: row.message,
        peer_host_id: row.peer_host_id,
        peer_service_resolution: row.peer_service_resolution,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}
/// Parse large closed Contact evidence away from nested async poll frames.
/// The transaction keeps its connection and locks while awaiting this pure work.
async fn decode_contact_rows(rows: Vec<ContactRow>) -> PersistenceResult<Vec<ContactRecord>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    tokio::task::spawn_blocking(move || rows.into_iter().map(contact_record_from_row).collect())
        .await
        .map_err(|error| PersistenceError::Internal(format!("Contact row decode task: {error}")))?
}

const CONTACT_COLUMNS: &str = "requester_id, target_id, contact_round_id, granted_to_target_scopes, granted_to_requester_scopes, status, pending_incoming_admitted, request_event_ref, request_slot_states, request_receipts, request_mirror_receipts, contact_round_evidence, current_state, response_event_ref, tombstone_event_ref, message, peer_id AS peer_host_id, peer_service_resolution, created_at, updated_at";
/// Both directional Contact rows of an exact pair, share-locked so a
/// concurrent Contact change cannot commit inside the reading transaction.
pub(crate) async fn pair_contacts_in_connection(
    conn: &mut AsyncPgConnection,
    left: &ActorId,
    right: &ActorId,
) -> PersistenceResult<Vec<ContactRecord>> {
    let rows = sql_query(format!(
        "SELECT {CONTACT_COLUMNS} FROM contacts \
         WHERE (requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1) \
         ORDER BY updated_at ASC, requester_id ASC FOR SHARE"
    ))
    .bind::<Text, _>(left.to_string())
    .bind::<Text, _>(right.to_string())
    .load::<ContactRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    decode_contact_rows(rows).await
}

/// Read the pair at a repeatable-read Snapshot cut without row locks.
/// Signal eligibility uses this inside a READ ONLY transaction; admission
/// continues to use `pair_contacts_in_connection` and its share locks.
pub(crate) async fn pair_contacts_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    left: &ActorId,
    right: &ActorId,
) -> PersistenceResult<Vec<ContactRecord>> {
    let rows = sql_query(format!(
        "SELECT {CONTACT_COLUMNS} FROM contacts \
         WHERE (requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1) \
         ORDER BY updated_at ASC, requester_id ASC"
    ))
    .bind::<Text, _>(left.to_string())
    .bind::<Text, _>(right.to_string())
    .load::<ContactRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    decode_contact_rows(rows).await
}

/// The one Contact row of a pair, in either orientation, locked for update.
pub(crate) async fn lock_pair_contact_in_connection(
    conn: &mut AsyncPgConnection,
    left: &ActorId,
    right: &ActorId,
) -> PersistenceResult<Option<ContactRecord>> {
    let rows = sql_query(format!(
        "SELECT {CONTACT_COLUMNS} FROM contacts \
         WHERE (requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1) \
         FOR UPDATE"
    ))
    .bind::<Text, _>(left.to_string())
    .bind::<Text, _>(right.to_string())
    .get_result::<ContactRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    decode_contact_rows(rows.into_iter().collect())
        .await
        .map(|mut rows| rows.pop())
}

/// The exact Contact row of a pair at revision `updated_at`, locked for the
/// accepting transaction. `None` when no row of the pair has that revision.
pub(crate) async fn lock_pair_contact_at_in_connection(
    conn: &mut AsyncPgConnection,
    left: &ActorId,
    right: &ActorId,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<ContactRecord>> {
    let rows = sql_query(format!(
        "SELECT {CONTACT_COLUMNS} FROM contacts \
         WHERE ((requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1)) \
           AND updated_at = $3 \
         FOR UPDATE"
    ))
    .bind::<Text, _>(left.to_string())
    .bind::<Text, _>(right.to_string())
    .bind::<diesel::sql_types::Timestamptz, _>(updated_at)
    .get_result::<ContactRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    decode_contact_rows(rows.into_iter().collect())
        .await
        .map(|mut rows| rows.pop())
}

pub(crate) async fn put_if_updated_at_in_connection(
    conn: &mut AsyncPgConnection,
    expected_updated_at: chrono::DateTime<chrono::Utc>,
    record: &ContactRecord,
) -> PersistenceResult<bool> {
    if record.updated_at <= expected_updated_at {
        return Ok(false);
    }
    let request_slot_states =
        encode_contact_json(&record.request_slot_states, "request_slot_states")?;
    let request_receipts = encode_contact_json(&record.request_receipts, "request_receipts")?;
    let request_mirror_receipts =
        encode_contact_json(&record.request_mirror_receipts, "request_mirror_receipts")?;
    let contact_round_evidence = record
        .contact_round_evidence
        .as_ref()
        .map(|value| encode_contact_json(value, "contact_round_evidence"))
        .transpose()?;
    let current_state = encode_contact_json(&record.current_state, "current_state")?;

    let affected = sql_query(
            "UPDATE contacts SET requester_id = $1, target_id = $2, \
                contact_round_id = $3, granted_to_target_scopes = $4, \
                granted_to_requester_scopes = $5, status = $6, pending_incoming_admitted = $7, request_event_ref = $8, \
                request_slot_states = $9, request_receipts = $10, request_mirror_receipts = $11, \
                contact_round_evidence = $12, current_state = $13, \
                response_event_ref = $14, tombstone_event_ref = $15, \
                message = $16, peer_id = $17, peer_service_resolution = $18, updated_at = $19 \
             WHERE ((requester_id = $1 AND target_id = $2) OR \
                    (requester_id = $2 AND target_id = $1)) AND updated_at = $20",
        )
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<diesel::sql_types::Bool, _>(record.pending_incoming_admitted)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(record.request_event_ref.as_ref())?)
        .bind::<Jsonb, _>(&request_slot_states)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&current_state)

        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(record.response_event_ref.as_ref())?)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.tombstone_event_ref.as_ref(),
        )?)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_host_id.as_ref())
        .bind::<Nullable<Jsonb>, _>(record.peer_service_resolution.as_ref())
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(expected_updated_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(affected == 1)
}

#[async_trait]
impl ContactStore for PgContactStore {
    async fn scope_intervals(
        &self,
        domain: &arkret_wire::TrustDomainId,
        holder: &arkret_models_collaboration::contact_operations::ContactPeer,
        peer: &arkret_models_collaboration::contact_operations::ContactPeer,
        grants: &[arkret_wire::EventId],
    ) -> PersistenceResult<
        Vec<arkret_models_collaboration::contact_operations::ContactHistoricalScopeInterval>,
    > {
        if grants.len() > 5 {
            return Err(PersistenceError::SchemaViolation(
                "Contact historical request exceeds five grants".into(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        let rows=sql_query("SELECT CASE WHEN closed_by IS NULL THEN interval_json ELSE interval_json || jsonb_build_object('closed_by',closed_by) END AS material FROM contact_scope_intervals WHERE trust_domain_id=$1 AND holder=$2 AND peer=$3 AND grant_event_ref=ANY($4) ORDER BY grant_event_ref,contact_scope LIMIT 6")
            .bind::<Text,_>(domain.as_str()).bind::<Jsonb,_>(serde_json::to_value(holder).map_err(|e|PersistenceError::SchemaViolation(e.to_string()))?).bind::<Jsonb,_>(serde_json::to_value(peer).map_err(|e|PersistenceError::SchemaViolation(e.to_string()))?).bind::<Array<Text>,_>(grants.iter().map(ToString::to_string).collect::<Vec<_>>()).get_results::<ContactIndexedMaterial>(&mut conn).await.map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|r| decode_contact_json(r.material, "scope interval"))
            .collect()
    }
    async fn known_round_closure(
        &self,
        domain: &arkret_wire::TrustDomainId,
        holder: &arkret_models_collaboration::contact_operations::ContactPeer,
        peer: &arkret_models_collaboration::contact_operations::ContactPeer,
        round: &arkret_wire::Hash,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::contact_operations::ContactRoundClosure>,
    > {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT material FROM contact_round_closures WHERE trust_domain_id=$1 AND ((holder=$2 AND peer=$3) OR (holder=$3 AND peer=$2)) AND contact_round_id=$4 ORDER BY holder LIMIT 1")
            .bind::<Text,_>(domain.as_str()).bind::<Jsonb,_>(serde_json::to_value(holder).map_err(|e|PersistenceError::SchemaViolation(e.to_string()))?).bind::<Jsonb,_>(serde_json::to_value(peer).map_err(|e|PersistenceError::SchemaViolation(e.to_string()))?).bind::<Text,_>(round.as_str()).get_result::<ContactIndexedMaterial>(&mut conn).await.optional().map_err(PersistenceError::database)?.map(|r|decode_contact_json(r.material,"round closure")).transpose()
    }
    async fn completion_for_request(
        &self,
        actor: &ActorId,
        key: &str,
        request_hash: &str,
    ) -> PersistenceResult<Option<coland_storage::ContactCompletionState>> {
        completion::lookup(&self.pool, actor, key, request_hash).await
    }
    async fn committed_completion_intents(
        &self,
        limit: u16,
        after: Option<&arkret_wire::Hash>,
    ) -> PersistenceResult<Vec<coland_storage::CommittedContactCompletionIntent>> {
        completion::confirmed(&self.pool, limit, after).await
    }
    async fn finalize_completion_intent(
        &self,
        ready: &coland_storage::CommittedContactCompletionIntent,
        result: &coland_storage::ContactCompletionResult,
        record: Option<&coland_storage::FederationOutboxRecord>,
        counterpart_proof: Option<
            &arkret_models_collaboration::contact_operations::ContactCurrentProof,
        >,
    ) -> PersistenceResult<bool> {
        completion::finalize(&self.pool, ready, result, record, counterpart_proof).await
    }
    async fn get(
        &self,
        requester_id: &ActorId,
        target_id: &ActorId,
    ) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 AND target_id = $2 \
             LIMIT 1"
        ))
        .bind::<Text, _>(requester_id.to_string())
        .bind::<Text, _>(target_id.to_string())
        .get_result::<ContactRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        decode_contact_rows(row.into_iter().collect())
            .await
            .map(|mut rows| rows.pop())
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let request_slot_states =
            encode_contact_json(&record.request_slot_states, "request_slot_states")?;
        let request_receipts = encode_contact_json(&record.request_receipts, "request_receipts")?;
        let request_mirror_receipts =
            encode_contact_json(&record.request_mirror_receipts, "request_mirror_receipts")?;
        let contact_round_evidence = record
            .contact_round_evidence
            .as_ref()
            .map(|value| encode_contact_json(value, "contact_round_evidence"))
            .transpose()?;
        let current_state = encode_contact_json(&record.current_state, "current_state")?;

        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, contact_round_id, granted_to_target_scopes, granted_to_requester_scopes, status, pending_incoming_admitted, request_event_ref, request_slot_states, request_receipts, request_mirror_receipts, contact_round_evidence, current_state, response_event_ref, tombstone_event_ref, message, peer_id, peer_service_resolution, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21) \
             ON CONFLICT (requester_id, target_id) DO UPDATE SET \
                contact_round_id = EXCLUDED.contact_round_id, \
                granted_to_target_scopes = EXCLUDED.granted_to_target_scopes, \
                granted_to_requester_scopes = EXCLUDED.granted_to_requester_scopes, \
                status = EXCLUDED.status, \
                pending_incoming_admitted = EXCLUDED.pending_incoming_admitted, \
                request_event_ref = EXCLUDED.request_event_ref, \
                request_slot_states = EXCLUDED.request_slot_states, \
                request_receipts = EXCLUDED.request_receipts, \
                request_mirror_receipts = EXCLUDED.request_mirror_receipts, \
                contact_round_evidence = EXCLUDED.contact_round_evidence, \
                current_state = EXCLUDED.current_state, \
                response_event_ref = EXCLUDED.response_event_ref, \
                tombstone_event_ref = EXCLUDED.tombstone_event_ref, \
                message = EXCLUDED.message, \
                peer_id = EXCLUDED.peer_id, \
                peer_service_resolution = EXCLUDED.peer_service_resolution, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<diesel::sql_types::Bool, _>(record.pending_incoming_admitted)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(record.request_event_ref.as_ref())?)
        .bind::<Jsonb, _>(&request_slot_states)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&current_state)

        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(record.response_event_ref.as_ref())?)
        .bind::<Nullable<Binary>, _>(parse_contact_event_ref(
            record.tombstone_event_ref.as_ref(),
        )?)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_host_id.as_ref())
        .bind::<Nullable<Jsonb>, _>(record.peer_service_resolution.as_ref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn put_if_updated_at(
        &self,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
        record: &ContactRecord,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        put_if_updated_at_in_connection(&mut conn, expected_updated_at, record).await
    }

    async fn put_if_updated_at_with_result(
        &self,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
        record: &ContactRecord,
        result: &crate::IdempotencyRecord,
    ) -> PersistenceResult<bool> {
        use diesel_async::AsyncConnection as _;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            if !put_if_updated_at_in_connection(conn, expected_updated_at, record).await? {
                return Ok(false);
            }
            crate::idempotency::record_exact_idempotency_in_connection(conn, result).await?;
            Ok(true)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn list_for_actor(&self, actor_id: &ActorId) -> PersistenceResult<Vec<ContactRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester_id = $1 OR target_id = $1 \
             ORDER BY created_at ASC, requester_id ASC, target_id ASC"
        ))
        .bind::<Text, _>(actor_id.to_string())
        .get_results::<ContactRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_contact_rows(rows).await
    }

    async fn delete(&self, requester_id: &ActorId, target_id: &ActorId) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM contacts WHERE requester_id = $1 AND target_id = $2")
            .bind::<Text, _>(requester_id.to_string())
            .bind::<Text, _>(target_id.to_string())
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}

pub struct PgMimiConsentCorrelationStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct MimiConsentCorrelationRow {
    #[diesel(sql_type = Text)]
    consent_id: String,
    #[diesel(sql_type = Text)]
    requester_actor_id: String,
    #[diesel(sql_type = Text)]
    holder_account_id: String,
    #[diesel(sql_type = Text)]
    purpose: String,
    #[diesel(sql_type = Nullable<Text>)]
    strand_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    source_id: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<MimiConsentCorrelationRow> for MimiConsentCorrelationRecord {
    fn from(row: MimiConsentCorrelationRow) -> Self {
        Self {
            consent_id: row.consent_id,
            requester_actor_id: row.requester_actor_id,
            holder_account_id: row.holder_account_id,
            purpose: row.purpose,
            strand_id: row.strand_id,
            source_id: row.source_id,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

#[async_trait]
impl MimiConsentCorrelationStore for PgMimiConsentCorrelationStore {
    async fn get(
        &self,
        consent_id: &str,
    ) -> PersistenceResult<Option<MimiConsentCorrelationRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT consent_id, requester_actor_id, holder_account_id, purpose, strand_id, \
             source_id, created_at, expires_at \
             FROM mimi_consent_correlations WHERE consent_id = $1",
        )
        .bind::<Text, _>(consent_id)
        .get_result::<MimiConsentCorrelationRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MimiConsentCorrelationRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn update_outcome(
        &self,
        request: &arkret_models_collaboration::mimi_operations::MimiUpdateConsentRequestBody,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::mimi_operations::MimiUpdateConsentOutcome>,
    > {
        #[derive(QueryableByName)]
        struct Outcome {
            #[diesel(sql_type=Nullable<Jsonb>)]
            terminal_outcome: Option<serde_json::Value>,
        }
        if self.update_binding(request).await? != Some(true) {
            return Err(PersistenceError::Conflict(
                "MIMI original is not frozen".into(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        let row =
            sql_query("SELECT terminal_outcome FROM mimi_consent_updates WHERE consent_id=$1")
                .bind::<Text, _>(request.consent_id.as_str())
                .get_result::<Outcome>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
        let outcome: Option<
            arkret_models_collaboration::mimi_operations::MimiUpdateConsentOutcome,
        > = row
            .terminal_outcome
            .map(serde_json::from_value)
            .transpose()
            .map_err(PersistenceError::database)?;
        if outcome.as_ref().is_some_and(|o| {
            o.consent_id != request.consent_id
                || o.decision != request.decision
                || o.event_ref != request.consent_event.event.event_id
                || o.updated_at != request.consent_event.event.created_at
        }) {
            return Err(PersistenceError::Conflict(
                "MIMI terminal binding is corrupt".into(),
            ));
        }
        Ok(outcome)
    }
    async fn complete_update(
        &self,
        request: &arkret_models_collaboration::mimi_operations::MimiUpdateConsentRequestBody,
        outcome: &arkret_models_collaboration::mimi_operations::MimiUpdateConsentOutcome,
    ) -> PersistenceResult<()> {
        if self.update_binding(request).await? != Some(true)
            || outcome.consent_id != request.consent_id
            || outcome.decision != request.decision
            || outcome.event_ref != request.consent_event.event.event_id
            || outcome.updated_at != request.consent_event.event.created_at
        {
            return Err(PersistenceError::Conflict(
                "MIMI terminal does not bind its frozen original".into(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        let value = serde_json::to_value(outcome).map_err(PersistenceError::database)?;
        let changed=sql_query("UPDATE mimi_consent_updates SET terminal_outcome=$2 WHERE consent_id=$1 AND (terminal_outcome IS NULL OR terminal_outcome=$2)")
            .bind::<Text,_>(request.consent_id.as_str()).bind::<Jsonb,_>(value).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if changed != 1 {
            return Err(PersistenceError::Conflict(
                "MIMI original has another terminal".into(),
            ));
        }
        Ok(())
    }
    async fn update_binding(
        &self,
        request: &arkret_models_collaboration::mimi_operations::MimiUpdateConsentRequestBody,
    ) -> PersistenceResult<Option<bool>> {
        #[derive(QueryableByName)]
        struct Binding {
            #[diesel(sql_type=Text)]
            consent_id: String,
            #[diesel(sql_type=Text)]
            decision: String,
            #[diesel(sql_type=Text)]
            event_id: String,
            #[diesel(sql_type=Jsonb)]
            submission: serde_json::Value,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let rows=sql_query("SELECT consent_id,decision,event_id,submission FROM mimi_consent_updates WHERE consent_id=$1 OR event_id=$2")
            .bind::<Text,_>(request.consent_id.as_str()).bind::<Text,_>(request.consent_event.event.event_id.as_str()).get_results::<Binding>(&mut *conn).await.map_err(PersistenceError::database)?;
        let decision =
            serde_json::to_value(request.decision).map_err(PersistenceError::database)?;
        let submission =
            serde_json::to_value(&request.consent_event).map_err(PersistenceError::database)?;
        Ok((!rows.is_empty()).then(|| {
            rows.iter().all(|row| {
                row.consent_id == request.consent_id.as_str()
                    && row.decision == decision.as_str().unwrap_or("")
                    && row.event_id == request.consent_event.event.event_id.as_str()
                    && row.submission == submission
            })
        }))
    }
    async fn freeze_update(
        &self,
        request: &arkret_models_collaboration::mimi_operations::MimiUpdateConsentRequestBody,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let decision =
            serde_json::to_value(request.decision).map_err(PersistenceError::database)?;
        sql_query("INSERT INTO mimi_consent_updates(consent_id,decision,event_id,submission) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind::<Text,_>(request.consent_id.as_str()).bind::<Text,_>(decision.as_str().ok_or_else(||PersistenceError::SchemaViolation("invalid MIMI decision".into()))?)
            .bind::<Text,_>(request.consent_event.event.event_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&request.consent_event).map_err(PersistenceError::database)?)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        drop(conn);
        if self.update_binding(request).await? != Some(true) {
            return Err(PersistenceError::Conflict(
                "MIMI update correlation or Event is already frozen".into(),
            ));
        }
        Ok(())
    }

    async fn put(&self, record: &MimiConsentCorrelationRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO mimi_consent_correlations \
             (consent_id, requester_actor_id, holder_account_id, purpose, strand_id, \
              source_id, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (consent_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.consent_id)
        .bind::<Text, _>(&record.requester_actor_id)
        .bind::<Text, _>(&record.holder_account_id)
        .bind::<Text, _>(&record.purpose)
        .bind::<Nullable<Text>, _>(record.strand_id.as_deref())
        .bind::<Nullable<Text>, _>(record.source_id.as_deref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
// ── Pg-backed invite-receive policy store ────────────────────────────────
// Account ownership is normalized through accounts.pk. The shared wire policy
// is the sole stored policy value; reads verify its binding against the owner.
pub struct PgInviteReceivePolicyStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct InviteReceivePolicyRow {
    #[diesel(sql_type = Text)]
    principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: DidCoreId,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
}
impl InviteReceivePolicyRow {
    fn into_policy(
        self,
    ) -> PersistenceResult<(
        arkret_wire::AccountId,
        arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    )> {
        let policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy =
            serde_json::from_value(self.policy_payload)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "invite_receive_policy payload decode: {error}"
                ))
            })?;
        let account_id = arkret_wire::AccountId::new(self.principal_id, self.station_id);
        coland_storage::validate_invite_policy_account(&account_id, &policy)?;
        Ok((account_id, policy))
    }
}

pub(crate) async fn put_invite_receive_policy(
    conn: &mut diesel_async::AsyncPgConnection,
    account_id: &arkret_wire::AccountId,
    policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
) -> PersistenceResult<()> {
    coland_storage::validate_invite_policy_account(account_id, policy)?;
    let payload = serde_json::to_value(policy).map_err(|error| {
        PersistenceError::Internal(format!("invite_receive_policy payload encode: {error}"))
    })?;
    let written = sql_query(
        "INSERT INTO invite_receive_policies (account_pk, policy_payload, updated_at) \
         SELECT pk, $3, NOW() FROM accounts WHERE principal_id = $1 AND station_id = $2 \
         ON CONFLICT (account_pk) DO UPDATE SET \
         revision = CASE WHEN invite_receive_policies.policy_payload IS DISTINCT FROM EXCLUDED.policy_payload \
             THEN invite_receive_policies.revision + 1 ELSE invite_receive_policies.revision END, \
         policy_payload = EXCLUDED.policy_payload, \
         updated_at = CASE WHEN invite_receive_policies.policy_payload IS DISTINCT FROM EXCLUDED.policy_payload \
             THEN NOW() ELSE invite_receive_policies.updated_at END",
    )
    .bind::<Text, _>(account_id.principal_id.as_str())
    .bind::<Text, _>(account_id.station_id.as_str())
    .bind::<Jsonb, _>(&payload)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "invite_receive_policy account does not exist".to_owned(),
        ));
    }
    Ok(())
}
#[async_trait]
impl InviteReceivePolicyStore for PgInviteReceivePolicyStore {
    async fn get(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT a.principal_id, a.station_id, p.policy_payload FROM invite_receive_policies p \
             JOIN accounts a ON a.pk = p.account_pk \
             WHERE a.principal_id = $1 AND a.station_id = $2",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .get_result::<InviteReceivePolicyRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(InviteReceivePolicyRow::into_policy)
            .transpose()
            .map(|row| row.map(|(_, policy)| policy))
    }

    async fn put(
        &self,
        account_id: &arkret_wire::AccountId,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        put_invite_receive_policy(&mut conn, account_id, policy).await
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<(
            arkret_wire::AccountId,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT a.principal_id, a.station_id, p.policy_payload FROM invite_receive_policies p \
             JOIN accounts a ON a.pk = p.account_pk",
        )
        .get_results::<InviteReceivePolicyRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(InviteReceivePolicyRow::into_policy)
            .collect()
    }
}
#[cfg(test)]
mod invite_policy_tests {
    use super::*;

    #[test]
    fn stored_policy_payload_must_match_normalized_account_owner() {
        use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
        let principal_id = DidCoreId::new("ak:did_core:web:holder.example".to_owned()).unwrap();
        let station_id = DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap();
        let account_id = arkret_wire::AccountId::new(principal_id.clone(), station_id.clone());
        let policy = InviteReceivePolicy::spec_default(account_id.clone());
        let payload = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            InviteReceivePolicyRow {
                principal_id: principal_id.clone(),
                station_id,
                policy_payload: payload.clone(),
            }
            .into_policy()
            .unwrap(),
            (account_id, policy)
        );
        assert!(
            InviteReceivePolicyRow {
                principal_id,
                station_id: DidCoreId::new("ak:did_core:web:other-station.example".to_owned())
                    .unwrap(),
                policy_payload: payload,
            }
            .into_policy()
            .is_err()
        );
    }
}

#[derive(QueryableByName)]
struct ContactIndexedMaterial {
    #[diesel(sql_type=Jsonb)]
    material: Value,
}
