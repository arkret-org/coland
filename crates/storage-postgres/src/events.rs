use diesel::sql_types::SmallInt;

use super::{
    BigInt, Binary, Bool, CanonicalEventRecord, DirectConversationDurableState,
    DirectConversationFoundingSlotRecord, DirectConversationMemberCurrent, EventStore, ExistsRow,
    FederationOutboxRecord, IdentityAnchorAccountSlot, Jsonb, MessageRecord, MessageStore,
    Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RealmEventStats, RunQueryDsl, Text, Timestamptz, Value, async_trait, ids, pg_conn, sql_query,
};
use crate::federation::{FederationOutboxRow, qualified_outbox_columns};
use crate::{AsyncConnection, PgTransactionError};

fn contact_durable_diagnostic(branch: &'static str) {
    #[cfg(feature = "conformance-harness")]
    tracing::warn!(target: "conformance_harness", stage = "contact_durable_read", diag_branch = branch,
        "Contact durable binding fixed diagnostic");
    #[cfg(not(feature = "conformance-harness"))]
    let _ = branch;
}

/// Read model for producer-signed Events. Event admission and ordering are
/// owned by `PgAuthorityCommitStore`; this store deliberately has no write API.
pub struct PgEventStore {
    pub pool: PgPool,
}

const EVENT_COLUMNS: &str =
    "id, digest_suite, digest, actor_id, realm_id, kind, canonical_bytes, envelope, received_at";

#[derive(QueryableByName)]
struct CanonicalEventRow {
    #[diesel(sql_type = Binary)]
    id: Vec<u8>,
    #[diesel(sql_type = SmallInt)]
    digest_suite: i16,
    #[diesel(sql_type = Binary)]
    digest: Vec<u8>,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct DirectConversationDurableStateRow {
    #[diesel(sql_type = Text)]
    founder_id: String,
    #[diesel(sql_type = Text)]
    trust_domain_id: String,
    #[diesel(sql_type = Text)]
    pair_key: String,
    #[diesel(sql_type = Text)]
    founding_unit_digest: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    main_strand_id: String,
    #[diesel(sql_type = Jsonb)]
    authorization_basis: Value,
    #[diesel(sql_type = Jsonb)]
    event_ids: Value,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    binding: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    group_state_ref: Option<String>,
    #[diesel(sql_type = Nullable<Bool>)]
    group_current_exact_pair: Option<bool>,
    #[diesel(sql_type = Nullable<Text>)]
    initial_exact_pair_group_state_ref: Option<String>,
    #[diesel(sql_type = Jsonb)]
    members: Value,
}

impl TryFrom<DirectConversationDurableStateRow> for DirectConversationDurableState {
    type Error = PersistenceError;

    fn try_from(row: DirectConversationDurableStateRow) -> Result<Self, Self::Error> {
        let members: Vec<serde_json::Value> =
            serde_json::from_value(row.members).map_err(PersistenceError::database)?;
        let members = members
            .into_iter()
            .map(|value| {
                let member_id = value
                    .get("member_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        PersistenceError::Database("stored member id is invalid".to_owned())
                    })
                    .and_then(|id| serde_json::from_str(id).map_err(PersistenceError::database))?;
                let membership = value
                    .get("membership")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        PersistenceError::Database("stored membership is invalid".to_owned())
                    })?
                    .to_owned();
                Ok(DirectConversationMemberCurrent {
                    member_id,
                    membership,
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        Ok(Self {
            founding_slot: DirectConversationFoundingSlotRecord {
                founder_id: row.founder_id,
                trust_domain_id: row.trust_domain_id,
                pair_key: row.pair_key,
                founding_unit_digest: row.founding_unit_digest,
                realm_id: row.realm_id,
                main_strand_id: row.main_strand_id,
                authorization_basis: serde_json::from_value(row.authorization_basis)
                    .map_err(PersistenceError::database)?,
                event_ids: serde_json::from_value(row.event_ids)
                    .map_err(PersistenceError::database)?,
                idempotency_key: row.idempotency_key,
                accepted_at: row.accepted_at,
            },
            binding: row
                .binding
                .map(serde_json::from_value)
                .transpose()
                .map_err(PersistenceError::database)?,
            group_state_ref: row
                .group_state_ref
                .map(arkret_wire::EventId::new)
                .transpose()
                .map_err(|error| PersistenceError::Database(error.to_string()))?,
            group_current_exact_pair: row.group_current_exact_pair,
            initial_exact_pair_group_state_ref: row.initial_exact_pair_group_state_ref
                .map(arkret_wire::EventId::new).transpose()
                .map_err(|error| PersistenceError::Database(error.to_string()))?,
            peer_mls_admission: arkret_models_collaboration::direct_conversation::DirectConversationPeerMlsAdmission::Missing,
            members,
        })
    }
}

impl TryFrom<CanonicalEventRow> for CanonicalEventRecord {
    type Error = PersistenceError;

    fn try_from(row: CanonicalEventRow) -> Result<Self, Self::Error> {
        let id: [u8; ids::EVENT_ID_BYTES] = row.id.try_into().map_err(|_| {
            PersistenceError::Internal("stored Event id has invalid length".to_owned())
        })?;
        let digest: [u8; ids::EVENT_DIGEST_BYTES] = row.digest.try_into().map_err(|_| {
            PersistenceError::Internal("stored Event digest has invalid length".to_owned())
        })?;
        let digest_suite = match row.digest_suite {
            1 => arkret_canonical::DigestSuite::Sha256,
            2 => arkret_canonical::DigestSuite::Blake3,
            other => {
                return Err(PersistenceError::Internal(format!(
                    "stored Event uses unsupported digest suite {other}"
                )));
            }
        };
        let canonical_digest = ids::format_event_digest(row.digest_suite as u8, &digest)
            .ok_or_else(|| PersistenceError::Internal("stored Event digest is invalid".into()))?;
        Ok(Self {
            event_id: ids::format_event_id(&id),
            actor_id: row.actor_id,
            realm_id: row.realm_id,
            kind: row.kind,
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite,
            canonical_digest,
            canonical_bytes: row.canonical_bytes,
            envelope: row.envelope,
            received_at: row.received_at,
        })
    }
}

fn decode_events(rows: Vec<CanonicalEventRow>) -> PersistenceResult<Vec<CanonicalEventRecord>> {
    rows.into_iter()
        .map(CanonicalEventRecord::try_from)
        .collect()
}

#[derive(QueryableByName)]
struct RealmEventStatsRow {
    #[diesel(sql_type = BigInt)]
    event_count: i64,
    #[diesel(sql_type = BigInt)]
    canonical_bytes: i64,
}

#[derive(QueryableByName)]
struct DirectConversationFoundingSlotRow {
    #[diesel(sql_type = Text)]
    founder_id: String,
    #[diesel(sql_type = Text)]
    trust_domain_id: String,
    #[diesel(sql_type = Text)]
    pair_key: String,
    #[diesel(sql_type = Text)]
    founding_unit_digest: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    main_strand_id: String,
    #[diesel(sql_type = Jsonb)]
    authorization_basis: Value,
    #[diesel(sql_type = Jsonb)]
    event_ids: Value,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<DirectConversationFoundingSlotRow> for DirectConversationFoundingSlotRecord {
    type Error = PersistenceError;

    fn try_from(row: DirectConversationFoundingSlotRow) -> Result<Self, Self::Error> {
        Ok(Self {
            founder_id: row.founder_id,
            trust_domain_id: row.trust_domain_id,
            pair_key: row.pair_key,
            founding_unit_digest: row.founding_unit_digest,
            realm_id: row.realm_id,
            main_strand_id: row.main_strand_id,
            authorization_basis: serde_json::from_value(row.authorization_basis)
                .map_err(PersistenceError::database)?,
            event_ids: serde_json::from_value(row.event_ids).map_err(PersistenceError::database)?,
            idempotency_key: row.idempotency_key,
            accepted_at: row.accepted_at,
        })
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    async fn federation_outbox_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        let outbox_columns = qualified_outbox_columns("outbox");
        let rows = sql_query(format!(
            "SELECT {outbox_columns} FROM federation_outbox outbox \
             JOIN event_federation_outbox link ON link.outbox_id = outbox.id \
             JOIN canonical_events event ON event.pk = link.event_pk \
             WHERE event.id = $1 ORDER BY outbox.created_at ASC, outbox.id ASC"
        ))
        .bind::<Binary, _>(event_id.to_vec())
        .load::<FederationOutboxRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(FederationOutboxRecord::try_from)
            .collect()
    }

    async fn foreign_direct_mls_input(
        &self,
        realm: &arkret_wire::RealmId,
        caller: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<coland_storage::ForeignDirectMlsInput>> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            crate::replica_direct_mls::input_in_connection(conn, realm, caller)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn install_foreign_direct_mls_public_state(
        &self,
        input: &coland_storage::ForeignDirectMlsInput,
        result: &coland_storage::ForeignDirectMlsBase,
        exact_pair: bool,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::replica_direct_mls::install_in_connection(conn, input, result, exact_pair)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<DirectConversationFoundingSlotRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT founder_id, trust_domain_id, pair_key, founding_unit_digest, realm_id, \
                    main_strand_id, authorization_basis, event_ids, idempotency_key, accepted_at \
             FROM direct_conversation_founding_slots \
             WHERE founder_id = $1 AND trust_domain_id = $2 AND pair_key = $3",
        )
        .bind::<Text, _>(founder_id)
        .bind::<Text, _>(trust_domain_id)
        .bind::<Text, _>(pair_key)
        .get_result::<DirectConversationFoundingSlotRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(DirectConversationFoundingSlotRecord::try_from)
        .transpose()
    }

    async fn direct_conversation_durable_state(
        &self,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<DirectConversationDurableState>> {
        let mut conn = pg_conn(&self.pool).await?;
        let result = conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn).await?;
        let row = sql_query(
            "SELECT s.founder_id,s.trust_domain_id,s.pair_key,s.founding_unit_digest,\
                    s.realm_id,s.main_strand_id,s.authorization_basis,s.event_ids,s.idempotency_key,s.accepted_at,\
                    b.value AS binding,\
                    m.value->>'current_mls_commit_event_ref' AS group_state_ref,\
                    g.current_exact_pair AS group_current_exact_pair,\
                    g.initial_exact_pair_group_state_ref,\
                    COALESCE((SELECT jsonb_agg(jsonb_build_object(\
                        'member_id',ms.member_id,'membership',ms.membership) ORDER BY ms.member_id)\
                      FROM member_state_current_results ms WHERE ms.realm_id=s.realm_id),\
                      '[]'::jsonb) AS members \
             FROM direct_conversation_founding_slots s \
             LEFT JOIN direct_conversation_binding_current_results b ON b.realm_id=s.realm_id \
             LEFT JOIN direct_conversation_group_states g ON g.realm_id=s.realm_id AND NOT EXISTS (SELECT 1 FROM replica_stream_anchors WHERE realm_id=s.realm_id) \
             LEFT JOIN mls_group_current_results m ON m.realm_id=s.realm_id \
                AND m.value->'effective_scope'->>'kind'='realm' AND NOT EXISTS (SELECT 1 FROM replica_stream_anchors WHERE realm_id=s.realm_id) \
             WHERE s.trust_domain_id=$1 AND s.pair_key=$2",
        )
        .bind::<Text, _>(trust_domain_id)
        .bind::<Text, _>(pair_key)
        .get_result::<DirectConversationDurableStateRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let mut facts = row.map(DirectConversationDurableState::try_from).transpose()?;
        if let Some(facts) = &mut facts {
            crate::replica_direct_mls::apply_in_connection(conn, facts).await?;
            facts.peer_mls_admission = crate::direct_conversation_admission::peer_mls_admission_snapshot(
                conn, &arkret_wire::RealmId::new(facts.founding_slot.realm_id.clone())
                    .map_err(|error| PersistenceError::Database(error.to_string()))?,
            ).await?;
        }
        Ok(facts)
        }).await.map_err(PgTransactionError::into_persistence);
        // Log only after the snapshot transaction completed successfully.
        match &result {
            Ok(None) => contact_durable_diagnostic("slot_absent"),
            Ok(Some(facts)) if facts.binding.is_none() => {
                contact_durable_diagnostic("binding_absent")
            }
            Ok(Some(_)) => contact_durable_diagnostic("binding_present"),
            Err(_) => contact_durable_diagnostic("lookup_failed"),
        }
        result
    }

    async fn direct_conversation_durable_state_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Option<DirectConversationDurableState>> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn).await?;
        let row = sql_query(
            "SELECT s.founder_id,s.trust_domain_id,s.pair_key,s.founding_unit_digest,\
                    s.realm_id,s.main_strand_id,s.authorization_basis,s.event_ids,s.idempotency_key,s.accepted_at,\
                    b.value AS binding,\
                    m.value->>'current_mls_commit_event_ref' AS group_state_ref,\
                    g.current_exact_pair AS group_current_exact_pair,\
                    g.initial_exact_pair_group_state_ref,\
                    COALESCE((SELECT jsonb_agg(jsonb_build_object(\
                        'member_id',ms.member_id,'membership',ms.membership) ORDER BY ms.member_id)\
                      FROM member_state_current_results ms WHERE ms.realm_id=s.realm_id),\
                      '[]'::jsonb) AS members \
             FROM direct_conversation_founding_slots s \
             LEFT JOIN direct_conversation_binding_current_results b ON b.realm_id=s.realm_id \
             LEFT JOIN direct_conversation_group_states g ON g.realm_id=s.realm_id AND NOT EXISTS (SELECT 1 FROM replica_stream_anchors WHERE realm_id=s.realm_id) \
             LEFT JOIN mls_group_current_results m ON m.realm_id=s.realm_id \
                AND m.value->'effective_scope'->>'kind'='realm' AND NOT EXISTS (SELECT 1 FROM replica_stream_anchors WHERE realm_id=s.realm_id) \
             WHERE s.realm_id=$1",
        )
        .bind::<Text, _>(realm_id)
        .get_result::<DirectConversationDurableStateRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let mut facts = row.map(DirectConversationDurableState::try_from).transpose()?;
        if let Some(facts) = &mut facts {
            crate::replica_direct_mls::apply_in_connection(conn, facts).await?;
            facts.peer_mls_admission = crate::direct_conversation_admission::peer_mls_admission_snapshot(
                conn, &arkret_wire::RealmId::new(facts.founding_slot.realm_id.clone())
                    .map_err(|error| PersistenceError::Database(error.to_string()))?,
            ).await?;
        }
        Ok(facts)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<IdentityAnchorAccountSlot>> {
        #[derive(QueryableByName)]
        struct AccountSlotRow {
            #[diesel(sql_type = Text)]
            account_authority_id: String,
            #[diesel(sql_type = Text)]
            account_subject: String,
            #[diesel(sql_type = Text)]
            principal_id: arkret_identifiers::DidCoreId,
            #[diesel(sql_type = Text)]
            station_id: arkret_identifiers::DidCoreId,
            #[diesel(sql_type = Text)]
            realm_id: String,
            #[diesel(sql_type = Text)]
            create_event_id: String,
        }
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(
            "SELECT account_authority_id, account_subject, principal_id, station_id, realm_id, \
                    create_event_id FROM identity_anchor_account_slots \
             WHERE principal_id = $1 AND station_id = $2 LIMIT 2",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .load::<AccountSlotRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => Ok(Some(IdentityAnchorAccountSlot {
                account_authority_id: row.account_authority_id.clone(),
                account_subject: row.account_subject.clone(),
                account_id: arkret_wire::AccountId::new(
                    row.principal_id.clone(),
                    row.station_id.clone(),
                ),
                realm_id: row.realm_id.clone(),
                create_event_id: row.create_event_id.clone(),
            })),
            _ => Err(PersistenceError::Conflict(
                "account has multiple identity-anchor account slots".to_owned(),
            )),
        }
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        let row = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events WHERE id = $1 AND state = 'committed'"
        ))
        .bind::<Binary, _>(event_id.to_vec())
        .get_result::<CanonicalEventRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(CanonicalEventRecord::try_from).transpose()
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        let mut conn = crate::pg_db(&self.pool);
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        sql_query(
            "SELECT EXISTS(SELECT 1 FROM canonical_events WHERE id = $1 AND state = 'committed') AS present",
        )
        .bind::<Binary, _>(event_id.to_vec())
        .get_result::<ExistsRow>(&mut conn)
        .await
        .map(|row| row.present)
        .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events WHERE actor_id = $1 AND state = 'committed' \
             ORDER BY received_at ASC, id ASC"
        ))
        .bind::<Text, _>(actor_id)
        .load::<CanonicalEventRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_events(rows)
    }

    async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events \
             WHERE realm_id = $1 AND actor_id = $2 AND kind = $3 AND state = 'committed' \
               AND envelope -> 'payload' ->> 'event_id' = $4 \
             ORDER BY received_at ASC, id ASC"
        ))
        .bind::<Text, _>(realm_id)
        // A proof is authored by the receiving service, and `actor_id` stores
        // the canonical key of the complete ActorId.
        .bind::<Text, _>(arkret_wire::ActorId::service(received_by.clone()).to_string())
        .bind::<Text, _>(arkret_wire::EventKind::ModerationFrankingProof.as_str())
        .bind::<Text, _>(target_event_id)
        .load::<CanonicalEventRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_events(rows)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events WHERE state = 'committed' \
             ORDER BY received_at ASC, id ASC"
        ))
        .load::<CanonicalEventRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_events(rows)
    }

    async fn realm_event_stats(&self, realm_id: &str) -> PersistenceResult<RealmEventStats> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT COUNT(*)::bigint AS event_count, \
                    COALESCE(SUM(OCTET_LENGTH(canonical_bytes)), 0)::bigint AS canonical_bytes \
             FROM canonical_events WHERE realm_id = $1 AND state = 'committed'",
        )
        .bind::<Text, _>(realm_id)
        .get_result::<RealmEventStatsRow>(&mut conn)
        .await
        .map(|row| RealmEventStats {
            count: row.event_count.max(0) as u64,
            canonical_bytes: row.canonical_bytes.max(0) as u64,
        })
        .map_err(PersistenceError::database)
    }

    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events WHERE realm_id = $1 AND state = 'committed' \
             ORDER BY received_at DESC, id DESC"
        ))
        .bind::<Text, _>(realm_id)
        .load::<CanonicalEventRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_events(rows)
    }
}

const MESSAGE_COLUMNS: &str =
    "event_id, message_id, realm_id, sender, thread_id, content, encrypted, created_at";

pub struct PgMessageStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct MessageRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    message_id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    sender: String,
    #[diesel(sql_type = Text)]
    thread_id: String,
    #[diesel(sql_type = Jsonb)]
    content: Value,
    #[diesel(sql_type = Bool)]
    encrypted: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<MessageRow> for MessageRecord {
    fn from(row: MessageRow) -> Self {
        Self {
            event_id: row.event_id,
            message_id: row.message_id,
            realm_id: row.realm_id,
            sender: row.sender,
            thread_id: row.thread_id,
            content: row.content,
            encrypted: row.encrypted,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl MessageStore for PgMessageStore {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE event_id = $1"
        ))
        .bind::<Text, _>(event_id)
        .get_result::<MessageRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(MessageRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "INSERT INTO messages \
             (event_id, message_id, realm_id, sender, thread_id, content, encrypted, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (event_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.event_id)
        .bind::<Text, _>(&record.message_id)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.sender)
        .bind::<Text, _>(&record.thread_id)
        .bind::<Jsonb, _>(&record.content)
        .bind::<Bool, _>(record.encrypted)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE realm_id = $1 \
             ORDER BY created_at DESC, pk DESC LIMIT $2"
        ))
        .bind::<Text, _>(realm_id)
        .bind::<BigInt, _>(limit as i64)
        .load::<MessageRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(MessageRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE thread_id = $1 \
             ORDER BY created_at ASC, pk ASC LIMIT $2"
        ))
        .bind::<Text, _>(thread_id)
        .bind::<BigInt, _>(limit as i64)
        .load::<MessageRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(MessageRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, event_id: &str) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM messages WHERE event_id = $1")
            .bind::<Text, _>(event_id)
            .execute(&mut conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
