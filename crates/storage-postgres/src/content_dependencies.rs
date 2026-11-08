//! Public dependencies and key-use uniqueness at the original Commit cut.
//! No root secret, content key or portable MLS private state reaches this unit.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::{EventContentEnvelopesExt as _, EventPayloadExt as _};
use arkret_models_collaboration::events_payloads::RealmPurpose;
use arkret_models_crypto::{
    ContentContext, ContentCoverageEntry, ContentRootContext, EncryptedEnvelopeEncryptionContext,
    KeyBackup, SecretStorageItemKind,
};
use arkret_wire::{CommittedEventRef, Event, EventKind, MlsGroupValue};
use coland_storage::{AuthorityCommitTransaction, PersistenceError, PersistenceResult};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::Value;

use crate::{AsyncPgConnection, PgTransactionError};

fn invalid(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.into())
}

fn missing(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {}", detail.into()))
}

#[derive(QueryableByName)]
struct GroupRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
}

#[derive(QueryableByName)]
struct RootSubjectRow {
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    custodian_actor: Option<Value>,
}

#[derive(QueryableByName)]
struct DomainRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    content_path: String,
    #[diesel(sql_type = Jsonb)]
    content_context: Value,
}

async fn original_event(
    conn: &mut AsyncPgConnection,
    event_id: &arkret_wire::EventId,
) -> PersistenceResult<Event> {
    let row = sql_query("SELECT e.envelope AS payload FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND e.state='committed'")
        .bind::<Text,_>(event_id.as_str()).get_result::<crate::JsonPayloadRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| missing("content root basis is not an accepted original"))?;
    serde_json::from_value(row.payload).map_err(PersistenceError::database)
}

async fn validate_root_basis(
    conn: &mut AsyncPgConnection,
    root: &ContentRootContext,
    group: &MlsGroupValue,
    declaration: &Event,
) -> PersistenceResult<()> {
    root.validate()
        .map_err(|error| invalid(error.to_string()))?;
    let strategy = declaration
        .as_realm_create()
        .map_err(|error| invalid(error.to_string()))?
        .object
        .initial_encryption_backup_strategy;
    if root.effective_scope != group.effective_scope
        || root.genesis_event_ref != group.genesis_event_ref
        || root.cipher_suite != group.cipher_suite.as_str()
        || root.backup_strategy_ref != declaration.event_id
        || root.encryption_backup_strategy != strategy
        || root.epoch > group.epoch
    {
        return Err(invalid(
            "content root context differs from its accepted group or original strategy",
        ));
    }
    let state = original_event(conn, &root.group_state_ref).await?;
    if state.scope_ref != root.effective_scope {
        return Err(invalid(
            "content root basis belongs to another effective scope",
        ));
    }
    let epoch = match state.kind {
        EventKind::MlsGenesis if state.event_id == root.genesis_event_ref => state
            .as_mls_genesis()
            .map_err(|error| invalid(error.to_string()))?
            .governance_binding
            .next_epoch(),
        EventKind::MlsCommit => state
            .as_mls_commit()
            .map_err(|error| invalid(error.to_string()))?
            .governance_binding()
            .next_epoch(),
        _ => {
            return Err(invalid(
                "content root basis is not its accepted MLS Genesis or Commit",
            ));
        }
    };
    if epoch != root.epoch {
        return Err(invalid(
            "content root epoch differs from the accepted original MLS result",
        ));
    }
    Ok(())
}

/// Called only inside the same native transaction that verified the producer,
/// serialized the effective scope and is installing this original Commit.
pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<(), PgTransactionError> {
    let event = &transaction.event;
    let carriers = event
        .event_content_envelopes()
        .map_err(|error| invalid(error.to_string()))?;
    if carriers.is_empty() {
        return commit_plain_pcr_coverage(conn, transaction).await;
    }
    crate::mls_group_current_states::require_mls_send_gate_in_connection(conn, event).await?;
    let scope_key = crate::mls_group_current_states::scope_key(&event.scope_ref)?;
    let row = sql_query(
        "SELECT value,public_state FROM mls_group_current_states WHERE scope_key=$1 FOR SHARE",
    )
    .bind::<Text, _>(&scope_key)
    .get_result::<GroupRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| missing("encrypted original has no accepted MLS group"))?;
    let group: MlsGroupValue =
        serde_json::from_value(row.value).map_err(PersistenceError::database)?;
    let endpoint =
        crate::content_endpoint_bindings::current_producer_in_connection(conn, transaction, &group)
            .await?;
    let tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &row.public_state,
        event
            .scope_ref
            .canonical_mls_group_id()
            .map_err(|error| invalid(error.to_string()))?
            .as_str(),
        group.epoch,
    )
    .map_err(|error| invalid(error.to_string()))?;
    if tracker
        .leaves()
        .map_err(|error| invalid(error.to_string()))?
        .iter()
        .filter(|leaf| {
            leaf.actor_id == endpoint.actor_id
                && leaf.signature_key.as_str() == endpoint.signature_key_base64url
        })
        .count()
        != 1
    {
        return Err(invalid("original producer is not one exact accepted MLS leaf").into());
    }
    let declaration = sql_query("SELECT e.envelope AS payload FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.realm_id=$1 AND e.kind='ak.realm.create' AND e.state='committed' ORDER BY c.stream_position LIMIT 1")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional()?
        .ok_or_else(|| missing("scope has no accepted original backup strategy declaration"))?;
    let declaration: Event =
        serde_json::from_value(declaration.payload).map_err(PersistenceError::database)?;
    let realm = declaration
        .as_realm_create()
        .map_err(|error| invalid(error.to_string()))?;
    if matches!(
        event.kind,
        EventKind::ProfileCreate | EventKind::ProfileUpdate
    ) && !matches!(
        realm.object.purpose,
        RealmPurpose::PrincipalControl | RealmPurpose::AgentControl
    ) {
        return Err(invalid("private Profile envelope requires its original Account PCR").into());
    }
    // Agent controller bootstrap requires its separate native qualification;
    // never reinterpret it as a Human subject while that adapter is absent.
    if realm.object.purpose == RealmPurpose::AgentControl {
        return Err(missing("Agent PCR root dependency admission is not yet qualified").into());
    }
    let pcr_actor = if realm.object.purpose == RealmPurpose::PrincipalControl {
        #[derive(QueryableByName)]
        struct Owner {
            #[diesel(sql_type=Text)]
            principal_id: String,
            #[diesel(sql_type=Text)]
            station_id: String,
        }
        let owner = sql_query("SELECT principal_id,station_id FROM principal_resolutions WHERE pcr_realm_id=$1 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).get_result::<Owner>(&mut *conn).await.optional()?
            .ok_or_else(|| missing("PCR has no accepted full Account owner"))?;
        Some(
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(owner.principal_id)
                    .map_err(|error| invalid(error.to_string()))?,
                arkret_wire::DidCoreId::new(owner.station_id)
                    .map_err(|error| invalid(error.to_string()))?,
            ))
            .to_string(),
        )
    } else {
        None
    };

    let mut backup_ids = BTreeSet::new();
    let mut required_roots = BTreeMap::new();
    let mut blob_refs = BTreeMap::new();
    for carrier in &carriers {
        let EncryptedEnvelopeEncryptionContext::EpochContent {
            epoch,
            group_state_ref,
            protection,
            ..
        } = &carrier.envelope.encryption_context;
        if *epoch != group.epoch || *group_state_ref != group.current_mls_commit_event_ref {
            return Err(invalid(
                "new encrypted original does not name the current accepted MLS result",
            )
            .into());
        }
        for id in &protection.backup_refs {
            backup_ids.insert(id.clone());
        }
        for root in &protection.root_refs {
            required_roots.insert(root.as_str().to_owned(), root.clone());
        }
        for blob in &protection.blob_refs {
            blob_refs.insert(blob.as_str().to_owned(), blob.clone());
        }
    }
    // Discover immutable actors first, then use the same actor-before-body lock
    // order as PUT, ordinary deletion, rotation and series erasure.
    let mut actors = BTreeMap::new();
    let mut recipients = BTreeMap::new();
    for id in &backup_ids {
        let row = sql_query("SELECT actor_id,payload->'custodian_actor_id' AS custodian_actor FROM key_backups WHERE id=$1")
            .bind::<diesel::sql_types::Uuid,_>(crate::ids::typed_uuid_part_expect_internal(id.as_str()))
            .get_result::<RootSubjectRow>(&mut *conn).await.optional()?
            .ok_or_else(|| missing("original references a missing durable root package"))?;
        let actor: arkret_wire::ActorId =
            serde_json::from_str(&row.actor_id).map_err(PersistenceError::database)?;
        let recipient = row
            .custodian_actor
            .map(serde_json::from_value::<arkret_wire::ActorId>)
            .transpose()
            .map_err(PersistenceError::database)?
            .unwrap_or_else(|| actor.clone());
        recipients.insert(recipient.to_string(), recipient);
        actors.insert(actor.to_string(), actor);
    }
    for recipient in recipients.values() {
        let account = recipient
            .as_account_id()
            .ok_or_else(|| missing("root custodian has no full Account policy"))?;
        crate::pcr_recovery_policy_unit::current_policy(conn, account).await?;
    }
    for actor in actors.values() {
        crate::key_backup::lock_backup_series_in_connection(conn, actor).await?;
    }
    let mut roots: BTreeMap<String, (ContentRootContext, String)> = BTreeMap::new();
    let mut packet_roots = BTreeMap::new();
    let wanted = required_roots.keys().cloned().collect::<Vec<_>>();
    for id in &backup_ids {
        let packet = crate::content_root_packages::read_in_connection(conn, id, &wanted).await?;
        if pcr_actor
            .as_ref()
            .is_some_and(|actor| actor != &packet.actor.to_string())
            || packet
                .expires_at
                .is_some_and(|expiry| expiry <= chrono::Utc::now())
        {
            return Err(
                invalid("root package subject or validity does not cover this original").into(),
            );
        }
        packet.require_current_recipient(conn).await?;
        let mut used = false;
        let mut selected = BTreeSet::new();
        for (root_ref, context) in &packet.roots {
            used = true;
            selected.insert(root_ref.as_str().to_owned());
            validate_root_basis(conn, context, &group, &declaration).await?;
            if let Some((previous, _)) = roots.get(root_ref.as_str()) {
                if previous != context {
                    return Err(
                        invalid("one root reference binds different accepted contexts").into(),
                    );
                }
            } else {
                roots.insert(
                    root_ref.as_str().to_owned(),
                    (context.clone(), packet.actor.to_string()),
                );
            }
        }
        if !used {
            return Err(
                invalid("protection names a backup package with no selected content root").into(),
            );
        }
        packet_roots.insert(id.clone(), selected);
    }
    if roots.len() != required_roots.len() {
        return Err(missing("not every authenticated root has a durable native package").into());
    }
    for carrier in &carriers {
        let EncryptedEnvelopeEncryptionContext::EpochContent { protection, .. } =
            &carrier.envelope.encryption_context;
        for root in &protection.root_refs {
            if !protection.backup_refs.iter().any(|id| {
                packet_roots
                    .get(id)
                    .is_some_and(|roots| roots.contains(root.as_str()))
            }) {
                return Err(missing(
                    "an envelope's own signed backup references do not cover its roots",
                )
                .into());
            }
        }
        for id in &protection.backup_refs {
            if !packet_roots.get(id).is_some_and(|roots| {
                protection
                    .root_refs
                    .iter()
                    .any(|root| roots.contains(root.as_str()))
            }) {
                return Err(invalid(
                    "an envelope's backup reference has no matching selected root",
                )
                .into());
            }
        }
    }
    for blob in blob_refs.values() {
        let exists =
            sql_query("SELECT payload FROM blobs WHERE id=$1 AND redacted=false FOR SHARE")
                .bind::<Text, _>(blob.as_str())
                .get_result::<crate::JsonPayloadRow>(&mut *conn)
                .await
                .optional()?;
        if exists.is_none() {
            return Err(missing("original references a missing durable ciphertext blob").into());
        }
    }
    let source = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: transaction.commit.commit_id.clone(),
        stream_ref: transaction.commit.stream_ref.clone(),
        stream_position: transaction.commit.stream_position,
    };
    let coverage = ContentCoverageEntry {
        source,
        root_refs: required_roots.into_values().collect(),
        blob_refs: blob_refs.into_values().collect(),
    };
    freeze_coverage(
        conn,
        transaction,
        &coverage,
        matches!(
            realm.object.purpose,
            RealmPurpose::PrincipalControl | RealmPurpose::AgentControl
        ),
    )
    .await?;
    for (root, (context, actor)) in &roots {
        sql_query("INSERT INTO content_original_roots(event_id,root_ref,root_context,backup_actor_id) VALUES($1,$2,$3,$4)")
            .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(root)
            .bind::<Jsonb,_>(serde_json::to_value(context).map_err(PersistenceError::database)?).bind::<Text,_>(actor)
            .execute(&mut *conn).await?;
    }
    let producer_digest =
        arkret_canonical::canonical_sha256(&endpoint).map_err(PersistenceError::database)?;
    for carrier in carriers {
        let EncryptedEnvelopeEncryptionContext::EpochContent {
            content_key_salt,
            root_ref,
            ..
        } = &carrier.envelope.encryption_context;
        let (root, _) = roots
            .get(root_ref.as_str())
            .ok_or_else(|| missing("primary root is missing"))?;
        if root.epoch != group.epoch || root.group_state_ref != group.current_mls_commit_event_ref {
            return Err(
                invalid("primary content root is not the current accepted MLS result").into(),
            );
        }
        let context = ContentContext {
            root_context: root.clone(),
            root_ref: root_ref.clone(),
            purpose: arkret_models_crypto::ContentPurpose::EventBody,
            encryption_scheme: carrier.envelope.encryption_scheme,
            encryption_algorithm: arkret_models_crypto::ContentEncryptionAlgorithm::Aes128Gcm,
            producer: endpoint.clone(),
            content_key_salt: content_key_salt.clone(),
        };
        context
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        let value = serde_json::to_value(&context).map_err(PersistenceError::database)?;
        sql_query("INSERT INTO content_key_domains(root_ref,producer_digest,purpose,content_key_salt,event_id,content_path,content_context) VALUES($1,$2,'event_body',$3,$4,$5,$6) ON CONFLICT(root_ref,producer_digest,purpose,content_key_salt) DO NOTHING")
            .bind::<Text,_>(root_ref.as_str()).bind::<Text,_>(&producer_digest).bind::<Text,_>(content_key_salt)
            .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(&carrier.content_path).bind::<Jsonb,_>(&value)
            .execute(&mut *conn).await?;
        let winner = sql_query("SELECT event_id,content_path,content_context FROM content_key_domains WHERE root_ref=$1 AND producer_digest=$2 AND purpose='event_body' AND content_key_salt=$3 FOR SHARE")
            .bind::<Text,_>(root_ref.as_str()).bind::<Text,_>(&producer_digest).bind::<Text,_>(content_key_salt)
            .get_result::<DomainRow>(&mut *conn).await?;
        if winner.event_id != event.event_id.as_str()
            || winner.content_path != carrier.content_path
            || winner.content_context != value
        {
            return Err(invalid(
                "content key and nonce domain is already bound to another immutable intent",
            )
            .into());
        }
    }
    Ok(())
}

async fn freeze_coverage(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    coverage: &ContentCoverageEntry,
    retain_full_history: bool,
) -> Result<(), PgTransactionError> {
    let event = &transaction.event;
    let inserted = sql_query("INSERT INTO content_originals(event_id,event_pk,commit_id,scope_key,coverage,retain_full_history) SELECT $1,e.pk,c.commit_id,$3,$4,$5 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND c.commit_id=$2 AND e.state='committed'")
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(transaction.commit.commit_id.as_str())
        .bind::<Text,_>(crate::mls_group_current_states::scope_key(&event.scope_ref)?)
        .bind::<Jsonb,_>(serde_json::to_value(coverage).map_err(PersistenceError::database)?)
        .bind::<diesel::sql_types::Bool,_>(retain_full_history).execute(&mut *conn).await?;
    if inserted != 1 {
        return Err(missing("coverage has no same-transaction original Commit").into());
    }
    for reference in &coverage.blob_refs {
        // The deferred FK permits a verified MLS material staging record here;
        // its native group unit must install the Blob before transaction end.
        sql_query("INSERT INTO content_original_blobs(event_id,blob_ref) VALUES($1,$2)")
            .bind::<Text, _>(event.event_id.as_str())
            .bind::<Text, _>(reference.as_str())
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

async fn commit_plain_pcr_coverage(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<(), PgTransactionError> {
    let event = &transaction.event;
    let declaration = if event.kind == EventKind::RealmCreate {
        Some(event.clone())
    } else {
        sql_query("SELECT e.envelope AS payload FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.realm_id=$1 AND e.kind='ak.realm.create' AND e.state='committed' ORDER BY c.stream_position LIMIT 1")
            .bind::<Text,_>(event.realm_id.as_str()).get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional()?
            .map(|row| serde_json::from_value::<Event>(row.payload)).transpose().map_err(PersistenceError::database)?
    };
    let Some(declaration) = declaration else {
        return Ok(());
    };
    let purpose = declaration
        .as_realm_create()
        .map_err(|error| invalid(error.to_string()))?
        .object
        .purpose;
    if !matches!(
        purpose,
        RealmPurpose::PrincipalControl | RealmPurpose::AgentControl
    ) {
        return Ok(());
    }
    let mut blobs = BTreeMap::new();
    match event.kind {
        EventKind::MlsGenesis => {
            let payload = event
                .as_mls_genesis()
                .map_err(|error| invalid(error.to_string()))?;
            for reference in [payload.group_info_ref, payload.ratchet_tree_ref] {
                blobs.insert(reference.to_string(), reference);
            }
        }
        EventKind::MlsCommit => {
            let payload = event
                .as_mls_commit()
                .map_err(|error| invalid(error.to_string()))?;
            for reference in [
                payload.group_info_ref().clone(),
                payload.ratchet_tree_ref().clone(),
            ] {
                blobs.insert(reference.to_string(), reference);
            }
        }
        EventKind::ProfileCreate => {
            if let Some(reference) = event
                .as_profile_create()
                .map_err(|error| invalid(error.to_string()))?
                .object
                .avatar_blob_ref
            {
                let reference = arkret_wire::BlobRef::new(reference.to_string())
                    .map_err(|error| invalid(error.to_string()))?;
                blobs.insert(reference.to_string(), reference);
            }
        }
        EventKind::ProfileUpdate => {
            let payload = event
                .as_profile_update()
                .map_err(|error| invalid(error.to_string()))?;
            for (path, operation) in payload.patch.iter() {
                let path = arkret_wire::patch::parse_object_path(path)
                    .map_err(|error| invalid(error.to_string()))?;
                if path.as_slice() == ["avatar_blob_ref"]
                    && operation.op() == arkret_wire::patch::PatchOpKind::Set
                    && let Some(value) = operation.value().filter(|value| !value.is_null())
                {
                    let reference: arkret_wire::BlobRef = serde_json::from_value(value.clone())
                        .map_err(PersistenceError::database)?;
                    blobs.insert(reference.to_string(), reference);
                }
            }
        }
        _ => {}
    }
    for reference in blobs.values() {
        let present =
            sql_query("SELECT payload FROM blobs WHERE id=$1 AND redacted=false FOR SHARE")
                .bind::<Text, _>(reference.as_str())
                .get_result::<crate::JsonPayloadRow>(&mut *conn)
                .await
                .optional()?
                .is_some();
        let staged = transaction.mls_state.as_ref().is_some_and(|state| {
            state
                .public_blobs
                .iter()
                .any(|blob| &blob.blob_ref == reference)
        });
        if !present && !staged {
            return Err(missing("PCR original references an unavailable durable Blob").into());
        }
    }
    let coverage = ContentCoverageEntry {
        source: CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: transaction.commit.commit_id.clone(),
            stream_ref: transaction.commit.stream_ref.clone(),
            stream_position: transaction.commit.stream_position,
        },
        root_refs: vec![],
        blob_refs: blobs.into_values().collect(),
    };
    freeze_coverage(conn, transaction, &coverage, true).await
}

/// Policy publication precedes the actor-series/body locks in every writer.
/// Merely locking does not assert that an old envelope's recipient is current.
async fn lock_recipient_policy(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
) -> Result<(), PgTransactionError> {
    let subject = backup
        .custodian_actor_id
        .as_ref()
        .unwrap_or(&backup.actor_id);
    let account = subject
        .as_account_id()
        .ok_or_else(|| missing("root custodian has no full Account policy"))?;
    crate::pcr_recovery_policy_unit::current_policy(conn, account).await?;
    Ok(())
}

/// Ordinary delete/series erase must leave a previously admitted sufficient
/// package for every original root. The immutable original reference itself is
/// never rewritten; matching retained R/context is the replacement mapping.
pub(crate) async fn guard_delete_in_connection(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
) -> Result<(), PgTransactionError> {
    if backup
        .contents
        .iter()
        .any(|item| item.item_kind == SecretStorageItemKind::ContentEpochRoot)
    {
        lock_recipient_policy(conn, backup).await?;
    }
    crate::key_backup::lock_backup_series_in_connection(conn, &backup.actor_id).await?;
    if backup
        .contents
        .iter()
        .any(|item| item.item_kind == SecretStorageItemKind::ContentEpochRoot)
    {
        let source = sql_query("SELECT writer_admission AS payload FROM key_backup_identities WHERE id=$1 AND deleted_at IS NULL FOR SHARE")
            .bind::<diesel::sql_types::Uuid,_>(crate::ids::typed_uuid_part_expect_internal(backup.backup_id.as_str()))
            .get_result::<crate::JsonPayloadRow>(&mut *conn).await?;
        let admission: crate::key_backup_authority::DeviceBackupAdmission =
            serde_json::from_value(source.payload).map_err(PersistenceError::database)?;
        admission.verify_retained_envelope(backup)?;
    }
    for item in &backup.contents {
        if item.item_kind != SecretStorageItemKind::ContentEpochRoot {
            continue;
        }
        let (Some(root), Some(context)) = (&item.root_ref, &item.root_context) else {
            return Err(invalid("root package has an incomplete public index").into());
        };
        let context_json = serde_json::to_value(context).map_err(PersistenceError::database)?;
        let dependent = sql_query("SELECT root_context AS payload FROM content_original_roots WHERE backup_actor_id=$1 AND root_ref=$2 AND root_context=$3 LIMIT 1")
            .bind::<Text,_>(backup.actor_id.to_string()).bind::<Text,_>(root.as_str()).bind::<Jsonb,_>(&context_json)
            .get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional()?;
        if dependent.is_none() {
            continue;
        }
        let selector = serde_json::json!([{"item_kind":"content_epoch_root","root_ref":root,"root_context":context}]);
        let mut after = uuid::Uuid::nil();
        let mut sufficient = false;
        // This is bounded storage pagination, never the ordinary 64-object
        // download allowance. Arbitrarily many compacted packages remain valid.
        loop {
            #[derive(QueryableByName)]
            struct Candidate {
                #[diesel(sql_type=diesel::sql_types::Uuid)]
                id: uuid::Uuid,
            }
            let page = sql_query("SELECT b.id FROM key_backups b JOIN key_backup_identities i ON i.id=b.id WHERE b.actor_id=$1 AND b.id<>$2 AND b.id>$3 AND i.deleted_at IS NULL AND i.content_index @> $4 ORDER BY b.id LIMIT 64 FOR SHARE OF b,i")
                .bind::<Text,_>(backup.actor_id.to_string())
                .bind::<diesel::sql_types::Uuid,_>(crate::ids::typed_uuid_part_expect_internal(backup.backup_id.as_str()))
                .bind::<diesel::sql_types::Uuid,_>(after).bind::<Jsonb,_>(&selector)
                .get_results::<Candidate>(&mut *conn).await?;
            let final_page = page.len() < 64;
            for candidate in page {
                after = candidate.id;
                let id = arkret_wire::BackupId::new(format!("ak:backup:{}", candidate.id))
                    .map_err(|error| invalid(error.to_string()))?;
                let replacement = crate::content_root_packages::read_in_connection(
                    conn,
                    &id,
                    &[root.as_str().to_owned()],
                )
                .await?;
                if replacement
                    .expires_at
                    .is_some_and(|expiry| expiry <= chrono::Utc::now())
                {
                    continue;
                }
                if !replacement
                    .roots
                    .iter()
                    .any(|(reference, basis)| reference == root && basis == context)
                {
                    continue;
                }
                match replacement.require_current_recipient(conn).await {
                    Ok(()) => {
                        sufficient = true;
                        break;
                    }
                    Err(PgTransactionError::Storage(PersistenceError::Conflict(_))) => {}
                    Err(error) => return Err(error),
                }
            }
            if sufficient || final_page {
                break;
            }
        }
        if !sufficient {
            return Err(missing("ordinary deletion would remove the last sufficient current-recipient content root package").into());
        }
    }
    Ok(())
}
