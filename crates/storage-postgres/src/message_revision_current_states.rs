//! The bounded `message_revision` writers at the accepting RealmCommit cut.
//!
//! Supported create carriers are plaintext or MLS ciphertext Messages under
//! the same-cut send gate, in an active discussion Strand of the exact Realm
//! or Circle source stream, by a joined author the same-cut evaluator admits
//! for `ak.message.create`. Other Message forms remain closed.
//!
//! `ak.message.revise` replaces the chain's current carrier with the same text
//! body gate; the target, its creation history and the edit authority are read
//! under the Realm authority lock, and redaction lives in its own
//! `object_redaction` family (`crate::object_redaction_current_states`).

use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct RootRow {
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: Value,
    #[diesel(sql_type = Text)]
    authority_event_ref: String,
}

#[derive(diesel::QueryableByName)]
struct StrandRevisionSourceRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Text)]
    created_event_id: String,
}

#[derive(diesel::QueryableByName)]
struct CurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

fn conflict(detail: &'static str) -> PersistenceError {
    PersistenceError::Conflict(detail.to_owned())
}

fn strand_lifecycle_conflict(code: coland_storage::ConflictCode, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", code.as_str()))
}

/// The bounded text Message body this Station admits: plain or Markdown
/// source without parts or extension members. Mentions use the separate
/// create carrier gate below.
fn plain_text_content(content: Option<&Value>) -> bool {
    let Some(content) = content.and_then(Value::as_object) else {
        return false;
    };
    content
        .keys()
        .all(|key| matches!(key.as_str(), "kind" | "format" | "body"))
        && content.get("kind") == Some(&Value::String("ak.content.text".to_owned()))
        && content
            .get("format")
            .is_none_or(|format| format == "plain" || format == "markdown")
        && content.get("body").is_some_and(Value::is_string)
}

fn supported_plain_text(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    object.keys().all(|key| {
        matches!(
            key.as_str(),
            "strand_id"
                | "track_name"
                | "content"
                | "blob_refs"
                | "reply_to_id"
                | "poll_response_heads"
        )
    }) && object.contains_key("strand_id")
        && object.get("track_name") == Some(&Value::String("discussion".to_owned()))
        && object.get("content").is_some_and(|content| {
            plain_text_content(Some(content))
                || content.as_object().is_some_and(|content| {
                    content
                        .keys()
                        .all(|key| matches!(key.as_str(), "kind" | "format" | "body" | "mentions"))
                        && content
                            .get("kind")
                            .is_some_and(|kind| kind == "ak.content.text")
                        && content
                            .get("format")
                            .is_none_or(|format| format == "plain" || format == "markdown")
                        && content.get("body").is_some_and(Value::is_string)
                })
        })
}

#[cfg(test)]
mod plain_text_format_tests {
    use super::{supported_mls_carrier, supported_plain_text, supported_plain_text_revision};

    #[test]
    fn plain_and_markdown_text_are_accepted_without_admitting_rich_carriers() {
        for content in [
            serde_json::json!({"kind":"ak.content.text","body":"hello"}),
            serde_json::json!({"kind":"ak.content.text","format":"plain","body":"hello"}),
            serde_json::json!({"kind":"ak.content.text","format":"markdown","body":"hello"}),
        ] {
            assert!(supported_plain_text(&serde_json::json!({
                "strand_id":"fixture","track_name":"discussion","content":content.clone()
            })));
            assert!(supported_plain_text_revision(&serde_json::json!({
                "message_id":"fixture","content":content
            })));
        }
        for content in [
            serde_json::json!({"kind":"ak.content.text","format":"html","body":"hello"}),
            serde_json::json!({"kind":"ak.content.text","format":null,"body":"hello"}),
            serde_json::json!({"kind":"ak.content.text"}),
        ] {
            assert!(!supported_plain_text(&serde_json::json!({
                "strand_id":"fixture","track_name":"discussion","content":content.clone()
            })));
            assert!(!supported_plain_text_revision(&serde_json::json!({
                "message_id":"fixture","content":content
            })));
        }
        // Signed attachment refs are routing/reducer metadata in the original
        // MessageCreate payload, not a different content or authority carrier.
        let reference = arkret_wire::BlobRef::from_bytes(b"bounded attachment");
        let mut plain = serde_json::json!({"strand_id":"fixture","track_name":"discussion",
            "content":{"kind":"ak.content.text","body":"attachment"},"blob_refs":[reference]});
        assert!(supported_plain_text(&plain));
        plain["metadata"] = serde_json::json!({"fields":{}});
        assert!(!supported_plain_text(&plain));
        let mut encrypted = serde_json::json!({"strand_id":"fixture","track_name":"discussion",
            "encrypted_content":{},"blob_refs":[reference]});
        assert!(supported_mls_carrier(&encrypted));
        encrypted["attachments"] = serde_json::json!([]);
        assert!(!supported_mls_carrier(&encrypted));
    }
}

/// The Realm-scope MLS carrier: the Strand, the discussion track and the
/// encrypted content with its optional encrypted metadata. Its ciphertext is
/// bound to the scope's current group by the same-cut send gate
/// (`crate::mls_group_current_states::require_mls_send_gate_in_connection`),
/// so no plaintext service policy applies.
fn supported_mls_carrier(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    object.keys().all(|key| {
        matches!(
            key.as_str(),
            "strand_id"
                | "track_name"
                | "encrypted_content"
                | "encrypted_metadata"
                | "blob_refs"
                | "reply_to_id"
        )
    }) && object.contains_key("strand_id")
        && object.contains_key("encrypted_content")
        && object.get("track_name") == Some(&Value::String("discussion".to_owned()))
}

/// A revise carrier of the same text body: the target, the body, and
/// optionally the discussion track and a reason. Metadata, encrypted and MIMI
/// carriers need their own authority cut.
fn supported_plain_text_revision(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    object.keys().all(|key| {
        matches!(
            key.as_str(),
            "message_id" | "content" | "track_name" | "reason"
        )
    }) && object
        .get("track_name")
        .is_none_or(|track| track == &Value::String("discussion".to_owned()))
        && object.get("reason").is_none_or(Value::is_string)
        && plain_text_content(object.get("content"))
}

pub(crate) async fn commit_message_create_current_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MessageCreate {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    require_message_source_stream(event, commit)?;
    if matches!(event.scope_ref, arkret_wire::ScopeRef::Sidecar { .. }) {
        admit_sidecar_message(conn, event, commit).await?;
        let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
        return insert_message_create_current(conn, event, commit, &payload).await;
    }
    let ordinary = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_position=0 AND e.kind='ak.realm.create' \
           AND e.state='committed' AND e.envelope->'payload'->'object'->>'purpose' IN ('collaboration','direct_conversation')) AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !ordinary.present {
        return Err(conflict(
            "Message current writer supports collaboration and Direct Conversation Realms only",
        ));
    }
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let typed: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
        serde_json::from_value(payload.clone())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    // content-types.md §2: blob_refs is signed reducer metadata. Validate its
    // original byte references, then use the same Message send cut below.
    // Referencing an attachment never grants access to the referenced bytes;
    // Blob delivery independently checks its accepted source and current cut.
    for reference in &typed.blob_refs {
        arkret_wire::BlobRef::new(reference.clone()).map_err(|_| {
            PersistenceError::SchemaViolation("Message attachment ref is not a BlobRef".to_owned())
        })?;
        let same_scope = diesel::sql_query(
            "SELECT NOT EXISTS(SELECT 1 FROM realm_actor_blob_uploads WHERE blob_ref=$1 AND effective_scope<>$2) AS present",
        )
        .bind::<Text, _>(reference)
        .bind::<Jsonb, _>(serde_json::json!(event.scope_ref))
        .get_result::<PresentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if !same_scope.present {
            return Err(conflict(
                "Message attachment differs from its immutable upload scope",
            ));
        }
    }
    let mimi = payload.get("mimi_provenance");
    let mut carrier = payload.clone();
    if mimi.is_some() {
        carrier
            .as_object_mut()
            .ok_or_else(|| conflict("invalid MIMI carrier"))?
            .remove("mimi_provenance");
        carrier
            .as_object_mut()
            .expect("object checked")
            .remove("metadata");
    }
    let mls_carrier = supported_mls_carrier(&carrier);
    let poll = crate::poll_state::supported_plaintext_poll(&payload);
    if !mls_carrier && !supported_plain_text(&carrier) && poll.is_none() {
        return Err(conflict("Message carrier needs a dedicated authority cut"));
    }
    let mut attributed = event.clone();
    if let Some(provenance) = mimi {
        attributed.actor_id = serde_json::from_value(
            provenance
                .get("attributed_sender_actor_id")
                .cloned()
                .ok_or_else(|| conflict("MIMI sender missing"))?,
        )
        .map_err(PersistenceError::database)?;
    }
    let admitted_actor = &attributed.actor_id;
    let root = diesel::sql_query(
        "SELECT r.controller_actor_id,r.authority_event_ref FROM realm_authority_root_current_states r \
         JOIN realm_commits c ON c.commit_id=r.current_commit_id \
         WHERE r.realm_id=$1 AND c.realm_id=r.realm_id \
           AND c.stream_position=r.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=r.realm_id \
         FOR SHARE OF r",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| conflict("Message root authority is unavailable"))?;
    let controller: arkret_wire::ActorId = serde_json::from_value(root.controller_actor_id)
        .map_err(|error| {
            PersistenceError::Internal(format!("stored Realm controller is invalid: {error}"))
        })?;
    // capabilities.md §2.2: joining does not grant writing. The same-cut
    // evaluator admits a joined author holding `ak.message.create`, the root
    // controller through its effective `ak.realm.owner`.
    let (cut, accepted_approvals) =
        crate::realm_authorization_cut::authorize_message_create_in_connection(
            conn,
            event,
            &attributed,
            commit,
            prepared,
        )
        .await?;
    if matches!(event.scope_ref, arkret_wire::ScopeRef::Circle { .. }) {
        crate::circle_current_states::require_active_author_in_connection(conn, event, commit)
            .await?;
    }
    // A Direct Conversation Message names its profile authority source,
    // which the profile table already decided at this cut.
    if !cut.is_direct_conversation()
        && event.applet_id.is_none()
        && event.executed_by.is_none()
        && event.authorization_ref.as_ref().is_some_and(|reference| {
            controller != event.actor_id || reference.as_str() != root.authority_event_ref.as_str()
        })
    {
        return Err(conflict(
            "Message authorization ref differs from current Realm root",
        ));
    }
    let member = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM member_state_current_states m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id) AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(admitted_actor.to_string())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !member.present {
        return Err(conflict("Message actor is not a confirmed Realm member"));
    }
    crate::moderation_report_current_states::ensure_scope_member(
        conn,
        &event.realm_id,
        &event.scope_ref,
        admitted_actor,
    )
    .await?;
    require_active_discussion_strand(conn, &event.realm_id, &typed.strand_id, &event.scope_ref)
        .await?;
    if mimi.is_none() {
        crate::message_interactions::require_message_actor(conn, event, commit.committed_at)
            .await?;
    }
    crate::message_interactions::require_poll_content_in_connection(conn, event, commit, &typed)
        .await?;
    crate::message_interactions::require_reply_and_mentions_in_connection(
        conn, event, commit, &typed,
    )
    .await?;
    if !mls_carrier {
        require_plaintext_message_service(conn, &event.realm_id, commit).await?;
    }
    let response = if let Some(poll) = poll
        && crate::poll_state::admit_poll_in_connection(
            conn,
            event,
            commit,
            poll,
            &typed.poll_response_heads,
        )
        .await?
    {
        // A response is an audit Event and a PollState input, never a MessageState.
        true
    } else {
        false
    };
    if !response {
        insert_message_create_current(conn, event, commit, &payload).await?;
    }
    crate::approval_admission::consume_and_audit(
        conn, event, commit, &accepted_approvals,
        &serde_json::json!({"message_create_admission":true,"strand_id":typed.strand_id,"scope_ref":event.scope_ref}),
    ).await
}

async fn insert_message_create_current(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    payload: &Value,
) -> PersistenceResult<()> {
    let message_id = arkret_wire::MessageId::from_event_id(&event.event_id);
    let inserted = diesel::sql_query(
        "INSERT INTO message_revision_current_states \
         (realm_id,message_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(message_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(
        i64::try_from(commit.stream_position)
            .map_err(|_| conflict("invalid Message stream position"))?,
    )
    .bind::<Jsonb, _>(payload)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(conflict("Message revision current result already exists"));
    }
    Ok(())
}

/// Private Messages use the native participant cut, never a parent capability.
/// The source Strand is a placement context; the current carrier stays on the
/// Sidecar stream and is disclosed through that stream's private floor.
async fn admit_sidecar_message(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::message::{
        MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE, MESSAGE_METADATA_MLS_CONTENT_TYPE,
        MessageCreatePayload,
    };
    let arkret_wire::ScopeRef::Sidecar { sidecar_id, .. } = &event.scope_ref else {
        return Err(conflict("private Message requires a native Sidecar scope"));
    };
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    crate::message_interactions::require_message_actor(conn, event, commit.committed_at).await?;
    if event.applet_id.is_some()
        || !crate::sidecar_access::participant_in_connection(
            conn,
            &event.realm_id,
            sidecar_id,
            &event.actor_id,
        )
        .await?
    {
        return Err(conflict(
            "private Message actor is outside the effective Sidecar access set",
        ));
    }
    let payload: MessageCreatePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if payload.content.is_some()
        || payload.metadata.is_some()
        || payload
            .encrypted_content
            .as_ref()
            .is_none_or(|content| content.content_type != MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE)
        || payload
            .encrypted_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.content_type != MESSAGE_METADATA_MLS_CONTENT_TYPE)
        || event.payload.contains_key("mimi_provenance")
    {
        return Err(conflict(
            "private Message requires the registered encrypted carriers",
        ));
    }
    let context = arkret_wire::SidecarContextRef::Strand {
        strand_id: payload.strand_id.clone(),
    };
    let digest =
        arkret_canonical::canonical_sha256(&context).map_err(PersistenceError::database)?;
    let attached = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM sidecar_context_current_states \
         WHERE realm_id=$1 AND sidecar_id=$2 AND context_ref_digest=$3 AND context_ref=$4) AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(sidecar_id.as_str())
    .bind::<Text, _>(&digest)
    .bind::<Jsonb, _>(serde_json::to_value(context).map_err(PersistenceError::database)?)
    .get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !attached.present {
        return Err(conflict("private Message source context is not attached"));
    }
    require_active_strand_track(
        conn,
        &event.realm_id,
        &payload.strand_id,
        &arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        &payload.track_name,
    )
    .await?;
    crate::message_interactions::require_reply_and_mentions_in_connection(
        conn, event, commit, &payload,
    )
    .await?;
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct ServiceIdRow {
    #[diesel(sql_type = Text)]
    value: String,
}

/// The Message's Strand is an active Realm-scope Strand of this Realm whose
/// discussion track is enabled at this cut (`strand-and-message.md` §4).
pub(crate) async fn require_active_discussion_strand(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    strand_id: &arkret_wire::StrandId,
    scope: &arkret_wire::ScopeRef,
) -> PersistenceResult<()> {
    require_active_strand_track(conn, realm_id, strand_id, scope, "discussion").await
}

async fn require_active_strand_track(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    strand_id: &arkret_wire::StrandId,
    scope: &arkret_wire::ScopeRef,
    track_name: &str,
) -> PersistenceResult<()> {
    // Strand identities preserve the creating Event's token. Resolve that
    // immutable source separately from the current value's covering Commit.
    let creating_event =
        arkret_wire::EventIdentityKey::new(strand_id.digest_suite_code(), strand_id.digest_bytes())
            .event_id();
    let stream = message_scope_stream(realm_id, scope)?;
    let strand = diesel::sql_query(
        "SELECT s.value,s.current_stream_position,created.envelope->>'event_id' AS created_event_id \
         FROM strand_current_states s \
         JOIN realm_commits c ON c.commit_id=s.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         JOIN canonical_events created ON created.id=$3 AND created.realm_id=s.realm_id \
         JOIN realm_commits creation ON creation.event_pk=created.pk AND creation.realm_id=s.realm_id \
         WHERE s.realm_id=$1 AND s.strand_id=$2 \
           AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position \
           AND c.stream_ref=$4 \
           AND e.state='committed' AND e.kind IN ('ak.strand.create','ak.strand.update','ak.strand.archive','ak.strand.restore','ak.strand.stage.set') \
           AND created.kind='ak.strand.create' AND created.state='committed' \
           AND creation.stream_ref=c.stream_ref \
           AND creation.stream_position<=c.stream_position \
         FOR SHARE OF s",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(strand_id.as_str())
    .bind::<diesel::sql_types::Binary, _>(creating_event.token_bytes().to_vec())
    .bind::<Jsonb, _>(serde_json::to_value(&stream).map_err(PersistenceError::database)?)
    .get_result::<StrandRevisionSourceRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| conflict("Message target Strand is unavailable"))?;
    let created_event_id = arkret_wire::EventId::new(strand.created_event_id).map_err(|error| {
        PersistenceError::Internal(format!(
            "stored Strand creating Event id is invalid: {error}"
        ))
    })?;
    if &arkret_wire::StrandId::from_event_id(&created_event_id) != strand_id {
        return Err(conflict(
            "Message target Strand identity has no creating Event",
        ));
    }
    let expected_circle = match scope {
        arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str()),
        _ => None,
    };
    match strand.value.get("state").and_then(Value::as_str) {
        Some("active") => {}
        Some("redacted") => {
            return Err(strand_lifecycle_conflict(
                coland_storage::ConflictCode::StrandAlreadyTerminal,
                "Message target Strand is redacted",
            ));
        }
        _ => {
            return Err(strand_lifecycle_conflict(
                coland_storage::ConflictCode::StrandNotActive,
                "Message target Strand is not active",
            ));
        }
    }
    if strand.value.get("scope_circle_id").and_then(Value::as_str) != expected_circle {
        return Err(conflict("Message target Strand is outside the Realm scope"));
    }
    let track = strand
        .value
        .get("tracks")
        .and_then(|tracks| tracks.get(track_name))
        .and_then(Value::as_object)
        .ok_or_else(|| conflict("Message target track is unavailable"))?;
    if track.get("enabled") == Some(&Value::Bool(false)) {
        return Err(conflict("Message target track is disabled"));
    }
    // Unsupported structural or terminal writes still invalidate the proof.
    // Already materialized kinds, including watches on other Strands, do not.
    let changed = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.realm_id=$1 AND e.state='committed' AND c.stream_position>$2 \
           AND c.stream_ref=$3 \
           AND ((e.kind LIKE 'ak.strand.%' AND e.kind NOT IN ('ak.strand.create','ak.strand.update','ak.strand.archive','ak.strand.restore','ak.strand.stage.set','ak.strand.watch.set','ak.strand.move','ak.strand.reorder')) OR e.kind='ak.redaction')) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<BigInt, _>(strand.current_stream_position)
    .bind::<Jsonb, _>(serde_json::to_value(&stream).map_err(PersistenceError::database)?)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed.present {
        return Err(conflict("Message Strand has an unprojected successor"));
    }
    Ok(())
}

fn message_scope_stream(
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
) -> PersistenceResult<arkret_wire::CommitStreamRef> {
    match scope {
        arkret_wire::ScopeRef::Realm { realm_id } if realm_id == realm => {
            Ok(arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            })
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == realm => Ok(arkret_wire::CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        }),
        arkret_wire::ScopeRef::Sidecar {
            realm_id,
            sidecar_id,
        } if realm_id == realm => Ok(arkret_wire::CommitStreamRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        }),
        _ => Err(conflict("Message has no admitted effective scope")),
    }
}

fn require_message_source_stream(
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if message_scope_stream(&event.realm_id, &event.scope_ref)? != commit.stream_ref
        || event.event_id != commit.event_ref
    {
        return Err(conflict("Message differs from its accepting source stream"));
    }
    Ok(())
}

/// This Station is a private plaintext service for message content of the
/// Realm at this cut, so it may hold and serve a plaintext Message body.
async fn require_plaintext_message_service(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let plaintext = diesel::sql_query(
        "SELECT b.value FROM realm_bootstrap_current_states b \
         JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE b.realm_id=$1 AND b.state_family='realm_plaintext_visible_services' \
           AND c.realm_id=b.realm_id AND c.stream_position=b.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=b.realm_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| conflict("Message plaintext service policy is unavailable"))?;
    let service_id = diesel::sql_query(
        "SELECT service_id AS value FROM realm_authorities WHERE realm_id=$1 FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ServiceIdRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let allowed = plaintext
        .value
        .get("services")
        .and_then(Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| {
                service.get("service_id").and_then(Value::as_str) == Some(service_id.value.as_str())
                    && service.get("visibility").and_then(Value::as_str)
                        == Some("private_plaintext")
                    && service
                        .get("data_classes")
                        .and_then(Value::as_array)
                        .is_some_and(|classes| {
                            classes.iter().any(|class| class == "message_content")
                        })
                    && service.get("expires_at").is_none_or(|expires| {
                        expires
                            .as_str()
                            .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
                            .is_some_and(|time| {
                                time.with_timezone(&chrono::Utc) > commit.committed_at
                            })
                    })
            })
        });
    if !allowed {
        return Err(conflict(
            "Message plaintext service is not authorized at this cut",
        ));
    }
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct CreationRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(diesel::QueryableByName)]
struct RevisionRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
}

/// What a revise or redact of one Message reads about its target at the
/// accepting cut: the current carrier's covering Commit, locked for this
/// transaction, and the creation history the Message id retypes to.
pub(crate) struct MessageTarget {
    pub(crate) message_id: arkret_wire::MessageId,
    pub(crate) current_commit_id: String,
    pub(crate) author: arkret_wire::ActorId,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) strand_id: arkret_wire::StrandId,
    pub(crate) scope_ref: arkret_wire::ScopeRef,
}

/// Lock the Message's `message_revision` row and read its creating
/// `ak.message.create`. A Message this Realm never accepted is `not_found`,
/// the same answer for a foreign, unknown or never-created id.
pub(crate) async fn locked_message_target(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    message_id: &arkret_wire::MessageId,
) -> PersistenceResult<MessageTarget> {
    let not_found = || PersistenceError::NotFound("message not found".to_owned());
    let revision = diesel::sql_query(
        "SELECT current_commit_id FROM message_revision_current_states \
         WHERE realm_id=$1 AND message_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(message_id.as_str())
    .get_result::<RevisionRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(not_found)?;
    let create_event_id = message_id.event_id();
    let token = crate::ids::parse_event_id(create_event_id.as_str()).ok_or_else(not_found)?;
    let creation = diesel::sql_query(
        "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.realm_id=$2 AND e.kind='ak.message.create' AND e.state='committed' \
           AND c.realm_id=e.realm_id",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CreationRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::Internal(
            "a message_revision row has no committed creating Event".to_owned(),
        )
    })?;
    let created: arkret_wire::Event =
        serde_json::from_value(creation.envelope).map_err(|error| {
            PersistenceError::Internal(format!("stored Message creating Event is invalid: {error}"))
        })?;
    let payload: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&created.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "stored Message creating payload is invalid: {error}"
            ))
        })?;
    Ok(MessageTarget {
        message_id: message_id.clone(),
        current_commit_id: revision.current_commit_id,
        author: created.actor_id,
        created_at: created.created_at,
        strand_id: payload.strand_id,
        scope_ref: created.scope_ref,
    })
}

/// Whether an `object_redaction` assertion already stands on the Message.
pub(crate) async fn message_is_redacted(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    message_id: &arkret_wire::MessageId,
) -> PersistenceResult<bool> {
    Ok(diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM object_redaction_current_states \
         WHERE realm_id=$1 AND target_ref=$2) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(message_id.as_str())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present)
}

/// The shared carrier rules of a Message revise or redact: a directly
/// authored Realm-scope Event on the Realm stream, outside the MIMI facade
/// branch (whose `service_attested` admission has its own ingress).
pub(crate) fn require_message_write_carrier(
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    require_message_source_stream(event, commit)?;
    if event.payload.contains_key("mimi_provenance") {
        return Err(conflict("Message carrier needs a dedicated authority cut"));
    }
    // A Realm actor's own Device retains its Applet marker. Its native
    // producer guard and Service grant chain are checked by the enclosing
    // unit; the marker must not turn a direct author into a Service proxy.
    if event.executed_by.is_some()
        || (event.applet_id.is_some() && event.actor_id.as_realm_actor_id().is_none())
    {
        return Err(PersistenceError::Conflict(format!(
            "{}: a Message revise or redact must be directly authored by its actor",
            coland_storage::ConflictCode::CapabilityDenied
        )));
    }
    Ok(())
}

/// `ak.message.revise` at the accepting RealmCommit cut
/// (`strand-and-message.md` §9.5.1, registry `state_writes`).
///
/// Under the Realm authority lock the target's `message_revision` row is
/// locked and its creation history read. The actor must be a joined member
/// holding `ak.message.revise`, or the author holding `ak.message.revise.own`
/// inside its edit window; the Message must not be redacted, its Strand must
/// still be an active Realm-scope discussion Strand, and the revise body passes
/// the same plain-text content gate as create. The accepted carrier then
/// replaces the row it locked, so the canonical revision is always the one at
/// the greatest stream position of the chain.
pub(crate) async fn commit_message_revise_current_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MessageRevise {
        return Ok(());
    }
    require_message_write_carrier(event, commit)?;
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let encrypted = payload.get("encrypted_content").is_some()
        && payload.as_object().is_some_and(|object| {
            object.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "message_id"
                        | "track_name"
                        | "reason"
                        | "encrypted_content"
                        | "encrypted_metadata"
                )
            })
        });
    if !encrypted && !supported_plain_text_revision(&payload) {
        return Err(conflict("Message carrier needs a dedicated authority cut"));
    }
    let typed: arkret_models_collaboration::events_payloads::message::MessageRevisePayload =
        serde_json::from_value(payload.clone())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event).await?;
    cut.require_governed_member(&event.kind)?;
    let target = locked_message_target(conn, &event.realm_id, &typed.message_id).await?;
    if target.scope_ref != event.scope_ref {
        return Err(PersistenceError::NotFound("message not found".to_owned()));
    }
    crate::moderation_report_current_states::ensure_scope_member(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &event.actor_id,
    )
    .await?;
    cut.require_authored_target_in_connection(
        conn,
        event,
        &crate::realm_authorization_cut::AuthoredTarget {
            author: &target.author,
            created_at: target.created_at,
            strand_id: &target.strand_id,
        },
        commit,
        prepared,
    )
    .await?;
    crate::message_interactions::require_message_actor(conn, event, commit.committed_at).await?;
    if message_is_redacted(conn, &event.realm_id, &target.message_id).await? {
        return Err(PersistenceError::Conflict(format!(
            "{}: a redacted Message cannot be revised",
            coland_storage::ConflictCode::FailedPrecondition
        )));
    }
    require_active_discussion_strand(conn, &event.realm_id, &target.strand_id, &event.scope_ref)
        .await?;
    if encrypted {
        crate::mls_group_current_states::require_mls_send_gate_in_connection(conn, event).await?;
    } else {
        if matches!(&event.scope_ref, arkret_wire::ScopeRef::Circle { .. }) {
            return Err(conflict(
                "Circle Message revision requires its admitted MLS carrier",
            ));
        }
        require_plaintext_message_service(conn, &event.realm_id, commit).await?;
    }
    let replaced = diesel::sql_query(
        "UPDATE message_revision_current_states SET current_commit_id=$3, \
         current_stream_position=$4, value=$5, updated_at=$6 \
         WHERE realm_id=$1 AND message_id=$2 AND current_commit_id=$7",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(target.message_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(
        i64::try_from(commit.stream_position)
            .map_err(|_| conflict("invalid Message stream position"))?,
    )
    .bind::<Jsonb, _>(&payload)
    .bind::<Timestamptz, _>(commit.committed_at)
    .bind::<Text, _>(&target.current_commit_id)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if replaced != 1 {
        return Err(PersistenceError::Internal(
            "message_revision row changed inside its lock".to_owned(),
        ));
    }
    Ok(())
}
