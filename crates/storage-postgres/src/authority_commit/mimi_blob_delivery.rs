//! Public native assets remain bound to accepted Room and current privacy facts.
use arkret_models_collaboration::events_payloads::mimi::{
    MimiLocalProviderRole, MimiRoomBindingStatus,
};
use arkret_models_collaboration::governance::realm_lifecycle::{
    AssetDownloadMode, RealmAssetPrivacyPolicyValue,
};
use arkret_models_collaboration::objects::blob::BlobVisibility;
use arkret_wire::{
    BlobRef, CommittedEventView, DidCoreId, EventKind, MimiRoomUri, ScopeRef, StrandId,
};
use coland_storage::{AccountContentDeliveryGuard, BlobRecord};

use super::*;

fn unavailable() -> PersistenceError {
    PersistenceError::Conflict("capability_denied: MIMI public asset is unavailable".into())
}

struct Guard {
    held: Box<crate::account_content_delivery::DeliveryGuard>,
}

#[async_trait::async_trait]
impl AccountContentDeliveryGuard for Guard {
    fn permits_handoff(&self) -> bool {
        true
    }
    async fn prepare_handoff(&mut self) -> bool {
        self.held.probe().await.is_ok()
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }
}

async fn binding(
    conn: &mut AsyncPgConnection,
    room: &MimiRoomUri,
) -> PersistenceResult<coland_storage::MimiRoomBindingCurrentRecord> {
    sql_query(MIMI_BINDING_CURRENT_SQL)
        .bind::<Text, _>(room.as_str())
        .get_result::<MimiRoomBindingStorageRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_mimi_room_binding_current)
        .transpose()?
        .ok_or_else(unavailable)
}

pub(super) async fn acquire(
    pool: &PgPool,
    station: &DidCoreId,
    provider: &DidCoreId,
    room: &MimiRoomUri,
    strand: &StrandId,
    reference: &BlobRef,
) -> PersistenceResult<(BlobRecord, Box<dyn AccountContentDeliveryGuard>)> {
    let mut held = crate::account_content_delivery::DeliveryGuard::begin(pool).await?;
    let first = binding(held.connection(), room).await?;
    let realm = first.realm_id;
    crate::realm_authorization_cut::lock_realm_authorization_cut(held.connection(), &realm).await?;
    let current = binding(held.connection(), room).await?;
    let value = &current.current.value;
    if current.realm_id != realm
        || value.binding_scope.realm_id != realm
        || &value.binding_scope.strand_id != strand
        || value.status != MimiRoomBindingStatus::Accepted
        || !matches!(
            value.local_provider_role,
            MimiLocalProviderRole::Hub | MimiLocalProviderRole::Follower
        )
        || !(provider == &value.hub_provider_id
            || value
                .follower_provider_ids
                .as_ref()
                .is_some_and(|members| members.contains(provider)))
    {
        return Err(unavailable());
    }
    #[derive(QueryableByName)]
    struct TextRow {
        #[diesel(sql_type=Text)]
        value: String,
    }
    let governor = sql_query("SELECT service_id AS value FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<TextRow>(held.connection())
        .await
        .map_err(PersistenceError::database)?;
    if governor.value != station.as_str() {
        return Err(unavailable());
    }
    let scope =
        crate::strand_current_states::locked_active_strand_scope(held.connection(), &realm, strand)
            .await?;
    if scope
        != (ScopeRef::Realm {
            realm_id: realm.clone(),
        })
    {
        return Err(unavailable());
    }
    #[derive(QueryableByName)]
    struct JsonRow {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    // The serving node is the current governor and holds its Realm lock. The
    // original Event and covering Commit must prove this exact current value.
    let policy=sql_query("SELECT r.value FROM realm_bootstrap_current_states r JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND r.state_family='realm_asset_privacy_policy' AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',r.realm_id) AND e.state='committed' AND e.kind='ak.realm.asset_privacy_policy' AND e.envelope->'payload'->'value'=r.value")
        .bind::<Text,_>(realm.as_str()).get_result::<JsonRow>(held.connection()).await.optional().map_err(PersistenceError::database)?.ok_or_else(unavailable)?;
    let policy: RealmAssetPrivacyPolicyValue =
        serde_json::from_value(policy.value).map_err(PersistenceError::database)?;
    if !public_direct_policy(&policy) {
        return Err(unavailable());
    }
    let genesis = crate::committed_disclosure::accepted_full_event_in_connection(
        held.connection(),
        &realm.event_id(),
    )
    .await?
    .ok_or_else(unavailable)?;
    if coland_domain::kinds::payload_declares_minimal_metadata_realm(
        &serde_json::to_value(&genesis.event.payload).map_err(PersistenceError::database)?,
    ) {
        return Err(unavailable());
    }
    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type=Bool)]
        present: bool,
    }
    let terminal=sql_query("SELECT EXISTS(SELECT 1 FROM realm_bootstrap_current_states WHERE realm_id=$1 AND state_family='realm_tombstone') AS present")
        .bind::<Text,_>(realm.as_str()).get_result::<Present>(held.connection()).await.map_err(PersistenceError::database)?;
    if terminal.present {
        return Err(unavailable());
    }
    let binding_original = crate::committed_disclosure::accepted_full_event_in_connection(
        held.connection(),
        &current.source_event_id,
    )
    .await?
    .ok_or_else(unavailable)?;
    if binding_original.event.kind != EventKind::MimiRoomBinding
        || binding_original.event.realm_id != realm
        || binding_original.commit.commit_id != current.current.revision.commit_id
        || serde_json::to_value(&binding_original.event.payload)
            .map_err(PersistenceError::database)?
            != serde_json::to_value(value).map_err(PersistenceError::database)?
    {
        return Err(unavailable());
    }
    let blob = crate::blobs::blob_for_delivery_in_connection(held.connection(), reference)
        .await?
        .ok_or_else(unavailable)?;
    if blob.visibility != BlobVisibility::Public
        || blob.realm_id.is_some()
        || blob.encryption.is_some()
        || blob.legal_hold
        || blob.redacted
    {
        return Err(unavailable());
    }
    let source=sql_query("SELECT e.envelope AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND e.state='committed' AND e.kind='ak.message.create' AND e.envelope->'payload'->>'strand_id'=$2 AND e.envelope->'payload'->'blob_refs' ? $3 ORDER BY c.stream_position DESC,c.commit_id LIMIT 1")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(strand.as_str()).bind::<Text,_>(reference.as_str())
        .get_result::<JsonRow>(held.connection()).await.optional().map_err(PersistenceError::database)?.ok_or_else(unavailable)?;
    let event: arkret_wire::Event =
        serde_json::from_value(source.value).map_err(PersistenceError::database)?;
    let original = crate::committed_disclosure::accepted_full_event_in_connection(
        held.connection(),
        &event.event_id,
    )
    .await?
    .ok_or_else(unavailable)?;
    let payload = event
        .typed_payload::<arkret_wire::event_spec::MessageCreate>()
        .map_err(PersistenceError::database)?;
    if event.kind != EventKind::MessageCreate
        || event.realm_id != realm
        || event.scope_ref != scope
        || payload.strand_id != *strand
        || !payload
            .blob_refs
            .iter()
            .any(|value| value == reference.as_str())
    {
        return Err(unavailable());
    }
    if !matches!(
        crate::committed_disclosure::disclose_in_connection(held.connection(), vec![original])
            .await?
            .as_slice(),
        [CommittedEventView::Full(_)]
    ) {
        return Err(unavailable());
    }
    Ok((blob, Box::new(Guard { held })))
}

fn public_direct_policy(policy: &RealmAssetPrivacyPolicyValue) -> bool {
    policy.direct_download_allowed == Some(true)
        && policy.download_mode == Some(AssetDownloadMode::Direct)
        && (policy.allowed_modes.is_empty()
            || policy.allowed_modes.contains(&AssetDownloadMode::Direct))
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn public_bearer_issuance_never_downgrades_a_private_download_mode_or_missing_permission() {
        let parse = |value| serde_json::from_value::<RealmAssetPrivacyPolicyValue>(value).unwrap();
        assert!(public_direct_policy(&parse(serde_json::json!({
            "download_mode":"direct","direct_download_allowed":true
        }))));
        for value in [
            serde_json::json!({}),
            serde_json::json!({"direct_download_allowed":true}),
            serde_json::json!({"download_mode":"direct"}),
            serde_json::json!({"download_mode":"direct","direct_download_allowed":false}),
            serde_json::json!({"download_mode":"provider_proxy","direct_download_allowed":true}),
            serde_json::json!({"download_mode":"ohttp_relay","direct_download_allowed":true}),
            serde_json::json!({"download_mode":"client_mirror","direct_download_allowed":true}),
            serde_json::json!({"download_mode":"direct","direct_download_allowed":true,"allowed_modes":["provider_proxy"]}),
        ] {
            assert!(!public_direct_policy(&parse(value)));
        }
    }
}
