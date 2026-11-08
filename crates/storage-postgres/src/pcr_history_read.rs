//! Own-Human PCR originals under the native current-device cut.

use arkret_wire::{CommitStreamRef, CommittedEventView, GenesisGovernance, ScopeRef};
use coland_storage::{
    AccountContentDeliveryGuard, HumanPcrHistoryRead, HumanPcrHistoryReader, PersistenceError,
    PersistenceResult,
};
use diesel::sql_query;
use diesel::sql_types::Text;
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::account_content_delivery::DeliveryGuard;
use crate::{AsyncPgConnection, PgPool};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("revision_unavailable: {detail}"))
}

struct HistoryGuard {
    held: Box<DeliveryGuard>,
    checked_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait::async_trait]
impl AccountContentDeliveryGuard for HistoryGuard {
    fn permits_handoff(&self) -> bool {
        let now = chrono::Utc::now();
        self.checked_at <= now && now < self.expires_at
    }

    async fn prepare_handoff(&mut self) -> bool {
        self.held.probe().await.is_ok() && self.permits_handoff()
    }

    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }
}

/// Potential ownership only routes the request. An unverified inception that
/// claims this Account never falls back to an ordinary membership/author read.
async fn own_control_origin(
    conn: &mut AsyncPgConnection,
    reader: &HumanPcrHistoryReader,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<bool> {
    // The accepted Account binding still identifies a PCR whose inception
    // original is damaged. Route it into native qualification so a missing
    // original can never reopen the ordinary author/membership fallback.
    let bound = sql_query("SELECT to_jsonb(p) AS payload FROM principal_resolutions p WHERE p.pcr_realm_id=$1 AND p.principal_id=$2 AND p.station_id=$3 LIMIT 1")
        .bind::<Text, _>(realm.as_str())
        .bind::<Text, _>(reader.account_id.principal_id.as_str())
        .bind::<Text, _>(reader.account_id.station_id.as_str())
        .get_result::<crate::JsonPayloadRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?;
    if bound.is_some() {
        return Ok(true);
    }
    let original = sql_query("SELECT e.envelope AS payload FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text) AND c.stream_position=0 AND e.kind='ak.realm.create' AND e.state='committed'")
        .bind::<Text,_>(realm.as_str()).get_result::<crate::JsonPayloadRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?;
    let Some(original) = original else {
        return Ok(false);
    };
    let event: arkret_wire::Event =
        serde_json::from_value(original.payload).map_err(PersistenceError::database)?;
    let origin = GenesisGovernance::from_genesis(&event).map_err(unavailable)?;
    Ok(origin.is_principal_control() && event.actor_id.as_account_id() == Some(&reader.account_id))
}

pub(crate) async fn qualify(
    conn: &mut AsyncPgConnection,
    reader: &HumanPcrHistoryReader,
    realm: &arkret_wire::RealmId,
    station: &arkret_wire::DidCoreId,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    let authority = crate::authority_commit::locked_authority(conn, realm)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
        .ok_or_else(|| unavailable("PCR archive authority is absent"))?;
    let origin = crate::pcr_private_authority::accepted_governance(conn, realm).await?;
    if !matches!(&origin, GenesisGovernance::Human(account) if account == &reader.account_id)
        || &reader.account_id.station_id != station
    {
        return Err(unavailable(
            "PCR archive has no exact accepted Human Account origin",
        ));
    }
    origin
        .validate_current(&authority.service_id, authority.generation)
        .map_err(unavailable)?;
    if &authority.service_id != station {
        return Err(unavailable(
            "PCR archive is not governed by the owning Station",
        ));
    }
    crate::morph_projection_reads::require_current_human_account(
        conn,
        &reader.account_id,
        realm,
        station,
        reader.account_status_observation.as_ref(),
    )
    .await?;
    let now = chrono::Utc::now();
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &reader.account_id,
        &reader.device_id,
        now,
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| unavailable("PCR archive reader has no native device status"))?;
    if cut.authority.realm_id != *realm
        || cut.admission() != arkret_wire::AccountDeviceRevocationAdmissionDecision::Allow
    {
        return Err(unavailable(
            "PCR archive reader is not a current accepted device",
        ));
    }
    let authorization = cut
        .authority
        .authorization
        .ok_or_else(|| unavailable("PCR archive reader authorization is absent"))?;
    let binding = reader
        .credential_device_binding
        .as_ref()
        .ok_or_else(|| unavailable("PCR archive credential has no original device binding"))?;
    if binding.device_id != reader.device_id
        || binding.authorization_event_id != authorization.event_id
        || Some(binding.model_generation_ref) != cut.authority.current_generation
    {
        return Err(unavailable(
            "PCR archive credential device binding is no longer current",
        ));
    }
    let mut expiry = authorization
        .payload
        .expires_at
        .flatten()
        .map_or(reader.credential_expires_at, |expiry| {
            expiry.min(reader.credential_expires_at)
        });
    if let Some(status_expiry) = reader
        .account_status_observation
        .as_ref()
        .and_then(|observation| observation.record().expires_at)
    {
        expiry = expiry.min(status_expiry);
    }
    if expiry <= now {
        return Err(unavailable("PCR archive reader credential expired"));
    }
    Ok(expiry)
}

pub(crate) async fn page(
    pool: &PgPool,
    reader: &HumanPcrHistoryReader,
    request: &arkret_wire::StreamScanRequestBody,
    station: &arkret_wire::DidCoreId,
) -> PersistenceResult<HumanPcrHistoryRead<arkret_wire::StreamScanResponseBody>> {
    request.validate().map_err(unavailable)?;
    let mut held = DeliveryGuard::begin(pool).await?;
    if !own_control_origin(held.connection(), reader, &request.realm_id).await? {
        held.finish().await?;
        return Ok(HumanPcrHistoryRead::NotApplicable);
    }
    if request.stream_ref
        != (CommitStreamRef::Realm {
            realm_id: request.realm_id.clone(),
        })
    {
        return Err(unavailable(
            "PCR archive request is outside its original Realm stream",
        ));
    }
    if reader.account_status_observation.is_none() {
        held.finish().await?;
        return Ok(HumanPcrHistoryRead::CurrentStatusRequired);
    }
    let expires_at = qualify(held.connection(), reader, &request.realm_id, station).await?;
    let value =
        crate::authority_commit::stream_page_in_connection(held.connection(), request).await?;
    if value
        .readable_floor
        .as_ref()
        .is_none_or(|floor| floor.oldest_position != 0)
        || value
            .committed_events
            .iter()
            .any(|row| !matches!(row, CommittedEventView::Full(_)))
    {
        return Err(unavailable("PCR archive original prefix is unavailable"));
    }
    held.probe().await?;
    Ok(HumanPcrHistoryRead::Ready {
        value,
        guard: Box::new(HistoryGuard {
            held,
            checked_at: chrono::Utc::now(),
            expires_at,
        }),
    })
}

pub(crate) async fn event(
    pool: &PgPool,
    reader: &HumanPcrHistoryReader,
    event_id: &arkret_wire::EventId,
    station: &arkret_wire::DidCoreId,
) -> PersistenceResult<HumanPcrHistoryRead<CommittedEventView>> {
    let mut held = DeliveryGuard::begin(pool).await?;
    let Some(original) =
        crate::committed_disclosure::accepted_full_event_in_connection(held.connection(), event_id)
            .await?
    else {
        held.finish().await?;
        return Ok(HumanPcrHistoryRead::NotApplicable);
    };
    let realm = original.event.realm_id.clone();
    if !own_control_origin(held.connection(), reader, &realm).await? {
        held.finish().await?;
        return Ok(HumanPcrHistoryRead::NotApplicable);
    }
    if original.commit.stream_ref
        != (CommitStreamRef::Realm {
            realm_id: realm.clone(),
        })
        || !matches!(
            original.event.scope_ref,
            ScopeRef::RealmGenesis | ScopeRef::Realm { .. }
        )
    {
        return Err(unavailable(
            "PCR archive original has an invalid control scope",
        ));
    }
    if reader.account_status_observation.is_none() {
        held.finish().await?;
        return Ok(HumanPcrHistoryRead::CurrentStatusRequired);
    }
    let expires_at = qualify(held.connection(), reader, &realm, station).await?;
    held.probe().await?;
    Ok(HumanPcrHistoryRead::Ready {
        value: CommittedEventView::Full(original),
        guard: Box::new(HistoryGuard {
            held,
            checked_at: chrono::Utc::now(),
            expires_at,
        }),
    })
}
