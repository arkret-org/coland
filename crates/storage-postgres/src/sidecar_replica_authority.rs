//! Private native stream authority is derived from accepted Sidecar ownership.
//! It never opens a stream on the basis of a Circle or parent Realm join alone.
use arkret_wire::{CommitStreamRef, DidCoreId, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::QueryableByName;
use diesel::sql_types::Jsonb;
use horme::{OptionalExtension, RunQueryDsl};

#[derive(QueryableByName)]
struct Owner {
    #[diesel(sql_type = Jsonb)]
    controller: serde_json::Value,
}

/// The surrounding replica transaction locks its native head and establishes
/// the source Realm authority. This proof is additional private read authority,
/// not an alternative source ordering or governance proof.
pub(crate) async fn permits_in_connection(
    conn: &mut crate::AsyncPgConnection,
    commit: &RealmCommit,
    local_station: &DidCoreId,
) -> PersistenceResult<bool> {
    let CommitStreamRef::Sidecar {
        realm_id,
        sidecar_id,
    } = &commit.stream_ref
    else {
        return Ok(false);
    };
    if realm_id != &commit.realm_id {
        return Ok(false);
    }
    holds_source_in_connection(conn, realm_id, sidecar_id, local_station).await
}

pub(crate) async fn holds_source_in_connection(
    conn: &mut crate::AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    sidecar_id: &arkret_wire::SidecarId,
    local_station: &DidCoreId,
) -> PersistenceResult<bool> {
    holds_source_at_cut(conn, realm_id, sidecar_id, local_station, true).await
}

pub(crate) async fn holds_source_at_cut(
    conn: &mut crate::AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    sidecar_id: &arkret_wire::SidecarId,
    local_station: &DidCoreId,
    lock_rows: bool,
) -> PersistenceResult<bool> {
    let lock = if lock_rows { " FOR SHARE" } else { "" };
    let owner = diesel::sql_query(format!(
        "SELECT controller_account_id AS controller FROM sidecar_current_states \
        WHERE realm_id=$1 AND sidecar_id=$2 AND value->>'state'='active'{lock}",
    ))
    .bind::<diesel::sql_types::Text, _>(realm_id.as_str())
    .bind::<diesel::sql_types::Text, _>(sidecar_id.as_str())
    .get_result::<Owner>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(owner) = owner else {
        return Ok(false);
    };
    let controller: arkret_wire::AccountId =
        serde_json::from_value(owner.controller).map_err(PersistenceError::database)?;
    // Full Account identity, including its Station, owns the private source.
    // Parent membership or an identically spelled principal elsewhere cannot
    // make that other Station a replication recipient.
    if &controller.station_id != local_station {
        return Ok(false);
    }
    Ok(
        crate::sidecar_authority_cut::in_connection(conn, realm_id, sidecar_id, &controller)
            .await?
            .is_some(),
    )
}

pub(crate) async fn controller_in_connection(
    conn: &mut crate::AsyncPgConnection,
    stream: &CommitStreamRef,
) -> PersistenceResult<Option<serde_json::Value>> {
    let CommitStreamRef::Sidecar {
        realm_id,
        sidecar_id,
    } = stream
    else {
        return Ok(None);
    };
    Ok(diesel::sql_query("SELECT controller_account_id AS controller FROM sidecar_current_states WHERE realm_id=$1 AND sidecar_id=$2")
        .bind::<diesel::sql_types::Text,_>(realm_id.as_str()).bind::<diesel::sql_types::Text,_>(sidecar_id.as_str())
        .get_result::<Owner>(&mut *conn).await.optional().map_err(PersistenceError::database)?.map(|row|row.controller))
}

#[derive(QueryableByName)]
struct Origin {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

pub(crate) async fn floor_in_connection(
    conn: &mut crate::AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    sidecar: &arkret_wire::SidecarId,
    caller: &arkret_wire::ActorId,
) -> PersistenceResult<Result<Option<arkret_wire::ReadableFloor>, &'static str>> {
    let Some(floor) =
        crate::sidecar_authority_cut::caller_floor_in_connection(conn, realm, sidecar, caller)
            .await?
    else {
        return Ok(Ok(None));
    };
    prove_floor_in_connection(conn, realm, sidecar, floor).await
}

/// Welcome verification uses the same held replica proof, with a restricted
/// handshake interval when the desired recipient has not consumed it yet.
pub(crate) async fn handshake_floor_in_connection(
    conn: &mut crate::AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    sidecar: &arkret_wire::SidecarId,
    caller: &arkret_wire::ActorId,
) -> PersistenceResult<Result<Option<arkret_wire::ReadableFloor>, &'static str>> {
    let Some(floor) = crate::sidecar_authority_cut::public_material_floor_in_connection(
        conn, realm, sidecar, caller,
    )
    .await?
    else {
        return Ok(Ok(None));
    };
    prove_floor_in_connection(conn, realm, sidecar, floor).await
}

async fn prove_floor_in_connection(
    conn: &mut crate::AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    sidecar: &arkret_wire::SidecarId,
    floor: arkret_wire::ReadableFloor,
) -> PersistenceResult<Result<Option<arkret_wire::ReadableFloor>, &'static str>> {
    let stream = CommitStreamRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let key = crate::authority_commit::stream_key(&stream)?;
    let origin=diesel::sql_query("SELECT EXISTS(SELECT 1 FROM replica_stream_anchors a JOIN realm_commits first ON first.commit_id=a.join_commit_id \
        WHERE a.stream_key=$1 AND a.realm_id=$2 AND first.stream_key=a.stream_key AND first.stream_position=0 \
        AND first.previous_commit_ref IS NULL AND a.anchor_commit_id IS NOT NULL \
        AND NOT EXISTS(SELECT 1 FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
          WHERE c.stream_key=a.stream_key AND (e.pk IS NULL OR e.envelope->>'event_id' IS DISTINCT FROM c.commit_json->>'event_ref' \
            OR e.envelope->'scope_ref' IS DISTINCT FROM c.stream_ref)) \
        AND (SELECT COUNT(*) FROM realm_commits c WHERE c.stream_key=a.stream_key)=(SELECT MAX(c.stream_position)+1 FROM realm_commits c WHERE c.stream_key=a.stream_key)) AS present")
        .bind::<diesel::sql_types::Text,_>(key).bind::<diesel::sql_types::Text,_>(realm.as_str()).get_result::<Origin>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !origin.present {
        return Ok(Err(
            "the private Sidecar origin and complete held chain are not proved",
        ));
    }
    Ok(Ok(Some(floor)))
}

/// A first private native Commit starts the stream at its own origin. It is
/// never a later membership join allowed to skip undisclosed history.
pub(crate) fn is_native_origin(commit: &RealmCommit) -> bool {
    matches!(commit.stream_ref, CommitStreamRef::Sidecar { .. })
        && commit.stream_position == 0
        && commit.previous_commit_ref.is_none()
}
