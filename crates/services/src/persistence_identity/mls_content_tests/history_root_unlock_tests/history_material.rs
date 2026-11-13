//! Native own-PCR public material after a genuine two-Event recovery unit.
//! The fixture retains public Blob metadata; physical HTTP Blob delivery is separate.

use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;
use arkret_wire::ActorId;
use coland_storage::{
    AuthorityCommitStore as _, HumanPcrHistoryRead, HumanPcrHistoryReader,
    MlsMemberGroupStateMaterialRead as Material,
};
use coland_storage_postgres::{PgAuthorityCommitStore, PgPersistenceStore, PgPool};
use diesel::sql_types::{Jsonb, Text};
use horme::RunQueryDsl as _;

pub(super) async fn exercise(
    pool: &PgPool,
    reader: &HumanPcrHistoryReader,
    old_reader: &HumanPcrHistoryReader,
    genesis: &coland_storage::AuthorityCommitTransaction,
) {
    let payload: MlsGenesisPayload =
        serde_json::from_value(serde_json::to_value(&genesis.event.payload).unwrap()).unwrap();
    let request = MlsGroupStateMaterialRequestBody {
        realm_id: genesis.event.realm_id.clone(),
        effective_scope: genesis.event.scope_ref.clone(),
        mls_group_id: payload.mls_group_id().unwrap(),
        epoch: 0,
        group_state_event_id: genesis.event.event_id.clone(),
        caller_actor_id: Some(ActorId::account(reader.account_id.clone())),
        target_commit_event_ref: Some(genesis.event.event_id.clone()),
        target_epoch: Some(0),
        group_info_ref: payload.group_info_ref.clone(),
        ratchet_tree_ref: payload.ratchet_tree_ref.clone(),
        max_response_bytes: None,
    };
    request.validate().unwrap();
    let station = &reader.account_id.station_id;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let app = crate::authority_commit::AuthorityCommitApplication::new(
        crate::persistence::PersistenceHandle::new(std::sync::Arc::new(PgPersistenceStore::new(
            pool.clone(),
        ))),
        64,
    );
    let mut conn = pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = Jsonb)]
        payload: serde_json::Value,
    }
    let members = diesel::sql_query("SELECT to_jsonb(count(*)) AS payload FROM member_state_current_states WHERE realm_id=$1 AND member_id=$2")
        .bind::<Text,_>(request.realm_id.as_str())
        .bind::<Text,_>(ActorId::account(reader.account_id.clone()).to_string())
        .get_result::<Count>(&mut *conn).await.unwrap();
    assert_eq!(members.payload, serde_json::json!(0));
    drop(conn);
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, station, None)
            .await
            .unwrap(),
        Material::NotFound
    ));

    let mut no_status = reader.clone();
    no_status.account_status_observation = None;
    assert!(matches!(
        store
            .read_human_pcr_group_state_material(&no_status, &request, station)
            .await
            .unwrap(),
        HumanPcrHistoryRead::CurrentStatusRequired
    ));
    let HumanPcrHistoryRead::Ready {
        value: Material::Authorized {
            group_state_event: Some(original),
        },
        mut guard,
    } = app
        .read_human_pcr_group_state_material(reader, &request, station)
        .await
        .unwrap()
    else {
        panic!("current native owner must read its original PCR MLS material without a Member row");
    };
    assert_eq!(original.event, genesis.event);
    assert_eq!(original.commit, genesis.commit);
    assert!(guard.prepare_handoff().await);
    guard.finish().await.unwrap();

    for changed in [
        old_reader.clone(),
        {
            let mut r = reader.clone();
            r.credential_expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
            r
        },
        {
            let mut r = reader.clone();
            r.credential_device_binding
                .as_mut()
                .unwrap()
                .model_generation_ref = 1;
            r
        },
        {
            let mut r = reader.clone();
            r.credential_device_binding
                .as_mut()
                .unwrap()
                .authorization_event_id = old_reader
                .credential_device_binding
                .as_ref()
                .unwrap()
                .authorization_event_id
                .clone();
            r
        },
    ] {
        assert!(
            store
                .read_human_pcr_group_state_material(&changed, &request, station)
                .await
                .is_err()
        );
    }
    let mut foreign = reader.clone();
    foreign.account_id.station_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-home.example").unwrap();
    assert!(matches!(
        store
            .read_human_pcr_group_state_material(&foreign, &request, station)
            .await
            .unwrap(),
        HumanPcrHistoryRead::NotApplicable
    ));
    let mut wrong_caller = request.clone();
    wrong_caller.caller_actor_id = Some(ActorId::service(station.clone()));
    assert!(
        store
            .read_human_pcr_group_state_material(reader, &wrong_caller, station)
            .await
            .is_err()
    );
    let mut wrong_epoch = request.clone();
    wrong_epoch.epoch = 1;
    let HumanPcrHistoryRead::Ready { value, guard } = store
        .read_human_pcr_group_state_material(reader, &wrong_epoch, station)
        .await
        .unwrap()
    else {
        panic!("native owner role must remain separate from selected material validity");
    };
    assert!(matches!(value, Material::NotFound));
    guard.finish().await.unwrap();
}

#[tokio::test]
async fn ordinary_material_reads_keep_member_peer_actor_and_epoch_gates() {
    use coland_storage::EventCommitUnitOfWork as _;
    use coland_storage_postgres::{PgEventCommitUnitOfWork, TestDatabase};

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let prepared = Box::pin(super::super::prepared_group(
        &pool,
        "ordinary-material-regression",
        false,
    ))
    .await;
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(prepared.request.clone())
        .await
        .unwrap();
    let original = &prepared.request.authority_commit.event;
    let payload: MlsGenesisPayload =
        serde_json::from_value(serde_json::to_value(&original.payload).unwrap()).unwrap();
    let mut request = MlsGroupStateMaterialRequestBody {
        realm_id: original.realm_id.clone(),
        effective_scope: original.scope_ref.clone(),
        mls_group_id: payload.mls_group_id().unwrap(),
        epoch: 0,
        group_state_event_id: original.event_id.clone(),
        caller_actor_id: Some(original.actor_id.clone()),
        target_commit_event_ref: Some(original.event_id.clone()),
        target_epoch: Some(0),
        group_info_ref: payload.group_info_ref,
        ratchet_tree_ref: payload.ratchet_tree_ref,
        max_response_bytes: None,
    };
    let station = super::super::ordinary_realm::station();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    for peer in [None, Some(&station)] {
        assert!(matches!(
            store
                .mls_member_group_state_material_read(&request, &station, peer)
                .await
                .unwrap(),
            Material::Authorized {
                group_state_event: Some(_)
            }
        ));
    }
    let outsider =
        arkret_wire::DidCoreId::new("ak:did_core:web:material-outsider.example").unwrap();
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, Some(&outsider))
            .await
            .unwrap(),
        Material::NotFound
    ));
    request.caller_actor_id = Some(ActorId::service(outsider));
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Material::NotFound
    ));
    request.caller_actor_id = Some(original.actor_id.clone());
    request.epoch = 1;
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Material::NotFound
    ));
}
