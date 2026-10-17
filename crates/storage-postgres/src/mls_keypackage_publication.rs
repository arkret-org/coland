//! Scope-bound native KeyPackages use the real Account/PCR and business cut.
use arkret_models_collaboration::governance::operation_wire::{
    AppletPolicyOperation, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_wire::{ActorId, PolicyEffect, ScopeRef};
use coland_storage::{
    AppletManagedDeviceScopeGuard, MlsKeyPackageRow, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

pub(crate) async fn require_native(
    conn: &mut AsyncPgConnection,
    record: &MlsKeyPackageRow,
    guard: &AppletManagedDeviceScopeGuard,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if record.effective_scope.as_ref() != Some(&guard.effective_scope)
        || record.owner_account_id != guard.authority.account_id
        || record.actor_id != guard.authority.account_id.principal_id.as_str()
        || record.device_id.as_deref() != Some(guard.authority.device_id.as_str())
        || record.device_authorize_event_id.as_deref()
            != Some(guard.authority.selector.authorization_ref.event_id.as_str())
        || record.agent_key_authorize_event_id.is_some()
        || record.endpoint_verification_method.is_some()
        || !matches!(
            guard.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        )
    {
        return Err(denied(
            "KeyPackage differs from its original Account Device and exact scope",
        ));
    }
    let mut realms = vec![
        guard.authority.pcr_realm_id.clone(),
        guard.effective_scope.realm_id().clone(),
    ];
    realms.sort();
    realms.dedup();
    for realm in realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
        let owner = sql_query(
            "SELECT to_jsonb(service_id) AS value FROM realm_authorities WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<Row>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if owner.value.as_str() != Some(guard.authority.account_id.station_id.as_str()) {
            return Err(PersistenceError::Conflict(
                "temporarily_unavailable: native KeyPackage current cut is not local".into(),
            ));
        }
    }
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    if at >= expires_at {
        return Err(denied("KeyPackage request authority expired"));
    }
    let current = crate::pcr_applet_device_authority::current_in_connection(
        conn,
        &record.owner_account_id,
        &guard.authority.device_id,
        at,
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| denied("KeyPackage Device is unavailable"))?;
    if current != guard.authority {
        return Err(denied("KeyPackage Device authorization instance changed"));
    }
    let (registration, installation) = crate::boxed_future(|| {
        crate::applet_device_admission::installation_for_keypackage_publication(
            conn,
            &current,
            &guard.effective_scope,
            &guard.service_did_document,
            at,
            true,
        )
    })
    .await?;
    crate::boxed_future(|| {
        crate::applet_e2ee::require_current_consent(
            conn,
            &registration,
            &installation,
            &guard.effective_scope,
            at,
        )
    })
    .await?;

    let scope = &guard.effective_scope;
    let group = crate::mls_group_current_results::locked_group(
        conn,
        &crate::mls_group_current_results::scope_key(scope)?,
    )
    .await?
    .ok_or_else(|| denied("KeyPackage target has no accepted MLS group"))?;
    if group.realm_id != *scope.realm_id() || group.value.effective_scope != *scope {
        return Err(denied(
            "KeyPackage target group differs from its real scope",
        ));
    }
    // Membership can advance the typed current revision without replacing
    // the accepted MLS head. Verify both writers at their actual positions.
    let original = sql_query("SELECT e.envelope AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk JOIN realm_commits revision ON revision.realm_id=c.realm_id AND revision.stream_ref=c.stream_ref JOIN canonical_events writer ON writer.pk=revision.event_pk WHERE e.state='committed' AND e.kind IN ('ak.mls.genesis','ak.mls.commit') AND e.envelope->>'event_id'=$1 AND revision.commit_id=$2 AND revision.stream_position=$3 AND c.stream_position<=revision.stream_position AND c.realm_id=$4 AND e.envelope->'scope_ref'=$5 AND writer.state='committed' AND writer.kind IN ('ak.mls.genesis','ak.mls.commit','ak.member.state','ak.invite.accept','ak.circle.member.state') AND writer.envelope->'scope_ref'=$5")
        .bind::<Text,_>(group.value.current_mls_commit_event_ref.as_str()).bind::<Text,_>(group.current_commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(group.current_stream_position).map_err(PersistenceError::database)?)
        .bind::<Text,_>(scope.realm_id().as_str()).bind::<Jsonb,_>(json!(scope))
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if original.is_none() {
        return Err(PersistenceError::Conflict(
            "temporarily_unavailable: native KeyPackage group original is unavailable".into(),
        ));
    }
    let actor = ActorId::account(record.owner_account_id.clone());
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, scope.realm_id(), &actor)
            .await?;
    cut.require_open_business_mutation()?;
    if !cut.actor_is_joined() {
        return Err(denied("KeyPackage owner is not joined to its target Realm"));
    }
    let circle = match scope {
        ScopeRef::Circle { circle_id, .. } => Some(circle_id),
        _ => None,
    };
    if let Some(circle) = circle {
        let basis =
            crate::circle_current_results::locked_circle_basis(conn, scope.realm_id(), circle)
                .await?;
        if basis["value"]["state"] != "active"
            || !crate::circle_current_results::effective_member_in_connection(
                conn,
                scope.realm_id(),
                circle,
                &actor,
            )
            .await?
        {
            return Err(denied(
                "KeyPackage owner has no active exact Circle membership",
            ));
        }
    }
    let policies =
        crate::policy_current_results::read_scoped_applet_management_policies_in_connection(
            conn,
            scope.realm_id(),
            circle,
        )
        .await?;
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(scope.realm_id().clone()),
        resource_ref: Some(scope.realm_id().to_string()),
    }];
    if let Some(circle) = circle {
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(scope.realm_id().clone()),
            resource_ref: Some(circle.to_string()),
        });
    }
    let decision = arkret_policy::applet_management::select_applet_management(
        Some(&policies),
        &arkret_policy::applet_management::AppletManagementContext {
            device_control: Some(
                arkret_wire::ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            ),
            realm_id: scope.realm_id(),
            requester_actor_id: &actor,
            applet_id: &registration.applet_id,
            effective_scope: scope,
            managed_actor_id: Some(&actor),
            operation: AppletPolicyOperation::Execute,
            content_action: None,
            resources: Some(&resources),
            at,
        },
    )
    .map_err(PersistenceError::database)?;
    if decision.effect != PolicyEffect::Allow {
        return Err(denied(
            "current Applet Policy rejects KeyPackage publication",
        ));
    }
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(&record.key_package_bytes, 0)
        .map_err(denied)?;
    let expected = arkret_models_crypto::mls_basic_credential_identity(&actor).map_err(denied)?;
    if !matches!(leaf.credential,arkret_mls::AuthorLeafCredential::Basic {identity} if identity==expected)
        || leaf.signature_key.as_slice() != current.public_key.as_slice()
        || arkret_canonical::sha256_digest(&record.key_package_bytes) != record.keypackage_digest
        || record.keypackage_ref != record.keypackage_digest
        || arkret_canonical::canonical_sha256(&record.capabilities).map_err(denied)?
            != record.capabilities_digest
    {
        return Err(denied(
            "KeyPackage leaf or original digest differs from its real Account Device",
        ));
    }
    arkret_mls::validate_keypackage_capability_binding(
        &record.key_package_bytes,
        &record.capabilities,
    )
    .map_err(denied)?;
    if at.timestamp() < record.lifetime_not_before
        || at.timestamp() >= record.lifetime_not_after
        || chrono::Utc::now() >= expires_at
        || chrono::Utc::now() >= current.expires_at
    {
        return Err(denied("KeyPackage publication window expired"));
    }
    Ok(())
}
