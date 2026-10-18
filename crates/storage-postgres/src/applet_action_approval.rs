//! Operation facts from the locked creation cut, without a synthetic Event.
use arkret_models_collaboration::governance::grant_constraint::CapabilityGrant;
use arkret_models_integration::{AppletManagedActorRole, AppletRegistrationPayload};
use arkret_wire::{ActorId, CapabilityActionId, GrantId, ScopeRef, WireResourceSelector};
use coland_storage::{
    AppletAuthoringCandidate, AuthorizationOperation, GrantEvaluation, OperationFacts,
    PersistenceError, PersistenceResult, QuotaReservation, VerifiedGrantApproval,
};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::applet_admission::ValidatedAppletUnit;
use crate::realm_authorization_cut::RealmAuthorizationCut;

/// Discover only participants of the real pending operation. The transaction
/// ends before HTTP resolves their portable current AA records.
pub(crate) async fn prepare_accounts(
    pool: &crate::PgPool,
    candidate: &AppletAuthoringCandidate,
) -> PersistenceResult<Vec<arkret_wire::AccountId>> {
    use diesel_async::AsyncConnection;
    let mut input = Box::new(candidate.clone());
    input.accepted_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut unit = crate::applet_admission::validate_candidate(&input).await?;
    let mut conn = crate::pg_conn(pool)
        .await
        .map_err(PersistenceError::database)?;
    (*conn).transaction::<_, crate::PgTransactionError, _>(async move |conn| {
        crate::boxed_future(|| async move {
            let station = crate::applet_admission::target_station(&input)?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind::<Text,_>(format!("applet:{}:{station}",input.package.applet_id))
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            let mut realms = std::collections::BTreeSet::from([unit.portal_realm.clone()]);
            if let coland_storage::AppletAdmissionRequest::Managed(
                arkret_models_integration::AppletManagedActorCommittedRequest::Ghost(body),
            ) = &input.request
                && let Some(existing) = &body.existing_managed_actor {
                realms.insert(existing.principal_control_realm_id.clone());
            }
            for realm in realms {
                crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
            }
            input.accepted_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            crate::applet_admission::validate_managed_current(conn, &input, &mut unit).await?;
            crate::agent_management_review::applet::require_current_installation(conn, &input).await?;
            let authority = CreationAuthority::read(conn, &input, &unit).await?;
            authority.pin_grant()?;
            let mut principals = std::collections::BTreeSet::new();
            for (_, grant) in authority.cut.effective_grants(input.accepted_at).filter(|(_, grant)| {
                coland_storage::grant_names_target(grant,&[authority.action.as_str()],&authority.target)
            }) {
                for constraint in grant.constraints.iter().filter(|constraint| {
                    crate::grant_approval_admission::is_approval_constraint(constraint)
                        && (constraint.approval_required == Some(true)
                            || constraint.guardian_approval_required == Some(true)
                            || constraint.controller_approval_required == Some(true))
                        && (constraint.applies_to_actions.is_empty()
                            || constraint.applies_to_actions.iter().any(|action| action.as_str()==authority.action.as_str()))
                }) {
                    principals.extend(constraint.approval_actor_ids.iter().cloned());
                }
            }
            let signatures = match &input.request {
                coland_storage::AppletAdmissionRequest::Managed(arkret_models_integration::AppletManagedActorCommittedRequest::Bot(body)) => &body.approval_signatures,
                coland_storage::AppletAdmissionRequest::Managed(arkret_models_integration::AppletManagedActorCommittedRequest::Ghost(body)) => &body.approval_signatures,
                _ => return Err(denied("approval preparation is not a creation")),
            };
            for signature in signatures {
                if matches!(signature.input.approval_context,arkret_wire::ApprovalContext::Grant { .. } | arkret_wire::ApprovalContext::RealmGovernance { .. }) {
                    principals.insert(arkret_wire::project_did_to_core_id(&signature.input.approver_did)
                        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?);
                }
            }
            #[derive(QueryableByName)]
            struct Member { #[diesel(sql_type=Text)] member_id:String }
            let members=sql_query("SELECT member_id FROM member_state_current_results WHERE realm_id=$1 AND membership='join' ORDER BY member_id")
                .bind::<Text,_>(unit.portal_realm.as_str()).load::<Member>(conn).await.map_err(PersistenceError::database)?;
            let mut accounts = std::collections::BTreeSet::new();
            for member in members {
                let actor:ActorId=serde_json::from_str(&member.member_id).map_err(PersistenceError::database)?;
                if principals.contains(actor.signing_principal_id())
                    && let Some(account)=actor.as_account_id() { accounts.insert(account.clone()); }
            }
            Ok(accounts.into_iter().collect::<Vec<_>>())
        }).await.map_err(Into::into)
    }).await.map_err(crate::PgTransactionError::into_persistence)
}

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

pub(crate) fn operation_binding(
    input: &AppletAuthoringCandidate,
) -> PersistenceResult<(arkret_wire::ServiceOperationId, arkret_wire::Hash)> {
    let target = crate::agent_management_review::applet::target(input)?;
    let operation = match &target {
        arkret_models_integration::management_review::ManagementReviewTarget::BotCreation {
            ..
        } => arkret_wire::ServiceOperationId::SelfAppletBotCommandProvisionV1,
        arkret_models_integration::management_review::ManagementReviewTarget::GhostCreation {
            ..
        } => arkret_wire::ServiceOperationId::SelfAppletGhostCommandProvisionV1,
        _ => return Err(denied("creation target has no registered operation")),
    };
    Ok((
        operation,
        target
            .canonical_target_digest()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
    ))
}

pub(crate) fn accepted_outcome(
    input: &AppletAuthoringCandidate,
    refs: &[arkret_wire::CommittedEventRef],
    response: &serde_json::Value,
) -> PersistenceResult<serde_json::Value> {
    let (operation, digest) = operation_binding(input)?;
    Ok(
        serde_json::json!({"operation":operation.as_str(),"target_digest":digest,"committed_event_refs":refs,"response_body":response}),
    )
}

/// All operation approval layers share the existing Event audit nonce key.
/// One original vote can qualify several requirements only in this transaction.
pub(crate) async fn consume(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringCandidate,
    qualified: &[crate::approval_admission::QualifiedApproval],
    refs: &[arkret_wire::CommittedEventRef],
    response: &serde_json::Value,
) -> PersistenceResult<()> {
    if qualified.is_empty() {
        return Ok(());
    }
    let (operation, digest) = operation_binding(input)?;
    let outcome = accepted_outcome(input, refs, response)?;
    for vote in qualified {
        let method = &vote.method;
        let context =
            arkret_canonical::canonical_json_string(&method.signature.input.approval_context)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let basis = serde_json::json!({
            "historical_method":method.signature.proof.verification_method,
            "public_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&method.public_key),
            "native_control_history":method.control_history,"qualifications":[vote.qualification_basis],
        });
        let inserted=sql_query("INSERT INTO event_approval_private_audit(approval_context,approver_did,nonce,realm_id,operation_id,operation_target_digest,operation_outcome,evidence,accepted_basis,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(approval_context,approver_did,nonce) DO UPDATE SET accepted_basis=jsonb_set(event_approval_private_audit.accepted_basis,'{qualifications}',(SELECT jsonb_agg(DISTINCT q) FROM jsonb_array_elements((event_approval_private_audit.accepted_basis->'qualifications') || (EXCLUDED.accepted_basis->'qualifications')) AS q)) WHERE event_approval_private_audit.xmin=pg_current_xact_id()::xid AND event_approval_private_audit.event_id IS NULL AND event_approval_private_audit.operation_id=EXCLUDED.operation_id AND event_approval_private_audit.operation_target_digest=EXCLUDED.operation_target_digest AND event_approval_private_audit.operation_outcome=EXCLUDED.operation_outcome AND event_approval_private_audit.evidence=EXCLUDED.evidence AND event_approval_private_audit.accepted_basis->'public_key'=EXCLUDED.accepted_basis->'public_key' AND event_approval_private_audit.accepted_basis->'native_control_history'=EXCLUDED.accepted_basis->'native_control_history'")
            .bind::<Text,_>(context).bind::<Text,_>(method.signature.input.approver_did.as_str()).bind::<Text,_>(&method.signature.input.nonce)
            .bind::<Text,_>(method.signature.input.realm_id.as_str()).bind::<Text,_>(operation.as_str()).bind::<Text,_>(digest.as_str()).bind::<Jsonb,_>(&outcome)
            .bind::<Jsonb,_>(serde_json::json!(method.signature)).bind::<Jsonb,_>(basis).bind::<Timestamptz,_>(input.accepted_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if inserted != 1 {
            return Err(PersistenceError::Conflict(
                "approval_nonce_reused: operation vote was consumed by another acceptance".into(),
            ));
        }
    }
    Ok(())
}

/// Constructed only by reopening authoritative registration and grant sources.
/// The references retain the already verified original unit at this SQL cut.
pub(crate) struct CreationAuthority<'a> {
    pub(crate) input: &'a AppletAuthoringCandidate,
    pub(crate) unit: &'a ValidatedAppletUnit,
    pub(crate) cut: RealmAuthorizationCut,
    registration: AppletRegistrationPayload,
    pub(crate) action: CapabilityActionId,
    pub(crate) target: WireResourceSelector,
    pub(crate) facts: OperationFacts,
    pub(crate) grant_id: GrantId,
}

impl<'a> CreationAuthority<'a> {
    pub(crate) async fn read(
        conn: &mut AsyncPgConnection,
        input: &'a AppletAuthoringCandidate,
        unit: &'a ValidatedAppletUnit,
    ) -> PersistenceResult<Self> {
        let provision = unit
            .provision
            .as_ref()
            .ok_or_else(|| denied("managed provenance absent"))?;
        let actor = ActorId::service(input.package.service_id.clone());
        if input.admin_actor_id != actor {
            return Err(denied("creation initiator differs from its exact Service"));
        }
        let cut = RealmAuthorizationCut::read(conn, &unit.portal_realm, &actor).await?;
        cut.require_open_business_mutation()?;
        let registration = crate::applet_admission::require_exact_service_grant(
            conn,
            input,
            provision,
            &unit.portal_realm,
        )
        .await?
        .ok_or_else(|| denied("current registration absent"))?;
        let target = match crate::applet_admission::effective_scope(input)? {
            ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
            _ => return Err(denied("unsupported creation scope")),
        };
        let facts = OperationFacts {
            applet_id: Some(registration.applet_id.to_string()),
            executed_by: Some(ActorId::service(registration.service_id.clone())),
            registration_epoch: Some(registration.registration_epoch.to_string()),
            ..Default::default()
        };
        let action = match provision.actor_role {
            AppletManagedActorRole::Bot => CapabilityActionId::AppletBotProvision,
            AppletManagedActorRole::Ghost => CapabilityActionId::AppletGhostProvision,
        };
        let grant_id = crate::applet_admission::creation_authorization_ref(input, provision)?;
        Ok(Self {
            input,
            unit,
            cut,
            registration,
            action,
            target,
            facts,
            grant_id,
        })
    }

    pub(crate) fn exact_grant(&self) -> PersistenceResult<&CapabilityGrant> {
        self.cut
            .effective_grants(self.input.accepted_at)
            .find(|(id, _)| *id == &self.grant_id)
            .map(|(_, grant)| grant)
            .ok_or_else(|| denied("exact creation grant is unavailable"))
    }

    /// Private pending intent may retain an unresolved approval obligation.
    /// This returns original source material and cannot authorize any write.
    pub(crate) fn pin_grant(&self) -> PersistenceResult<serde_json::Value> {
        let actions = [self.action.as_str()];
        let operation = AuthorizationOperation {
            actor: &self.input.admin_actor_id,
            actions: &actions,
            target: &self.target,
            at: self.input.accepted_at,
            facts: &self.facts,
        };
        let all = coland_storage::evaluate_grants(
            &operation,
            self.cut
                .effective_grants(self.input.accepted_at)
                .map(|(_, grant)| grant),
        );
        if !matches!(
            all,
            GrantEvaluation::Allowed(_) | GrantEvaluation::RequiresReview
        ) {
            return Err(denied("current creation authority refuses the candidate"));
        }
        let exact = self.exact_grant()?;
        if !matches!(
            coland_storage::evaluate_grants(&operation, std::iter::once(exact)),
            GrantEvaluation::Allowed(_) | GrantEvaluation::RequiresReview
        ) {
            return Err(denied("exact creation grant does not admit this candidate"));
        }
        serde_json::to_value(exact)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))
    }

    pub(crate) fn granted(
        &self,
        approvals: &[VerifiedGrantApproval],
    ) -> PersistenceResult<(serde_json::Value, Vec<QuotaReservation>, Vec<GrantId>)> {
        let actions = [self.action.as_str()];
        let operation = AuthorizationOperation {
            actor: &self.input.admin_actor_id,
            actions: &actions,
            target: &self.target,
            at: self.input.accepted_at,
            facts: &self.facts,
        };
        let evaluation = coland_storage::evaluate_grants_with_verified_approvals(
            &operation,
            self.cut
                .effective_grants(self.input.accepted_at)
                .map(|(_, grant)| grant),
            approvals,
        );
        let GrantEvaluation::Allowed(satisfied) = evaluation else {
            return Err(match evaluation {
                GrantEvaluation::RequiresReview => PersistenceError::Conflict(
                    "approval_required: creation grant approval is unresolved".into(),
                ),
                _ => denied("exact managed provisioning grant is unavailable"),
            });
        };
        let selected = satisfied
            .iter()
            .find(|grant| grant.grant.id == self.grant_id)
            .ok_or_else(|| denied("exact managed provisioning grant is unavailable"))?;
        Ok((
            serde_json::to_value(selected.grant)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            selected.reservations.clone(),
            satisfied
                .iter()
                .map(|grant| grant.grant.id.clone())
                .collect(),
        ))
    }

    /// Independent grant and governance requirements over the actual operation.
    /// All qualification remains inside the aggregate's locked authority cut.
    pub(crate) async fn admit(
        &self,
        conn: &mut AsyncPgConnection,
        prepared: Option<&coland_storage::OperationApprovalCommit>,
    ) -> PersistenceResult<(
        Vec<QuotaReservation>,
        Vec<crate::approval_admission::QualifiedApproval>,
    )> {
        let (operation, digest) = operation_binding(self.input)?;
        if prepared.is_some_and(|prepared| {
            prepared.operation != operation || prepared.target_digest != digest
        }) {
            return Err(PersistenceError::Conflict(
                "signature_invalid: creation approval target differs".into(),
            ));
        }
        let methods = prepared.map_or(&[][..], |prepared| prepared.methods.as_slice());
        crate::approval_admission::validate_operation_candidate(
            methods,
            &digest,
            operation.as_str(),
            self.action,
            &self.unit.portal_realm,
            &self.input.admin_actor_id,
            self.input.accepted_at,
        )?;
        self.pin_grant()?;
        let empty_current = coland_storage::ManagementReviewCurrent {
            station_id: crate::applet_admission::target_station(self.input)?.clone(),
            observations: Vec::new(),
            applet_candidate: None,
            applet_event: None,
        };
        let current = prepared.map_or(&empty_current, |prepared| &prepared.current);
        let relevant = self
            .cut
            .effective_grants(self.input.accepted_at)
            .filter(|(_, grant)| {
                coland_storage::grant_names_target(grant, &[self.action.as_str()], &self.target)
            })
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        for method in methods {
            if let arkret_wire::ApprovalContext::Grant { grant_id } =
                &method.signature.input.approval_context
                && !relevant.iter().any(|grant| &grant.id == grant_id)
            {
                return Err(PersistenceError::Conflict(
                    "signature_invalid: approval names an unrelated creation grant".into(),
                ));
            }
        }
        let mut markers = Vec::new();
        let mut accepted = Vec::new();
        let mut exact_missing = false;
        for grant in relevant {
            let requirements =
                match crate::grant_approval_admission::require_creation_grant_approvals(
                    conn, self, methods, grant, current,
                )
                .await
                {
                    Ok(requirements) => requirements,
                    Err(PersistenceError::Conflict(detail))
                        if detail.starts_with("approval_required:") =>
                    {
                        exact_missing |= grant.id == self.grant_id;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            for requirement in requirements {
                markers.push(VerifiedGrantApproval {
                    grant_id: requirement.grant_id,
                    constraint_digest: requirement.constraint_digest,
                    action: self.action,
                });
                accepted.extend(requirement.accepted);
            }
        }
        if exact_missing {
            return Err(PersistenceError::Conflict(
                "approval_required: exact creation grant approval is not satisfied".into(),
            ));
        }
        let (_, reservations, dependencies) = self.granted(&markers)?;
        if let Some(quorum) = crate::policy_action_admission::current_operation_quorum(
            conn,
            &self.unit.portal_realm,
            self.action,
            &self.target,
            &self.facts,
            self.input.accepted_at,
        )
        .await?
        {
            let mut counted = std::collections::BTreeSet::new();
            for method in methods {
                match &method.signature.input.approval_context {
                    arkret_wire::ApprovalContext::RealmGovernance {} => {}
                    arkret_wire::ApprovalContext::Grant { grant_id }
                        if dependencies.contains(grant_id)
                            && self
                                .cut
                                .effective_grants(self.input.accepted_at)
                                .find(|(id, _)| *id == grant_id)
                                .is_some_and(|(_, grant)| {
                                    crate::grant_approval_admission::grant_vote_is_current(
                                        grant,
                                        self.action,
                                        &method.signature,
                                        self.input.accepted_at,
                                    )
                                }) => {}
                    _ => continue,
                }
                let principal =
                    arkret_wire::project_did_to_core_id(&method.signature.input.approver_did)
                        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                if counted.contains(&principal) {
                    continue;
                }
                if let Some(mut basis) = crate::approval_admission::qualify_creation_principal(
                    conn, self, &principal, current,
                )
                .await?
                {
                    basis["governance_requirement"] = serde_json::json!({
                        "action":self.action,"target":self.target,"effective_approval_quorum":quorum,
                        "evaluated_at":arkret_canonical::format_timestamp_canonical(self.input.accepted_at),
                    });
                    counted.insert(principal);
                    accepted.push(crate::approval_admission::QualifiedApproval {
                        method: method.clone(),
                        qualification_basis: basis,
                    });
                }
            }
            if (counted.len() as u64) < quorum {
                return Err(PersistenceError::Conflict(format!(
                    "approval_required: action={} effective_approval_quorum={quorum} counted_approvals={}",
                    self.action.as_str(),
                    counted.len(),
                )));
            }
        }
        Ok((reservations, accepted))
    }

    pub(crate) fn satisfies_evaluator_check(&self, check: &str) -> bool {
        let Some(provision) = self.unit.provision.as_ref() else {
            return false;
        };
        let exact_registration = self.registration.applet_id == self.input.package.applet_id
            && self.registration.service_id == self.input.package.service_id
            && self.registration.registration_epoch == self.input.package.registration_epoch
            && provision.applet_id == self.registration.applet_id
            && provision.service_id == self.registration.service_id;
        let fixed_unit = self.unit.events.len() == 4
            || (self.unit.events.is_empty()
                && self.input.prior_managed_refs.len() == 4
                && provision.actor_role == AppletManagedActorRole::Ghost);
        match check {
            "active_applet_registration_exact" => exact_registration,
            "bot_managed_actor_provision_unit_atomic" => {
                exact_registration
                    && fixed_unit
                    && provision.actor_role == AppletManagedActorRole::Bot
            }
            "ghost_managed_actor_provision_unit_atomic" => {
                exact_registration
                    && fixed_unit
                    && provision.actor_role == AppletManagedActorRole::Ghost
            }
            "ghost_actor_namespace_match" => {
                provision.actor_role == AppletManagedActorRole::Ghost
                    && self
                        .input
                        .package
                        .namespaces
                        .actors
                        .iter()
                        .any(|namespace| {
                            arkret_models_integration::namespace_pattern_matches(
                                arkret_models_integration::AppletNamespaceDomain::Actors,
                                &namespace.pattern,
                                provision.initial_resolution.did.as_str(),
                            )
                        })
            }
            _ => false,
        }
    }
}
