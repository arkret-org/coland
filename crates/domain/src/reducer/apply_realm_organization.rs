//! SOL-ORG-02 / SOL-ORG-03 — `ak.realm.organization` relationship-statement
//! reducer + projection.
//!
//! ## Model
//!
//! `ak.realm.organization` carries an **organization-authorized Realm
//! relationship statement or revocation** (spec event-kind-registry +
//! `event-payload.schema.json#/$defs/realm_organization_payload`). It is NOT
//! Realm mutable metadata: the cell family `ak.component.realm.organization.v1`
//! is a `causal_register` keyed by the composite subject
//! `(organization_id, relationship)`, so distinct
//! `(organization_id, relationship)` pairs form independent cells and an
//! `owner` / `governance` / `sponsor` / `directory_certifier` relationship can
//! all coexist for one Realm.
//!
//! ## Two-sided authorization gate (SOL-ORG-03)
//!
//! Accepting a relationship requires BOTH:
//!   1. **Realm side** — the event must be admitted into Realm history by a bootstrap path or by an
//!      actor holding `ak.realm.admin` (enforced at ingest in the routing/authz layer, not here —
//!      the reducer runs after admission). A human OIDC session only proves the executor's
//!      identity; it never by itself creates organization principal control.
//!   2. **Organization side** — the statement's `authorization` must pass the SDK
//!      [`verify_realm_organization_statement`] check: issuer-role / delegation coupling (delegated
//!      roles MUST carry a resolvable `delegation_ref`), proof presence, validity window, and
//!      status/revocation consistency.
//!
//! The reducer is a pure projection with no DID-document runtime, so it injects
//! the fail-closed [`NoDelegationResolver`]: a `governance_service` /
//! `account_authority` statement (which requires a live delegation) is rejected
//! here and only accepted once a runtime resolver is wired at the
//! admission/HTTP layer (see SOL-ORG-06 notes). `organization_id` /
//! `threshold_quorum` statements (no `delegation_ref`) project directly.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::{
    RealmOrganizationControlScope, RealmOrganizationPayload, SignatureMaterial,
};
use arkret_policy::{NoDelegationResolver, verify_realm_organization_statement};

use super::facets::{FacetRef, facet};
use super::{ProjectionEffect, ProjectionState, RealmOrganizationStatementState};

impl ProjectionState {
    /// Project a `ak.realm.organization` relationship statement.
    ///
    /// Cell family: `ak.component.realm.organization.v1` (registered state model,
    /// composite subject `(organization_id, relationship)`).
    ///
    /// On an `active` statement that passes the organization-side verifier the
    /// relationship projection is written/updated; a `revoked` statement marks
    /// the relationship inactive while retaining `statement_id` for audit.
    /// Supports `expires_at` / `not_before` / `supersedes_statement_id` /
    /// `revokes_statement_id`.
    pub(crate) fn apply_realm_organization(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        // Strong-typed parse. We never hand-roll the wire struct.
        let payload = match operation.typed_payload::<arkret_wire::event_spec::RealmOrganization>()
        {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };

        // The statement's `realm_id` MUST equal the enclosing event's
        // `realm_id`. The SDK verifier also checks this, but we resolve the
        // expected RealmId up front so a malformed envelope realm fails closed.
        let expected_realm_id = operation.realm_id.clone();

        // SOL-ORG-03 organization side: run the SDK fail-closed verifier with
        // the offline resolver. Delegated issuer roles
        // (governance_service / account_authority) require a live delegation
        // and are rejected here until a runtime resolver is injected upstream.
        if let Err(error) = verify_realm_organization_statement(
            &payload,
            &expected_realm_id,
            now,
            &NoDelegationResolver,
        ) {
            // A statement that fails ONLY because it is outside its validity
            // window (expired or not-yet-valid) is still projected as an audit
            // row: it is retained for history and simply excluded from the
            // verified set by the read-side `is_effective_active` filter. The
            // SDK verifier checks proof / issuer-role / delegation strictly
            // before the validity window, so a validity-window error code means
            // every structural and authorization check already passed. Any
            // other failure (bad proof, unresolved delegation, status mismatch)
            // fails closed and is not stored.
            let reason = organization_rejection_reason(&error.to_string());
            let window_only = (reason == arkret_wire::ReasonCode::REALM_ORGANIZATION_EXPIRED
                && payload.is_expired(now))
                || (reason == arkret_wire::ErrorCode::FAILED_PRECONDITION
                    && payload.is_not_yet_valid(now));
            if !window_only {
                tracing::warn!(
                    statement_id = %payload.statement_id,
                    organization_id = %payload.organization_id.as_str(),
                    error = %error,
                    "rejected ak.realm.organization: organization-side verification failed"
                );
                return ProjectionEffect::Rejected { reason };
            }
        }

        let realm_id = expected_realm_id.to_string();
        let organization_id = payload.organization_id.clone();
        let relationship = relationship_str(&payload).to_owned();
        let status = if payload.is_active_status() {
            "active"
        } else {
            "revoked"
        };

        // Cell write — registered state model keyed by the composite
        // `{organization_id}::{relationship}` subject. This mirrors the SDK
        // `RealmOrganization::subject_for_effect` form exactly so the inline
        // cache and the Move/Seal cell store agree.
        {
            let value = serde_json::json!({
                "statement_id": payload.statement_id,
                "realm_id": realm_id,
                "organization_id": organization_id,
                "relationship": relationship,
                "status": status,
                "control_scopes": control_scopes_str(&payload),
                "issued_at": arkret_canonical::format_timestamp_canonical(payload.issued_at),
                "updated_at": arkret_canonical::format_timestamp_canonical(now),
                "operation_id": operation.operation_id.as_str(),
            });
            self.set_facet(
                &realm_id,
                Self::realm_organization_facet(&organization_id, &relationship),
                value,
            );
        }

        let row = RealmOrganizationStatementState {
            realm_id: realm_id.clone(),
            organization_id: organization_id.clone(),
            relationship: relationship.clone(),
            statement_id: payload.statement_id.clone(),
            status: status.to_owned(),
            control_scopes: control_scopes_str(&payload),
            issued_at: payload.issued_at,
            not_before: payload.not_before,
            expires_at: payload.expires_at,
            supersedes_statement_id: payload.supersedes_statement_id.clone(),
            revokes_statement_id: payload.revokes_statement_id.clone(),
            realm_commit_ref: payload.realm_commit_ref.as_ref().map(ToString::to_string),
            proof_digest: proof_digest(&payload.authorization.proof),
            delegation_ref: payload.authorization.delegation_ref.clone(),
            issuer_role: issuer_role_str(&payload).to_owned(),
            updated_at: now,
        };
        self.realm_organization_statements.insert(
            (
                realm_id.clone(),
                organization_id.clone(),
                relationship.clone(),
            ),
            row,
        );

        ProjectionEffect::RealmOrganizationProjected {
            realm_id,
            organization_id,
            relationship,
            status: status.to_owned(),
        }
    }

    /// Facet coordinate of one `(organization_id, relationship)` statement.
    pub(crate) fn realm_organization_facet(
        organization_id: &arkret_wire::DidCoreId,
        relationship: &str,
    ) -> FacetRef {
        FacetRef::composite(
            facet::REALM_ORGANIZATION,
            &[organization_id.as_str(), relationship],
        )
    }

    // ── SOL-ORG-05 — verified-relationship + effective-policy reads ──

    /// Every `ak.realm.organization` relationship statement projected for
    /// `realm_id`, regardless of status / validity. Admin / audit surfaces use
    /// this to render revoked / expired history; the verified-relationship and
    /// policy-inheritance reads use the filtered helpers below.
    pub fn realm_organization_statements_for_realm(
        &self,
        realm_id: &str,
    ) -> Vec<&RealmOrganizationStatementState> {
        self.realm_organization_statements
            .iter()
            .filter(|((rid, ..), _)| rid == realm_id)
            .map(|(_, row)| row)
            .collect()
    }

    /// SOL-ORG-05 — the verified (active + in-window) organization
    /// relationships for `realm_id` at `now`. A revoked or expired statement
    /// immediately drops out of this set; an `owning_organization_ids` declared
    /// hint never enters it.
    pub fn verified_organization_relationships(
        &self,
        realm_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<&RealmOrganizationStatementState> {
        self.realm_organization_statements_for_realm(realm_id)
            .into_iter()
            .filter(|row| row.is_effective_active(now))
            .collect()
    }

    /// SOL-ORG-05 — the verified stable organization ids whose active statement for
    /// `realm_id` covers `scope` at `now`. Drives scope-gated policy
    /// inheritance: only these organizations' policies may flow into the
    /// matching effective-policy facet.
    pub fn verified_organizations_with_scope(
        &self,
        realm_id: &str,
        scope: RealmOrganizationControlScope,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<arkret_wire::DidCoreId> {
        let scope = control_scope_str(scope);
        self.verified_organization_relationships(realm_id, now)
            .iter()
            .filter(|row| row.covers_scope(scope))
            .map(|row| row.organization_id.clone())
            .collect()
    }
}

/// Map the SDK verifier's `Error::Protocol` message — which embeds the canonical
/// spec wire error-code constant in parentheses — onto the coland rejection
/// reason. We surface the embedded code when present, falling back to a stable
/// generic when the message shape is unexpected.
fn organization_rejection_reason(message: &str) -> String {
    // The verifier formats every error as `... (<wire_code>)`. Extract the
    // last parenthesised token.
    if let Some(open) = message.rfind('(')
        && let Some(close) = message[open..].find(')')
    {
        let code = message[open + 1..open + close].trim();
        if !code.is_empty() {
            return code.to_owned();
        }
    }
    arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned()
}

/// Audit-only digest of the proof material — never the raw signature bytes.
fn proof_digest(proof: &SignatureMaterial) -> Option<String> {
    let bytes = match proof {
        SignatureMaterial::NonEmptyString(s) => s.as_bytes().to_vec(),
        SignatureMaterial::Variant1(map) => {
            arkret_canonical::canonical_json_bytes(map).unwrap_or_default()
        }
    };
    if bytes.is_empty() {
        return None;
    }
    Some(arkret_canonical::sha256_digest(&bytes))
}

fn relationship_str(payload: &RealmOrganizationPayload) -> &'static str {
    use arkret_models_collaboration::RealmOrganizationRelationship as R;
    match payload.relationship {
        R::Owner => "owner",
        R::Governance => "governance",
        R::Sponsor => "sponsor",
        R::DirectoryCertifier => "directory_certifier",
    }
}

fn issuer_role_str(payload: &RealmOrganizationPayload) -> &'static str {
    use arkret_models_collaboration::RealmOrganizationIssuerRole as Role;
    match payload.authorization.issuer_role {
        Role::Organization => "organization",
        Role::GovernanceService => "governance_service",
        Role::AccountAuthority => "account_authority",
        Role::ThresholdQuorum => "threshold_quorum",
    }
}

pub(crate) fn control_scope_str(scope: RealmOrganizationControlScope) -> &'static str {
    use RealmOrganizationControlScope as S;
    match scope {
        S::OfficialBadge => "official_badge",
        S::RealmAdmin => "realm_admin",
        S::RealmAuthority => "realm_authority",
        S::ModerationPolicy => "moderation_policy",
        S::RetentionPolicy => "retention_policy",
        S::DirectoryListing => "directory_listing",
        S::PlaintextVisibleService => "plaintext_visible_service",
    }
}

fn control_scopes_str(payload: &RealmOrganizationPayload) -> Vec<String> {
    payload
        .control_scopes
        .iter()
        .map(|scope| control_scope_str(*scope).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{DidCoreId, OperationId, RealmId};
    use arkret_models_collaboration::RealmOrganizationControlScope as Scope;
    use serde_json::{Value, json};

    use super::*;

    const REALM: &str = "ak:realm:AaucqKYsYtNwus16IgXDBl88-LWNZZVtRpZ-CqgnPQoi";
    const REALM_OTHER: &str = "ak:realm:AQVZRUJrSSC16EodjmqL6mBFC9TGwv6oxx-sQlJzlvxS";
    const ORG: &str = "ak:did_core:webvh:z6mkorgfixturea";
    const ORG2: &str = "ak:did_core:webvh:z6mkorgfixtureb";
    const ORG_DID: &str = "did:webvh:z6mkorgfixturea:example.test:orgs:a";
    const ORG2_DID: &str = "did:webvh:z6mkorgfixtureb:example.test:orgs:b";

    fn org_id(raw: &str) -> DidCoreId {
        DidCoreId::new(raw).unwrap()
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-25T12:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn op(realm_id: &str, payload: Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
            RealmId::new(realm_id).unwrap(),
            arkret_wire::EventKind::RealmOrganization.as_str(),
            payload,
        )
    }

    /// Active `organization` statement (no delegation_ref required).
    fn active_payload(realm_id: &str, org: &str, relationship: &str, scopes: &[&str]) -> Value {
        let did = if org == ORG { ORG_DID } else { ORG2_DID };
        json!({
            "statement_id": format!("org-stmt-{relationship}"),
            "realm_id": realm_id,
            "organization_id": org,
            "relationship": relationship,
            "status": "active",
            "control_scopes": scopes,
            "issued_at": "2026-06-25T00:00:00.000Z",
            "authorization": {
                "issuer_id": org,
                "issuer_role": "organization",
                "verification_method": format!("{did}#k1"),
                "signed_at": "2026-06-25T00:00:00.000Z",
                "proof": "c2ln"
            }
        })
    }

    fn apply(state: &mut ProjectionState, payload: Value) -> ProjectionEffect {
        state.apply_realm_organization(&op(REALM, payload), now())
    }

    #[test]
    fn active_organization_statement_projects_relationship() {
        let mut state = ProjectionState::new();
        let effect = apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["official_badge", "realm_admin"]),
        );
        assert!(matches!(
            effect,
            ProjectionEffect::RealmOrganizationProjected { ref status, .. } if status == "active"
        ));
        let verified = state.verified_organization_relationships(REALM, now());
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].organization_id, org_id(ORG));
        assert_eq!(verified[0].relationship, "owner");
        // Facet written under the composite subject.
        assert!(
            state
                .facet_value(
                    REALM,
                    &ProjectionState::realm_organization_facet(&org_id(ORG), "owner")
                )
                .is_some()
        );
    }

    #[test]
    fn distinct_relationships_coexist_for_same_realm() {
        let mut state = ProjectionState::new();
        apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["realm_admin"]),
        );
        apply(
            &mut state,
            active_payload(REALM, ORG2, "governance", &["moderation_policy"]),
        );
        apply(
            &mut state,
            active_payload(REALM, ORG, "sponsor", &["official_badge"]),
        );
        let verified = state.verified_organization_relationships(REALM, now());
        assert_eq!(verified.len(), 3);
        // moderation_policy scope only from the governance org.
        let mods = state.verified_organizations_with_scope(REALM, Scope::ModerationPolicy, now());
        assert_eq!(mods, vec![org_id(ORG2)]);
    }

    #[test]
    fn revoked_statement_marks_inactive_but_retains_audit() {
        let mut state = ProjectionState::new();
        apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["realm_admin"]),
        );
        assert_eq!(
            state
                .verified_organization_relationships(REALM, now())
                .len(),
            1
        );

        let mut revoke = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        revoke["status"] = json!("revoked");
        revoke["statement_id"] = json!("org-stmt-owner-2");
        revoke["revokes_statement_id"] = json!("org-stmt-owner");
        let effect = apply(&mut state, revoke);
        assert!(matches!(
            effect,
            ProjectionEffect::RealmOrganizationProjected { ref status, .. } if status == "revoked"
        ));
        // Verified relationship + control scope immediately gone.
        assert!(
            state
                .verified_organization_relationships(REALM, now())
                .is_empty()
        );
        // Audit row retained with the revoking statement_id.
        let all = state.realm_organization_statements_for_realm(REALM);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].status, "revoked");
        assert_eq!(all[0].statement_id, "org-stmt-owner-2");
        assert_eq!(
            all[0].revokes_statement_id.as_deref(),
            Some("org-stmt-owner")
        );
    }

    #[test]
    fn sol_org_06_lifecycle_phase_split() {
        // SOL-ORG-06 read contract: the org-relationship projection the
        // `ak.self.realm_organization.read.list.v1` handler reads must expose
        // BOTH the active and the revoked statement, with exactly the active,
        // in-window one classified `verified_active` (the others
        // `revoked_or_expired`). An org with a currently-verified statement is
        // never also surfaced as an unverified declared hint.
        let mut state = ProjectionState::new();
        apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["realm_admin"]),
        );
        let mut revoke = active_payload(REALM, ORG2, "governance", &["moderation_policy"]);
        revoke["status"] = json!("revoked");
        revoke["statement_id"] = json!("org-stmt-governance-2");
        revoke["revokes_statement_id"] = json!("org-stmt-governance");
        apply(&mut state, revoke);

        let rows = state.realm_organization_statements_for_realm(REALM);
        assert_eq!(rows.len(), 2, "both active and revoked rows are projected");
        let verified: Vec<_> = rows
            .iter()
            .filter(|row| row.is_effective_active(now()))
            .map(|row| row.organization_id.clone())
            .collect();
        // Exactly the active statement maps onto verified_active.
        assert_eq!(verified, vec![org_id(ORG)]);
        // The revoked statement maps onto revoked_or_expired (not verified).
        assert!(
            rows.iter()
                .any(|row| row.organization_id == org_id(ORG2) && !row.is_effective_active(now()))
        );
    }

    #[test]
    fn expired_statement_is_not_verified() {
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        payload["expires_at"] = json!("2026-06-25T06:00:00.000Z");
        apply(&mut state, payload);
        // Row stored, but not verified at `now()` (12:00 > 06:00 expiry).
        assert_eq!(
            state.realm_organization_statements_for_realm(REALM).len(),
            1
        );
        assert!(
            state
                .verified_organization_relationships(REALM, now())
                .is_empty()
        );
    }

    #[test]
    fn not_yet_valid_statement_is_not_verified() {
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        payload["not_before"] = json!("2026-06-26T00:00:00.000Z");
        apply(&mut state, payload);
        assert!(
            state
                .verified_organization_relationships(REALM, now())
                .is_empty()
        );
    }

    #[test]
    fn missing_delegation_for_delegated_role_is_rejected() {
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        payload["authorization"]["issuer_role"] = json!("governance_service");
        let effect = apply(&mut state, payload);
        assert!(matches!(effect, ProjectionEffect::Rejected { .. }));
        assert!(
            state
                .realm_organization_statements_for_realm(REALM)
                .is_empty()
        );
    }

    #[test]
    fn delegated_role_with_delegation_ref_fails_closed_in_reducer() {
        // The in-reducer NoDelegationResolver cannot resolve any delegation, so
        // even a well-formed delegated statement is rejected here (it must be
        // accepted at the admission layer where a runtime resolver is wired).
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "governance", &["moderation_policy"]);
        payload["authorization"]["issuer_role"] = json!("account_authority");
        payload["authorization"]["delegation_ref"] =
            json!("ak:grant:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19");
        let effect = apply(&mut state, payload);
        assert!(matches!(effect, ProjectionEffect::Rejected { .. }));
    }

    #[test]
    fn bad_proof_is_rejected() {
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        payload["authorization"]["proof"] = json!("   ");
        let effect = apply(&mut state, payload);
        assert!(matches!(effect, ProjectionEffect::Rejected { .. }));
    }

    #[test]
    fn realm_id_mismatch_is_rejected() {
        let mut state = ProjectionState::new();
        // Envelope realm REALM, but payload claims REALM_OTHER.
        let payload = active_payload(REALM_OTHER, ORG, "owner", &["realm_admin"]);
        let effect = state.apply_realm_organization(&op(REALM, payload), now());
        assert!(matches!(effect, ProjectionEffect::Rejected { .. }));
    }

    #[test]
    fn malformed_payload_is_schema_violation() {
        let mut state = ProjectionState::new();
        let effect = apply(
            &mut state,
            json!({ "organization_ref": "ak:did_core:web:org.example" }),
        );
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_wire::ErrorCode::SCHEMA_VIOLATION
        ));
    }

    #[test]
    fn proof_digest_is_recorded_not_raw_bytes() {
        let mut state = ProjectionState::new();
        apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["realm_admin"]),
        );
        let row = state.realm_organization_statements_for_realm(REALM)[0];
        let digest = row.proof_digest.as_deref().expect("proof digest");
        assert_ne!(digest, "c2ln");
        assert!(!digest.is_empty());
    }
}
