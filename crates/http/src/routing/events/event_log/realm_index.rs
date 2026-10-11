use super::*;

#[cfg(test)]
pub(super) fn event_string_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

/// True when an invite is authored by the authenticated inviter Account.
/// Used to admit private delivery on a recipient Station outside the Realm.
///
/// `InviteCreatePayload` deliberately does not duplicate an
/// `inviter_account_id`: the signed full `actor_id` is the inviter identity.
/// Requiring a payload copy here made every canonical directed invite fail the
/// recipient's private-ingress membership bypass.
pub(super) fn invite_create_actor_is_inviter(
    object: &serde_json::Map<String, Value>,
    actor: &str,
) -> bool {
    object
        .get("actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
        .is_some_and(|author| {
            author.signing_principal_id().as_str() == actor && author.as_account_id().is_some()
        })
}

#[cfg(test)]
mod private_invite_tests {
    use super::*;

    #[test]
    fn canonical_invite_payload_uses_signed_actor_as_inviter() {
        let principal = "ak:did_core:webvh:QmZx45CviywxAszP7ZLdbGWXTKbaGqyZEBKJ1mu3U1Lw6P";
        let event = serde_json::json!({
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": principal,
                    "station_id": "ak:did_core:webvh:QmRRRztcj9JJ2sMx7g9CNZEoUJskv5ndMNFsDvQKxwx13a"
                }
            },
            "payload": {
                "invitee_account_id": {
                    "principal_id": "ak:did_core:webvh:QmXaqGi2FZv9YMf441tjbm5nz8ZKnafjfE2S7QWzyRHqj1",
                    "station_id": "ak:did_core:webvh:QmNzZX7HtR8SS1ANSNZZLSgJtpFDuUgFd7aP3PgkPtXZCV"
                },
                "introduction_evidence_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "expires_at": "2026-09-11T10:15:28.202Z"
            }
        });
        let object = event.as_object().expect("fixture object");

        assert!(invite_create_actor_is_inviter(object, principal));
        assert!(!invite_create_actor_is_inviter(
            object,
            "ak:did_core:webvh:QmXaqGi2FZv9YMf441tjbm5nz8ZKnafjfE2S7QWzyRHqj1"
        ));
    }
}

#[cfg(test)]
/// True when a `ak.member.state` event is a self-authored join-policy entry by
/// a not-yet-member applicant:
///   - `membership=knock` — stage 1 of the application-review path (join-policy.md §7.1); and
///   - `membership=join` carrying `gate_proofs[]` — the auto-resolve path (join-policy.md §5),
///     where the not-yet-member submits its own join with inline gate proofs.
///
/// In both cases the applicant is not yet a member, so the generic
/// `realm_has_member` gate would wrongly reject the entry. The actual
/// join-policy gate / review enforcement runs in
/// `check_membership_join_admission`
/// later in the submit pipeline, not here.
pub(super) fn member_self_knock(object: &serde_json::Map<String, Value>, actor: &str) -> bool {
    if object.get("kind").and_then(Value::as_str)
        != Some(arkret_wire::EventKind::MemberState.as_str())
    {
        return false;
    }
    let Some(payload) = object.get("payload") else {
        return false;
    };
    let membership = payload.get("membership").and_then(Value::as_str);
    let is_knock = membership == Some("knock");
    let is_gate_proof_join = membership == Some("join")
        && payload
            .get("gate_proofs")
            .and_then(Value::as_array)
            .is_some_and(|proofs| !proofs.is_empty());
    if !is_knock && !is_gate_proof_join {
        return false;
    }
    let author = object
        .get("actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok());
    let member = payload
        .get("member_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok());
    author.zip(member).is_some_and(|(author, member)| {
        author == member && author.signing_principal_id().as_str() == actor
    })
}

#[cfg(test)]
/// Invite membership exemptions belong to the authenticated exact Account,
/// never another Station's account or a service actor with the same signer.
fn invite_event_account<'a>(
    object: &serde_json::Map<String, Value>,
    actor: &'a arkret_wire::ActorId,
) -> Option<&'a arkret_wire::AccountId> {
    let author = object
        .get("actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())?;
    if author != *actor {
        return None;
    }
    actor.as_account_id()
}

#[cfg(test)]
async fn directed_pending_invite_matches(
    state: &AppState,
    realm_id: &str,
    invite_id: &str,
    account: &arkret_wire::AccountId,
) -> bool {
    let (Ok(realm_id), Ok(invite_id)) = (
        arkret_wire::RealmId::new(realm_id.to_owned()),
        arkret_wire::InviteId::new(invite_id.to_owned()),
    ) else {
        return false;
    };
    state
        .persistence()
        .open_directed_invites_for_invitee(account, Some(&realm_id))
        .await
        .is_ok_and(|invites| {
            invites.into_iter().any(|invite| {
                invite.invite_id == invite_id
                    && matches!(
                        invite.state,
                        arkret_wire::InviteState::Pending | arkret_wire::InviteState::Claimed
                    )
                    && invite.expires_at > now()
            })
        })
}

#[cfg(test)]
pub(super) async fn member_join_accepts_pending_invite(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor: &arkret_wire::ActorId,
    realm_id: &str,
) -> bool {
    // Invitation acceptance has one canonical wire event. A bare
    // `ak.member.state{membership:join, invite_ref}` would bypass the
    // invite-lifecycle transition and the registry's atomic two-cell
    // contract, so it must not receive the not-yet-member exemption.
    if object.get("kind").and_then(Value::as_str)
        != Some(arkret_wire::EventKind::InviteAccept.as_str())
    {
        return false;
    }
    let Some(account) = invite_event_account(object, actor) else {
        return false;
    };
    let Some(payload) = object.get("payload") else {
        return false;
    };
    // `event-payload.schema.json#/$defs/invite_accept_payload` is
    // `additionalProperties:false` over `{invite_id}`: the accepting subject
    // is the exact Station-bound Event actor, so there is
    // no payload actor field to read, and `invite_id` is the only target
    // carrier (`invite_ref` belongs to `membership_payload`, a different kind).
    let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
        return false;
    };
    directed_pending_invite_matches(state, realm_id, invite_id, account).await
}

#[cfg(test)]
pub(super) async fn invitee_cancels_pending_invite(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor: &arkret_wire::ActorId,
    realm_id: &str,
) -> bool {
    if object.get("kind").and_then(Value::as_str)
        != Some(arkret_wire::EventKind::InviteCancel.as_str())
    {
        return false;
    }
    let Some(account) = invite_event_account(object, actor) else {
        return false;
    };
    let Some(payload) = object.get("payload") else {
        return false;
    };
    let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
        return false;
    };
    directed_pending_invite_matches(state, realm_id, invite_id, account).await
}

#[cfg(test)]
pub(super) async fn invite_claim_actor_claims_pending_third_party_invite(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor: &arkret_wire::ActorId,
    realm_id: &str,
) -> bool {
    if object.get("kind").and_then(Value::as_str) != Some(arkret_wire::event_kind_str::INVITE_CLAIM)
    {
        return false;
    }
    let Some(account) = invite_event_account(object, actor) else {
        return false;
    };
    let Some(payload) = object.get("payload") else {
        return false;
    };
    if !payload
        .get("subject_account_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::AccountId>(value).ok())
        .is_some_and(|subject| subject == *account)
    {
        return false;
    }
    let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
        return false;
    };
    let (Ok(realm_id), Ok(invite_id)) = (
        arkret_wire::RealmId::new(realm_id.to_owned()),
        arkret_wire::InviteId::new(invite_id.to_owned()),
    ) else {
        return false;
    };
    let Ok(invites) = state.persistence().invites_in_realm(Some(&realm_id)).await else {
        return false;
    };
    let Some(invite) = invites
        .into_iter()
        .find(|invite| invite.invite_id == invite_id)
    else {
        return false;
    };
    let is_pending_third_party =
        invite.state == arkret_wire::InviteState::Pending && invite.third_party_invite.is_some();
    let is_duplicate_claim_by_invitee = invite.state == arkret_wire::InviteState::Claimed
        && invite
            .accepted_claim
            .as_ref()
            .is_some_and(|claim| claim.subject_account_id == *account);
    if !is_pending_third_party && !is_duplicate_claim_by_invitee {
        return false;
    }
    // The claim writer checks canonical expiry at its accepting cut. A refused
    // claim writes nothing; only an independently accepted revoke expires it.
    invite
        .invitee_account_id
        .as_ref()
        .is_none_or(|invitee_id| invitee_id == account)
}

#[cfg(test)]
/// When an `ak.realm.create` Event commits, materialise the in-memory Realm
/// directory entry. Ordinary Collaboration genesis does not seed creator
/// membership here: its final explicit `ak.member.state(join)` slot is the
/// sole membership write. Minimal control-realm and direct-conversation
/// bootstrap retain their dedicated implicit-founder semantics.
///
/// Extracted out of `submit_event` (called once after `store.put`
/// succeeds for a `ak.realm.create` event) so the canonical Event
/// Envelope path owns Realm bootstrap state.
pub(super) async fn bootstrap_realm_member_index(
    state: &AppState,
    realm_id: &str,
    actor: &str,
    object: &serde_json::Map<String, Value>,
) {
    let Ok(realm_id_typed) = arkret_identifiers::RealmId::new(realm_id.to_owned()) else {
        tracing::warn!(%realm_id, "bootstrap_realm_member_index: invalid realm_id shape");
        return;
    };
    let Ok(actor_typed) = arkret_identifiers::DidCoreId::new(actor.to_owned()) else {
        tracing::warn!(%actor, "bootstrap_realm_member_index: invalid actor DID");
        return;
    };
    let payload_object = object
        .get("payload")
        .and_then(|payload| payload.get("object"));
    let title = payload_object
        .and_then(|create_object| create_object.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let summary = payload_object
        .and_then(|create_object| create_object.get("summary"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let discoverability = payload_object
        .and_then(|create_object| create_object.get("default_discoverability"))
        .and_then(Value::as_str)
        .unwrap_or("invite_only")
        .to_owned();
    let history_access = payload_object
        .and_then(|create_object| create_object.get("history_access"))
        .and_then(Value::as_str)
        .unwrap_or("since_join")
        .to_owned();
    let encryption_profile = payload_object
        .and_then(|create_object| create_object.get("encryption_profile"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let preview_policy = payload_object
        .and_then(|create_object| create_object.get("preview_policy"))
        .cloned();
    let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
    let asset_privacy_policy = payload_object
        .and_then(|create_object| create_object.get("asset_privacy_policy"))
        .cloned();
    let asset_privacy_policy_digest = asset_privacy_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let plaintext_visible_services = std::collections::BTreeSet::new();
    let plaintext_visible_service_classes = std::collections::BTreeMap::new();
    let minimal_metadata_realm = payload_object
        .is_some_and(coland_services::operation_semantics::payload_declares_minimal_metadata_realm);
    // `object` is the accepted Event envelope, so the provenance this entry needs
    // is right here. It used to inherit the constructor's minted placeholder: a
    // directory entry for a real Realm advertising an Event id that resolves to
    // nothing, with the real id one field away.
    let provenance = match event_string_field(object, &["event_id"]) {
        Some(event_id) => coland_services::events::DirectoryProvenance::AcceptedEvent(event_id),
        None => {
            tracing::warn!(%realm_id, "bootstrap_realm_member_index: envelope carries no event_id");
            coland_services::events::DirectoryProvenance::LocalOnly
        }
    };
    let mut entry =
        crate::state::RealmDirectoryEntry::new(realm_id_typed.clone(), title, provenance);
    entry.description = summary.clone();
    entry.realm_class = payload_object
        .and_then(|object| object.get("realm_class"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    entry.default_join_rule = payload_object
        .and_then(|object| object.get("default_join_rule"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    entry.public = discoverability == "public";
    let purpose = payload_object
        .and_then(|object| object.get("purpose"))
        .and_then(Value::as_str);
    if purpose != Some("collaboration") {
        entry.members.insert(actor_typed);
    }
    state.realm_directory().upsert(entry);
    let meta = coland_services::events::RealmMetadata {
        owner: actor.to_owned(),
        deleted: false,
        discoverability,
        history_access,
        preview_policy,
        preview_policy_digest,
        asset_privacy_policy,
        asset_privacy_policy_digest,
        encryption_profile,
        plaintext_visible_services,
        plaintext_visible_service_classes,
        minimal_metadata_realm,
        created_at: super::now(),
        updated_at: super::now(),
    };
    // The canonical bootstrap batch can project later policy facets before
    // this Realm-create index hook runs. Never replace that richer durable
    // metadata with the create envelope's intentionally sparse defaults.
    match state.realms().realm_metadata(realm_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Err(error) = state.realms().store_realm_metadata(realm_id, meta).await {
                tracing::error!(%error, %realm_id, "bootstrap_realm_member_index: failed to persist Realm meta record");
            }
        }
        Err(error) => {
            tracing::error!(%error, %realm_id, "bootstrap_realm_member_index: failed to read existing Realm meta record");
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ALICE: &str = "ak:did_core:web:alice.example";
    const BOB: &str = "ak:did_core:web:bob.example";

    fn account_actor(principal_id: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(principal_id.to_owned()).unwrap(),
            crate::test_event::station_id(),
        ))
    }

    fn member_state(payload: Value) -> serde_json::Map<String, Value> {
        json!({
            "kind": arkret_wire::EventKind::MemberState.as_str(),
            "actor_id": account_actor(ALICE),
            "payload": payload,
        })
        .as_object()
        .expect("event object")
        .clone()
    }

    #[tokio::test]
    async fn realm_create_index_does_not_erase_later_bootstrap_policy_projection() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        let service_id = "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x";
        let timestamp = now();
        state
            .realms()
            .store_realm_metadata(
                realm_id,
                coland_services::events::RealmMetadata {
                    owner: ALICE.to_owned(),
                    deleted: false,
                    discoverability: "invite_only".to_owned(),
                    history_access: "since_join".to_owned(),
                    preview_policy: None,
                    preview_policy_digest: None,
                    asset_privacy_policy: None,
                    asset_privacy_policy_digest: None,
                    encryption_profile: Some("none".to_owned()),
                    plaintext_visible_services: std::collections::BTreeSet::from([
                        service_id.to_owned()
                    ]),
                    plaintext_visible_service_classes: Default::default(),
                    minimal_metadata_realm: false,
                    created_at: timestamp,
                    updated_at: timestamp,
                },
            )
            .await
            .unwrap();
        let envelope = json!({
            "event_id": "ak:event:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD",
            "payload": {"object": {"purpose": "collaboration"}}
        })
        .as_object()
        .unwrap()
        .clone();

        bootstrap_realm_member_index(&state, realm_id, ALICE, &envelope).await;

        let persisted = state
            .realms()
            .realm_metadata(realm_id)
            .await
            .unwrap()
            .unwrap();
        assert!(persisted.plaintext_visible_services.contains(service_id));
    }

    /// A self-authored knock names the exact member ActorId, including Station.
    #[test]
    fn member_self_knock_requires_exact_member_actor() {
        assert!(member_self_knock(
            &member_state(json!({"membership": "knock", "member_id": account_actor(ALICE)})),
            ALICE
        ));
        assert!(!member_self_knock(
            &member_state(json!({"membership": "knock", "member_id": account_actor(BOB)})),
            ALICE
        ));
        let other_account = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(ALICE.to_owned()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example".to_owned())
                .unwrap(),
        ));
        assert!(!member_self_knock(
            &member_state(json!({"membership": "knock", "member_id": other_account})),
            ALICE
        ));
        assert!(!member_self_knock(
            &member_state(json!({"membership": "knock", "actor_id": ALICE})),
            ALICE
        ));
    }

    /// The not-yet-member exemption is only for `ak.member.state`; the invite
    /// acceptance path has its own canonical event.
    #[test]
    fn member_self_knock_only_applies_to_member_state() {
        let mut object =
            member_state(json!({"membership": "knock", "member_id": account_actor(ALICE)}));
        object.insert(
            "kind".to_owned(),
            json!(arkret_wire::EventKind::InviteAccept.as_str()),
        );
        assert!(!member_self_knock(&object, ALICE));
    }

    #[tokio::test]
    async fn invite_membership_exemptions_fail_without_committed_invite() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let actor = account_actor(ALICE);
        let account = actor.as_account_id().unwrap();
        let other = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            account.principal_id.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        let service = arkret_wire::ActorId::service(account.principal_id.clone());
        let invite_id = "ak:invite:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
        let realm_id = "ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C";
        for kind in ["ak.invite.accept", "ak.invite.cancel"] {
            let object = json!({
                "kind": kind,
                "actor_id": actor,
                "payload": {"invite_id": invite_id}
            })
            .as_object()
            .unwrap()
            .clone();
            for caller in [&actor, &other, &service] {
                let accepted = if kind == "ak.invite.accept" {
                    member_join_accepts_pending_invite(&state, &object, caller, realm_id).await
                } else {
                    invitee_cancels_pending_invite(&state, &object, caller, realm_id).await
                };
                // An Event naming a plausible InviteId cannot stand in
                // for accepted create and typed lifecycle evidence.
                assert!(!accepted, "{kind}: {caller}");
                let mut other_event = object.clone();
                other_event.insert("actor_id".to_owned(), json!(caller));
                let own_event_accepted = if kind == "ak.invite.accept" {
                    member_join_accepts_pending_invite(&state, &other_event, caller, realm_id).await
                } else {
                    invitee_cancels_pending_invite(&state, &other_event, caller, realm_id).await
                };
                assert!(!own_event_accepted, "own {kind}: {caller}");
            }
        }

        // A well-formed 3PID subject cannot claim an uncommitted Invite.
        let mut claim = json!({
            "kind": "ak.invite.claim",
            "actor_id": actor,
            "payload": {"invite_id": invite_id, "subject_account_id": account}
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(
            !invite_claim_actor_claims_pending_third_party_invite(&state, &claim, &actor, realm_id)
                .await
        );
        claim.get_mut("payload").unwrap()["subject_account_id"] = json!(other.as_account_id());
        assert!(
            !invite_claim_actor_claims_pending_third_party_invite(&state, &claim, &actor, realm_id)
                .await
        );
        claim.insert(
            "payload".to_owned(),
            json!({"invite_id": invite_id, "subject_id": ALICE}),
        );
        assert!(
            !invite_claim_actor_claims_pending_third_party_invite(&state, &claim, &actor, realm_id)
                .await
        );
    }
}
