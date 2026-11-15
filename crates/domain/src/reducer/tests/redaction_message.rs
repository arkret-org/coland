use super::*;

#[test]
fn redaction_human_reason_reads_the_single_registered_member() {
    let payload = serde_json::json!({
        "message_id": "ak:message:AYTeR35PxnHtaUMXFLoHqGA1yiou3pai07-tzQyViJnt",
        "reason": "machine policy"
    });

    assert_eq!(
        redaction_human_reason(&payload).as_deref(),
        Some("machine policy")
    );

    // Both redaction payload classes are closed and register only `reason`,
    // so no alternative spelling is wire-reachable.
    let unregistered = serde_json::json!({
        "message_id": "ak:message:AYTeR35PxnHtaUMXFLoHqGA1yiou3pai07-tzQyViJnt",
        "human_reason": "moderator request"
    });
    assert_eq!(redaction_human_reason(&unregistered), None);
}

#[test]
fn message_create_and_query() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let op = make_operation(
        arkret_wire::EventKind::MessageCreate,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        serde_json::json!({
            "event_id": "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
            "sender": "ak:did_core:web:alice",
            "strand_id": "ak:strand:1",
            "content": {"kind": "ak.content.text", "body": "hello"}
        }),
    );
    let effect = state.apply(&op, &hlc);
    assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));

    let msgs = state.messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb");
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs[0].event_id,
        "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R"
    );
}

#[test]
fn redaction_hides_message() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
                "sender": "ak:did_core:web:alice",
                "strand_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "message_id": "ak:message:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
                "sender": "ak:did_core:web:alice",
                "reason": "wrong room"
            }),
        ),
        &hlc,
    );

    assert!(
        state
            .messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
            .is_empty()
    );
    assert!(
        state
            .redactions
            .contains("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
    );
    // The original MessageState is preserved (only the
    // parallel cell + flat redactions index move).
    assert!(
        state
            .messages
            .contains_key("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
    );
    let cell = state
        .redaction_cells
        .get("ak:message:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
        .cloned()
        .unwrap();
    assert_eq!(cell.by, account_actor_string("ak:did_core:web:alice"));
    assert_eq!(cell.reason.as_deref(), Some("wrong room"));
}

// ── Redaction reducer tests ───────────────────────────────────────

fn redact_make_message(state: &mut ProjectionState, hlc: &ServerHlc, event_id: &str) {
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": event_id,
                "sender": "ak:did_core:web:alice",
                "strand_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        ),
        hlc,
    );
}

#[test]
fn mal14_tombstone_visible_to_author() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:AVH4Dy1ng6HIwqHRIemmcRdGF6ErKqNeNOzRpc2sGDV2";
    redact_make_message(&mut state, &hlc, event_id);
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "message_id": message_id_from_event_id(event_id),
                "sender": "ak:did_core:web:alice",
                "reason": "policy:auto",
            }),
        ),
        &hlc,
    );
    let view = state.projected_message(event_id, true).unwrap();
    // Author still sees the original payload (audit-view).
    assert!(view.content.is_some(), "author should see original content");
    // Tombstone metadata is also present.
    let r = view.redaction.unwrap();
    assert_eq!(r.by, account_actor_string("ak:did_core:web:alice"));
    assert_eq!(r.reason.as_deref(), Some("policy:auto"));
}

#[test]
fn mal14_tombstone_hidden_from_members() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:AfqWfYd8Ne_ep-HLww8vFeZV55RaKPRMN4cOWHP3uQt8";
    redact_make_message(&mut state, &hlc, event_id);
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "message_id": message_id_from_event_id(event_id),
                "sender": "ak:did_core:web:alice",
            }),
        ),
        &hlc,
    );
    let view = state.projected_message(event_id, false).unwrap();
    assert!(view.content.is_none(), "non-author should see tombstone");
    assert!(view.redaction.is_some());
}

#[test]
fn mal14_late_arriving_redaction_still_takes_effect() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:AWFQAWZebUfJ-E0wgUFcO4HGLOIjmZHbM8U5PZLfGeED";
    // Pre-create the projected message and let the projection
    // rendering query it once before the redaction lands.
    redact_make_message(&mut state, &hlc, event_id);
    let pre = state.projected_message(event_id, false).unwrap();
    assert!(pre.content.is_some());
    assert!(pre.redaction.is_none());
    // Now a delayed redaction arrives.
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "message_id": message_id_from_event_id(event_id),
                "sender": "ak:did_core:web:alice",
                "reason": "late",
            }),
        ),
        &hlc,
    );
    let post = state.projected_message(event_id, false).unwrap();
    assert!(
        post.content.is_none(),
        "late-arriving redaction must hide payload from non-authors"
    );
    let r = post.redaction.unwrap();
    assert_eq!(r.reason.as_deref(), Some("late"));
    // The flat-redactions index now has the entry.
    assert!(state.redactions.contains(event_id));
    // Author still sees the audit-view.
    let post_author = state.projected_message(event_id, true).unwrap();
    assert!(post_author.content.is_some());
}

fn accepted_reaction(kind: arkret_wire::EventKind, position: u64) -> Operation {
    let operation = make_operation(
        kind,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        serde_json::json!({
            "target_ref":"ak:message:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R", "key":"👍"
        }),
    );
    let source = arkret_wire::CommittedEventRef {
        event_id: operation.context.event_id.clone(),
        commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("reaction:{position}").as_bytes(),
        )),
        stream_ref: arkret_wire::CommitStreamRef::from_scope(
            &operation.context.accepted_scope_ref,
            Some(operation.realm_id.clone()),
        )
        .unwrap(),
        stream_position: position,
    };
    operation.with_committed_ref(source).unwrap()
}

#[test]
fn reaction_active_current_preserves_empty_revision_and_ignores_old_prefix() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let add = accepted_reaction(arkret_wire::EventKind::ReactionAdd, 2);
    let remove = accepted_reaction(arkret_wire::EventKind::ReactionRemove, 3);
    state.apply(&add, &hlc);
    let target = "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R";
    assert_eq!(state.reactions_for_event(target).len(), 1);
    let entry = state.reactions_for_event(target)[0];
    assert_eq!(entry.actor_id, add.context.sender);
    assert_eq!(Some(&entry.source), add.context.committed_ref.as_ref());
    state.apply(&remove, &hlc);
    assert!(state.reactions_for_event(target).is_empty());
    assert!(state.reactions.contains_key(target));
    assert_eq!(state.reaction_revisions[target].stream_position, 3);
    assert!(matches!(state.apply(&add, &hlc), ProjectionEffect::Ignored));
    assert!(state.reactions_for_event(target).is_empty());
    assert_eq!(state.reaction_revisions[target].stream_position, 3);
}

#[test]
fn reaction_cache_requires_accepted_source_and_full_actor_identity() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let first = accepted_reaction(arkret_wire::EventKind::ReactionAdd, 1);
    let mut missing = first.clone();
    missing.context.committed_ref = None;
    assert!(matches!(
        state.apply(&missing, &hlc),
        ProjectionEffect::Rejected { .. }
    ));
    state.apply(&first, &hlc);
    let mut second = accepted_reaction(arkret_wire::EventKind::ReactionAdd, 2);
    let account = second.context.sender.as_account_id().unwrap();
    second.context.sender = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        account.principal_id.clone(),
        "ak:did_core:web:other-station.example".parse().unwrap(),
    ));
    state.apply(&second, &hlc);
    let target = "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R";
    assert_eq!(state.reactions_for_event(target).len(), 2);
    let mut remove = accepted_reaction(arkret_wire::EventKind::ReactionRemove, 3);
    remove.context.sender = second.context.sender.clone();
    state.apply(&remove, &hlc);
    let remaining = state.reactions_for_event(target);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].actor_id, first.context.sender);
}

#[test]
fn membership_join_leave() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "public".to_owned());

    let join_payload = serde_json::json!({
        "realm_id": realm_id,
        "member_id": account_actor("ak:did_core:web:bob"),
        "membership": "join"
    });
    let mut join = make_operation(arkret_wire::EventKind::MemberState, realm_id, join_payload);
    join.context.sender = account_actor("ak:did_core:web:bob");
    state.apply_projected(&join, &hlc);
    assert_eq!(state.members_of_realm(realm_id).len(), 1);

    let leave_payload = serde_json::json!({
        "member_id": account_actor("ak:did_core:web:bob"),
        "membership": "leave"
    });
    let mut leave = make_operation(arkret_wire::EventKind::MemberState, realm_id, leave_payload);
    leave.context.sender = account_actor("ak:did_core:web:bob");
    state.apply_projected(&leave, &hlc);
    assert_eq!(state.members_of_realm(realm_id).len(), 0);
}

#[test]
fn message_revise_creates_chain() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
                "sender": "ak:did_core:web:alice",
                "strand_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "original"}
            }),
        ),
        &hlc,
    );

    let revise = make_operation(
        arkret_wire::EventKind::MessageRevise,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        serde_json::json!({
            "message_id": "ak:message:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
            "content": {"kind": "ak.content.text", "body": "revised"}
        }),
    );
    let revision_id = revise.context.event_id.to_string();
    state.apply(&revise, &hlc);

    let msgs = state.messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].event_id, revision_id);
    assert_eq!(msgs[0].content["body"], "revised");
    assert_eq!(state.messages.len(), 2);
    let revision = state.messages.get(&revision_id).unwrap();
    assert_eq!(
        revision.revision_of.as_deref(),
        Some("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
    );
}

#[test]
fn message_revise_resolves_schema_message_id_and_preserves_event_id() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R";
    let message_id = message_id_from_event_id(event_id);
    let revision_event_id = "ak:event:AY3yMyh6E9PG9a6M5sarXiHRk89RGO88qpJX6TmFfw4K";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": event_id,
                "sender": "ak:did_core:web:alice",
                "strand_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "original"}
            }),
        ),
        &hlc,
    );

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRevise,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": revision_event_id,
                "message_id": message_id,
                "content": {"kind": "ak.content.text", "body": "revised"}
            }),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::MessageRevised { ref original_id, ref revision }
            if original_id == event_id && revision.event_id == revision_event_id
    ));
    let msgs = state.messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].event_id, revision_event_id);
    assert_eq!(msgs[0].message_id, message_id);
    assert_eq!(msgs[0].revision_of.as_deref(), Some(event_id));
    assert_eq!(msgs[0].content["body"], "revised");
}

#[test]
fn redaction_accepts_schema_message_id_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:ARM_vloO6RecwhzJiZLJp_sEMbLAlYxMqDRCnIx5zTYC";
    let message_id = message_id_from_event_id(event_id);
    let redaction_event_id = "ak:event:AeV1nAe67z8tQd57ghKnYX3pO3XHc0CWcgZeG1UtWi7m";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": event_id,
                "sender": "ak:did_core:web:alice",
                "strand_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        ),
        &hlc,
    );
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": redaction_event_id,
                "message_id": message_id,
                "sender": "ak:did_core:web:alice",
                "reason": "wrong room"
            }),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::MessageRedacted { event_id: target } if target == event_id
    ));
    assert!(state.redactions.contains(event_id));
    assert!(!state.redactions.contains(redaction_event_id));
    assert!(state.redaction_cells.contains_key(&message_id));
    assert!(
        state
            .projected_message(event_id, false)
            .unwrap()
            .content
            .is_none()
    );
}

#[test]
fn redaction_by_message_id_hides_latest_revision() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:AYFOTCo9ihbm1rHVVboZzk8j6Y76eIOqKgzp0m3azE5f";
    let message_id = message_id_from_event_id(event_id);
    let revision_event_id = "ak:event:AVvHap65LnD8zHKvce7Yq8fodmj2dYC4w32MPRABihB9";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": event_id,
                "sender": "ak:did_core:web:alice",
                "strand_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "original"}
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRevise,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": revision_event_id,
                "message_id": message_id,
                "content": {"kind": "ak.content.text", "body": "revised"}
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": "ak:event:AaviAQUPcXQA_m9RNFUvox0-znrutEvE8BkTgEoWNTJx",
                "message_id": message_id,
                "sender": "ak:did_core:web:alice",
                "reason": "wrong room"
            }),
        ),
        &hlc,
    );

    assert!(
        state
            .messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
            .is_empty()
    );
    assert!(
        state
            .projected_message(revision_event_id, false)
            .unwrap()
            .content
            .is_none()
    );
    assert!(
        state
            .projected_message(event_id, false)
            .unwrap()
            .content
            .is_none()
    );
    assert!(state.redaction_cells.contains_key(&message_id));
}
