// @generated automatically by Diesel CLI.

diesel::table! {
    event_notification_relay (id) {
        id -> Uuid,
        payload -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    account_data_changes (position) {
        position -> Int8,
        actor_id -> Text,
        account_data_key -> Text,
        payload -> Jsonb,
        revision -> Int8,
        tombstone -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    account_status_affected_services (account_id, service_id, source) {
        account_id -> Jsonb,
        service_id -> Text,
        source -> Text,
        first_observed_at -> Timestamptz,
        last_observed_at -> Timestamptz,
    }
}

diesel::table! {
    account_status_propagations (account_status_record_id) {
        account_authority_id -> Text,
        account_id -> Jsonb,
        account_status_record_id -> Text,
        status_seq -> Int8,
        state -> Text,
        deadline_at -> Timestamptz,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    account_status_propagation_targets (account_status_record_id, destination_id) {
        account_status_record_id -> Text,
        destination_id -> Text,
        acknowledged_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    account_data_change_retention (actor_id) {
        actor_id -> Text,
        latest_position -> Int8,
        retained_through_position -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    account_datas (id) {
        id -> Uuid,
        actor_id -> Text,
        account_data_key -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    account_lifecycle (account_pk) {
        account_pk -> Int8,
        state -> Text,
        reason -> Nullable<Text>,
        changed_by -> Nullable<Jsonb>,
        changed_at -> Timestamptz,
    }
}

diesel::table! {
    account_localparts (id) {
        id -> Uuid,
        account_pk -> Int8,
        localpart -> Text,
        is_primary -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    accounts (pk) {
        pk -> Int8,
        principal_id -> Text,
        station_id -> Text,
        display_name -> Nullable<Text>,
        payload -> Jsonb,
        disabled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_membership_cleanup_intents (cleanup_intent_digest) {
        cleanup_intent_digest -> Text,
        realm_id -> Text,
        controller_terminal_event_id -> Text,
        record_json -> Jsonb,
        accepted_at -> Timestamptz,
        cleanup_due_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_participation (id) {
        id -> Uuid,
        agent_id -> Text,
        scope_kind -> Text,
        scope_key -> Text,
        realm_id -> Text,
        scope -> Jsonb,
        version -> Int8,
        reply_message -> Bool,
        reaction_add -> Bool,
        reaction_remove -> Bool,
        accept_third_party_mention -> Bool,
        act_on_behalf -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_principals (id) {
        id -> Text,
        controller_principal_id -> Text,
        principal_control_realm_id -> Text,
        controller_authorization_ref -> Text,
        display_name -> Nullable<Text>,
        agent_slug -> Nullable<Text>,
        avatar_blob_ref -> Nullable<Text>,
        state -> Text,
        requested_scope -> Nullable<Jsonb>,
        accountability -> Nullable<Jsonb>,
        provision_event_refs -> Nullable<Jsonb>,
        pairing_request_id -> Nullable<Text>,
        paired_pairing_request_id -> Nullable<Text>,
        paired_request_digest -> Nullable<Text>,
        pending_pairing_commit_intent -> Nullable<Jsonb>,
        pairing_code -> Nullable<Text>,
        pairing_expires_at -> Nullable<Timestamptz>,
        approval_request_id -> Nullable<Text>,
        controller_account_pk -> Nullable<Int8>,
        recipient_id -> Nullable<Text>,
        runtime_key_binding_digest -> Nullable<Text>,
        approval_notification_id -> Nullable<Uuid>,
        runtime_key_material -> Nullable<Jsonb>,
        approval_requested_at -> Nullable<Timestamptz>,
        authorized_event_ref -> Nullable<Text>,
        authorized_verification_method -> Nullable<Text>,
        authorized_public_key_digest -> Nullable<Text>,
        authorized_key_event -> Nullable<Jsonb>,
        state_changed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_sidecar_contexts (sidecar_pk, normalized_context_ref_digest, version) {
        sidecar_pk -> Int8,
        normalized_context_ref_digest -> Text,
        version -> Int8,
        normalized_context_ref -> Jsonb,
        predecessor_event_ref -> Nullable<Bytea>,
        attach_event_ref -> Bytea,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    agent_sidecars (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        controller_account_id -> Jsonb,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    applet_managed_identities (applet_id, target_station_id) {
        applet_id -> Text,
        target_station_id -> Text,
        record -> Jsonb,
        accepted_at -> Timestamptz,
    }
}

diesel::table! {
    applet_installations (applet_id, effective_scope_key) {
        applet_id -> Text,
        effective_scope_key -> Text,
        record -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    applet_transactions (applet_id, source_id, idempotency_key) {
        applet_id -> Text,
        source_id -> Text,
        idempotency_key -> Text,
        delivery_authentication_record -> Jsonb,
        delivery_authentication_record_digest -> Text,
        request_digest -> Text,
        outcome -> Nullable<Jsonb>,
        received_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    audit_logs (id) {
        id -> Uuid,
        actor_id -> Nullable<Text>,
        request_id -> Nullable<Uuid>,
        action -> Text,
        outcome -> Text,
        realm_id -> Nullable<Text>,
        operation_id -> Nullable<Uuid>,
        device_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    blobs (id) {
        id -> Text,
        sha256 -> Text,
        media_type -> Text,
        filename -> Nullable<Text>,
        uploaded_by -> Text,
        realm_id -> Nullable<Text>,
        size_bytes -> Int8,
        storage_backend -> Text,
        storage_key -> Text,
        payload -> Jsonb,
        legal_hold -> Bool,
        redacted -> Bool,
        visibility -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    publication_evidence (event_id) {
        event_id -> Text,
        committed_ref -> Jsonb,
        accepted_at -> Timestamptz,
    }
}

diesel::table! {
    signal_relay (id) {
        id -> Uuid,
        realm_id -> Text,
        position -> Int8,
        scope_ref -> Jsonb,
        sender_actor_id -> Text,
        sender_device_id -> Nullable<Text>,
        signal_class -> Text,
        envelope_digest -> Text,
        envelope -> Jsonb,
        sent_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    signal_relay_position (realm_id) {
        realm_id -> Text,
        next_position -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    signal_relay_watermark (actor_id, device_id, realm_id) {
        actor_id -> Text,
        device_id -> Text,
        realm_id -> Text,
        delivered_through -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    canonical_realms (pk) {
        pk -> Int8,
        id -> Bytea,
        digest_suite -> Int2,
        digest -> Bytea,
        wire_id -> Text,
    }
}

diesel::table! {
    canonical_events (pk) {
        pk -> Int8,
        id -> Bytea,
        digest_suite -> Int2,
        digest -> Bytea,
        actor_id -> Text,
        actor_seq -> Int8,
        realm_id -> Nullable<Text>,
        realm_pk -> Nullable<Int8>,
        scope_ref -> Jsonb,
        kind -> Text,
        schema_id -> Text,
        canonical_bytes -> Bytea,
        envelope -> Jsonb,
        state -> Text,
        received_at -> Timestamptz,
        committed_at -> Nullable<Timestamptz>,
        rejection_reason -> Nullable<Text>,
    }
}

diesel::table! {
    realm_authorities (realm_id) {
        realm_id -> Text,
        generation -> Int8,
        service_id -> Text,
        authority_ref -> Jsonb,
        last_handoff_ref -> Nullable<Text>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    realm_commits (commit_id) {
        commit_id -> Text,
        realm_id -> Text,
        stream_key -> Text,
        stream_ref -> Jsonb,
        stream_position -> Int8,
        previous_commit_ref -> Nullable<Text>,
        event_pk -> Nullable<Int8>,
        governance_generation -> Int8,
        commit_json -> Jsonb,
        committed_at -> Timestamptz,
    }
}

diesel::table! {
    realm_authority_handoffs (handoff_id) {
        handoff_id -> Text,
        realm_id -> Text,
        from_generation -> Int8,
        to_generation -> Int8,
        from_service_id -> Text,
        to_service_id -> Text,
        handoff_json -> Jsonb,
        installed_at -> Timestamptz,
    }
}

diesel::table! {
    account_device_signer_evidence (evidence_ref) {
        evidence_ref -> Text,
        principal_id -> Text,
        station_id -> Text,
        device_id -> Text,
        authorization_event_id -> Text,
        authorization_commit_id -> Text,
        attested_at -> Timestamptz,
        evidence_json -> Jsonb,
    }
}

diesel::table! {
    forwarded_producer_device_evidence (commit_id) {
        commit_id -> Text,
        evidence_ref -> Text,
        principal_id -> Text,
        station_id -> Text,
        device_id -> Text,
        attested_at -> Timestamptz,
        evidence_json -> Jsonb,
    }
}

diesel::table! {
    realm_state_snapshots (snapshot_id) {
        snapshot_id -> Text,
        realm_id -> Text,
        governance_generation -> Int8,
        snapshot_json -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    mls_welcome_deliveries (welcome_id) {
        welcome_id -> Text,
        realm_id -> Text,
        commit_event_pk -> Int8,
        recipient -> Text,
        recipient_endpoint_kind -> Text,
        recipient_device_id -> Nullable<Text>,
        recipient_verification_method -> Nullable<Text>,
        recipient_authorization_event_ref -> Text,
        recipient_device_authorization -> Nullable<Jsonb>,
        keypackage_claim_ref -> Text,
        position -> Int8,
        delivery_json -> Jsonb,
        state -> Text,
        queued_at -> Timestamptz,
        delivered_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    event_collision_variants (pk) {
        pk -> Int8,
        event_pk -> Int8,
        actor_id -> Text,
        actor_seq -> Int8,
        realm_id -> Nullable<Text>,
        kind -> Text,
        schema_id -> Text,
        canonical_bytes -> Bytea,
        envelope -> Jsonb,
        received_at -> Timestamptz,
    }
}

diesel::table! {
    mimi_consent_correlations (consent_id) {
        consent_id -> Text,
        purpose -> Text,
        strand_id -> Nullable<Text>,
        source_id -> Nullable<Text>,
        created_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    contacts (id) {
        id -> Uuid,
        requester_id -> Text,
        target_id -> Text,
        contact_round_id -> Nullable<Text>,
        granted_to_target_scopes -> Array<Text>,
        granted_to_requester_scopes -> Array<Text>,
        status -> Text,
        pending_incoming_admitted -> Bool,
        request_event_ref -> Nullable<Bytea>,
        request_slot_states -> Jsonb,
        request_receipts -> Jsonb,
        request_mirror_receipts -> Jsonb,
        contact_round_evidence -> Nullable<Jsonb>,
        contact_round_evidence_history -> Jsonb,
        control_outcomes -> Jsonb,
        response_event_ref -> Nullable<Bytea>,
        tombstone_event_ref -> Nullable<Bytea>,
        message -> Nullable<Text>,
        peer_id -> Nullable<Text>,
        peer_service_resolution -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    contact_verified_mirrors (target_holder_principal_id, request_event_id) {
        target_holder_principal_id -> Text,
        request_event_id -> Text,
        request_digest -> Text,
        canonical_event_bytes -> Bytea,
        source_receipt -> Jsonb,
        issuer_id -> Text,
        verified_at -> Timestamptz,
    }
}

diesel::table! {
    device_message_ack_tokens (ack_token) {
        ack_token -> Text,
        recipient -> Text,
        device_id -> Text,
        recipient_device_authorization -> Jsonb,
        queue_position -> Int8,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    agent_recipient_delivery_ack_tokens (ack_token) {
        ack_token -> Text,
        agent_id -> Text,
        verification_method -> Text,
        authorization_event_ref -> Text,
        queue_position -> Int8,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    device_message_idempotency (message_key) {
        message_key -> Text,
        intent_digest -> Text,
        delivered -> Bool,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    device_message_lost_watermarks (recipient, device_id) {
        recipient -> Text,
        device_id -> Text,
        lost_through -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_message_txns (key) {
        key -> Text,
        request_digest -> Text,
        outcome -> Jsonb,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    device_messages (id) {
        id -> Uuid,
        idempotency_key -> Text,
        sender -> Text,
        recipient -> Text,
        device_id -> Text,
        recipient_device_authorization -> Jsonb,
        position -> Int8,
        content -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    device_history_projections (principal_id, station_id) {
        principal_id -> Text,
        station_id -> Text,
        realm_id -> Text,
        confirmed_head -> Text,
    }
}

diesel::table! {
    devices (id) {
        station_id -> Text,
        id -> Uuid,
        actor_id -> Text,
        device_id -> Text,
        device_key -> Nullable<Text>,
        verification_state -> Text,
        payload -> Jsonb,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_keys (actor_id, device_id) {
        actor_id -> Text,
        device_id -> Text,
        device_authorization -> Jsonb,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_revocation_linearization_heads (principal_id, station_id, device_id) {
        principal_id -> Text,
        station_id -> Text,
        device_id -> Text,
        last_seq -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_revocation_targets (event_id) {
        event_id -> Text,
        selector -> Jsonb,
        committed_ref -> Jsonb,
        committed_at -> Timestamptz,
    }
}

diesel::table! {
    device_revocation_gate_receipts (principal_id, station_id, device_id, action_class, intent_digest) {
        principal_id -> Text,
        station_id -> Text,
        device_id -> Text,
        action_class -> Text,
        intent_digest -> Text,
        request_json -> Jsonb,
        status_json -> Jsonb,
        linearization_seq -> Int8,
        linearized_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    device_revocation_cleanup_intents (event_id) {
        event_id -> Text,
        committed_ref -> Jsonb,
        selector -> Jsonb,
        created_at -> Timestamptz,
        material_cleanup_completed_at -> Nullable<Timestamptz>,
        mls_obligation_completed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    federation_frontier_exchange (realm_id, peer_id) {
        realm_id -> Text,
        peer_id -> Text,
        status -> Text,
        consecutive_failures -> Int4,
        last_success_at -> Nullable<Int8>,
        last_failure_at -> Nullable<Int8>,
        last_frontier_root -> Nullable<Text>,
        last_error -> Nullable<Text>,
        updated_at -> Int8,
    }
}

diesel::table! {
    federation_frontier_confirmed_evidence (realm_id, peer_id, evidence_scope_key) {
        realm_id -> Text,
        peer_id -> Text,
        evidence_scope_key -> Text,
        reason -> Text,
        evidence_scope -> Jsonb,
        observed_at -> Int8,
        local_resolution_kind -> Nullable<Text>,
        local_resolution_digest -> Nullable<Text>,
        local_normalized_at -> Nullable<Int8>,
        peer_alignment_digest -> Nullable<Text>,
        peer_aligned_at -> Nullable<Int8>,
    }
}

diesel::table! {
    federation_frontier_resolution (realm_id, cell_subject_key) {
        realm_id -> Text,
        cell_subject_key -> Text,
        subject -> Jsonb,
        verdict -> Jsonb,
        conflict_evidence_digest -> Text,
        resolution_event_digest -> Text,
        normalized_at -> Int8,
    }
}

diesel::table! {
    federation_frontier_reduction_checkpoint (realm_id, peer_id) {
        realm_id -> Text,
        peer_id -> Text,
        remote_snapshot_digest -> Text,
        actor_set_digest -> Text,
        actor_id -> Text,
        cursor -> Nullable<Text>,
        updated_at -> Int8,
    }
}

diesel::table! {
    federation_operations (id) {
        id -> Uuid,
        realm_id -> Text,
        object_kind -> Text,
        object_id -> Nullable<Text>,
        operation_kind -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    federation_outbox (id) {
        id -> Text,
        peer_id -> Text,
        peer_url -> Nullable<Text>,
        endpoint -> Text,
        idempotency_key -> Text,
        payload_json -> Text,
        state -> Text,
        leased_from_state -> Nullable<Text>,
        realm_fanout -> Nullable<Jsonb>,
        attempts -> Int4,
        semantic_attempts -> Int4,
        next_attempt_at -> Int8,
        last_http_status -> Nullable<Int4>,
        last_error_code -> Nullable<Text>,
        last_response_excerpt -> Nullable<Text>,
        lease_owner -> Nullable<Text>,
        lease_token -> Nullable<Text>,
        lease_expires_at -> Nullable<Int8>,
        policy_version -> Nullable<Text>,
        supersedes_outbox_id -> Nullable<Text>,
        completed_at -> Nullable<Int8>,
        created_at -> Int8,
    }
}

diesel::table! {
    event_federation_outbox (event_pk, outbox_id) {
        event_pk -> Int8,
        outbox_id -> Text,
    }
}

diesel::table! {
    federation_outbox_dead_letter (id) {
        id -> Text,
        outbox_id -> Text,
        peer_id -> Text,
        endpoint -> Text,
        idempotency_key -> Text,
        last_http_status -> Nullable<Int4>,
        attempts -> Int4,
        response_excerpt -> Nullable<Text>,
        reason -> Text,
        failed_at -> Int8,
        requeued_outbox_id -> Nullable<Text>,
        requeued_by -> Nullable<Text>,
        requeue_reason -> Nullable<Text>,
        requeue_request_digest -> Nullable<Text>,
        requeued_at -> Nullable<Int8>,
    }
}

diesel::table! {
    handle_releases (localpart) {
        localpart -> Text,
        released_at -> Timestamptz,
    }
}

diesel::table! {
    websocket_auth_challenges (connection_id, nonce) {
        connection_id -> Text,
        nonce -> Text,
        canonical_origin -> Text,
        canonical_base_url -> Text,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed -> Bool,
        retain_until -> Timestamptz,
    }
}

diesel::table! {
    websocket_auth_replay_ledger (cnf_jkt, jti, proof_context) {
        cnf_jkt -> Text,
        jti -> Text,
        proof_context -> Text,
        consumed_at -> Timestamptz,
        retain_until -> Timestamptz,
    }
}

diesel::table! {
    idempotency_keys (actor_key, operation_id, idempotency_key) {
        actor_key -> Text,
        authenticated_actor -> Jsonb,
        operation_id -> Text,
        idempotency_key -> Text,
        request_hash -> Text,
        response_status -> Int4,
        response_body -> Jsonb,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    invite_locators (locator_id) {
        locator_id -> Text,
        token_digest -> Text,
        subject_id -> Text,
        recipient_id -> Text,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        one_time_use -> Bool,
        record_payload -> Jsonb,
        revoked_at -> Nullable<Timestamptz>,
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    invite_receive_policies (account_pk) {
        account_pk -> Int8,
        policy_payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    key_backups (id) {
        id -> Uuid,
        actor_id -> Nullable<Text>,
        device_id -> Nullable<Text>,
        backup_kind -> Nullable<Text>,
        backup_version -> Nullable<Text>,
        payload -> Jsonb,
        metadata -> Jsonb,
        last_accessed_at -> Nullable<Timestamptz>,
        scheme -> Nullable<Text>,
        version -> Int4,
        key_material_encrypted -> Nullable<Bytea>,
        series_actor_id -> Nullable<Text>,
        series_id -> Nullable<Text>,
        series_seq -> Nullable<Int8>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    member_identity_handle_claims (subject_id, digest) {
        digest -> Text,
        subject_id -> Text,
        issuer_id -> Text,
        audience -> Nullable<Text>,
        status -> Text,
        revocation_digest -> Nullable<Text>,
        fresh_until -> Timestamptz,
        visibility -> Nullable<Text>,
        expires_at -> Nullable<Timestamptz>,
        envelope -> Jsonb,
    }
}

diesel::table! {
    messages (pk) {
        pk -> Int8,
        event_id -> Text,
        message_id -> Text,
        realm_id -> Text,
        sender -> Text,
        thread_id -> Text,
        content -> Jsonb,
        encrypted -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    mls_key_packages (id) {
        id -> Text,
        keypackage_ref -> Text,
        keypackage_digest -> Text,
        owner_account_pk -> Int8,
        actor_id -> Text,
        device_id -> Nullable<Text>,
        endpoint_verification_method -> Nullable<Text>,
        key_package_bytes -> Bytea,
        capabilities -> Jsonb,
        capabilities_digest -> Text,
        last_resort -> Bool,
        last_resort_realm_id -> Nullable<Text>,
        lifetime_not_before -> Int8,
        lifetime_not_after -> Int8,
        claimed_by_mls_group_id -> Nullable<Text>,
        device_authorize_event_id -> Nullable<Bytea>,
        agent_key_authorize_event_id -> Nullable<Bytea>,
        claimed_at -> Nullable<Int8>,
        claim_expires_at_unix_ms -> Nullable<Int8>,
        consumed_at -> Nullable<Int8>,
        created_at -> Int8,
    }
}

diesel::table! {
    notifications (id) {
        id -> Uuid,
        recipient_actor_id -> Text,
        realm_id -> Nullable<Text>,
        source_event_id -> Nullable<Text>,
        controller_account_pk -> Nullable<Int8>,
        recipient_id -> Nullable<Text>,
        source_account_artifact_kind -> Nullable<Text>,
        source_account_artifact_id -> Nullable<Text>,
        source_ref -> Nullable<Text>,
        strand_id -> Nullable<Text>,
        track_name -> Nullable<Text>,
        notification_kind -> Nullable<Text>,
        event_kind -> Nullable<Text>,
        source_actor_id -> Nullable<Text>,
        priority -> Text,
        state -> Text,
        preview -> Nullable<Jsonb>,
        projection_action -> Nullable<Text>,
        projection_data -> Nullable<Jsonb>,
        projection_position -> Int8,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    one_time_keys (actor_id, device_id, position) {
        actor_id -> Text,
        device_id -> Text,
        device_authorization -> Jsonb,
        position -> Int4,
        key -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    organizations (organization_id) {
        organization_id -> Text,
        handle -> Nullable<Text>,
        display_name -> Text,
        source_refs -> Jsonb,
        policy_revision -> Text,
        verified -> Bool,
        members -> Jsonb,
        member_count -> Int8,
        created_by -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    peer_keypackage_claims (source_id, claim_request_id) {
        source_id -> Text,
        claim_request_id -> Text,
        request_digest -> Text,
        key_package_use -> Text,
        keypackage_id -> Nullable<Text>,
        outcome -> Nullable<Jsonb>,
        terminal_receipt -> Nullable<Jsonb>,
        consume_receipt -> Nullable<Jsonb>,
        claim_expires_at_unix_ms -> Nullable<Int8>,
        expires_at -> Int8,
        state -> Text,
        updated_at -> Int8,
    }
}

diesel::table! {
    policy_documents (id) {
        id -> Uuid,
        owner_id -> Text,
        scope -> Text,
        subject_ref -> Text,
        policy_kind -> Text,
        document -> Jsonb,
        version -> Int4,
        signed_by -> Nullable<Text>,
        active -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    projection_circle_members (pk) {
        pk -> Int8,
        circle_pk -> Int8,
        actor_id -> Text,
        state -> Text,
        invited_at -> Nullable<Timestamptz>,
        joined_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    projection_circles (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        profile_ref -> Nullable<Text>,
        title -> Text,
        summary -> Nullable<Text>,
        display -> Jsonb,
        directory_visibility -> Text,
        join_rule -> Text,
        history_access -> Text,
        encryption_profile -> Text,
        mls_group_ref -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by -> Jsonb,
        updated_by -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    projection_events (pk) {
        pk -> Int8,
        event_pk -> Int8,
        realm_pk -> Int8,
        realm_id -> Text,
        event_kind -> Text,
        operation_kind -> Text,
        operation_id -> Nullable<Uuid>,
        sender_id -> Nullable<Text>,
        payload -> Jsonb,
        received_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    projection_morphs (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        morph_kind -> Text,
        title -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        stage -> Nullable<Text>,
        stage_changed_at -> Nullable<Timestamptz>,
        created_by -> Jsonb,
        updated_by -> Nullable<Jsonb>,
        fields -> Jsonb,
        schema_refs -> Jsonb,
        facets -> Jsonb,
        versions -> Jsonb,
        content -> Nullable<Jsonb>,
        encrypted_content -> Nullable<Jsonb>,
        scope_circle_id -> Nullable<Bytea>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    projection_spaces (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        scope_circle_id -> Nullable<Bytea>,
        child_scope_policy -> Nullable<Text>,
        child_scope_policy_scope_circle_id -> Nullable<Bytea>,
        kind -> Text,
        title -> Text,
        fields -> Jsonb,
        parent_ref -> Nullable<Bytea>,
        rank -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by -> Jsonb,
        updated_by -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    projection_strands (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        scope_circle_id -> Nullable<Bytea>,
        tracks -> Jsonb,
        title -> Text,
        summary -> Nullable<Text>,
        content -> Nullable<Jsonb>,
        encrypted_content -> Nullable<Jsonb>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        stage -> Nullable<Text>,
        stage_changed_at -> Nullable<Timestamptz>,
        created_by -> Jsonb,
        updated_by -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    push_devices (id) {
        id -> Text,
        actor_id -> Nullable<Text>,
        device_id -> Text,
        device_authorization -> Jsonb,
        push_gateway -> Text,
        push_key -> Text,
        platform -> Nullable<Text>,
        app_id -> Nullable<Text>,
        public_handoff -> Bool,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    push_hard_logout_journal (grant_token_digest) {
        grant_token_digest -> Text,
        revocation_ref -> Text,
        account_id -> Jsonb,
        device_id -> Text,
        cnf_jkt -> Text,
        auth_side_confirmed -> Bool,
        completed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    push_registration_handoff_intents (source_station_id, registration_id) {
        source_station_id -> Text,
        local_account_id -> Jsonb,
        local_device_id -> Text,
        local_push_route_id -> Text,
        device_authorization -> Jsonb,
        registration_id -> Text,
        destination_gateway_id -> Text,
        desired_state -> Text,
        request_digest -> Text,
        client_input_digest -> Text,
        canonical_request -> Bytea,
        status -> Text,
        receipt -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    realm_meta (realm_id) {
        realm_id -> Text,
        owner -> Text,
        deleted -> Bool,
        discoverability -> Text,
        history_access -> Text,
        preview_policy -> Nullable<Jsonb>,
        preview_policy_digest -> Nullable<Text>,
        asset_privacy_policy -> Nullable<Jsonb>,
        asset_privacy_policy_digest -> Nullable<Text>,
        encryption_profile -> Nullable<Text>,
        plaintext_visible_services -> Jsonb,
        plaintext_visible_service_classes -> Jsonb,
        minimal_metadata_realm -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    realm_organizations (realm_id, organization_id, relationship) {
        realm_id -> Text,
        organization_id -> Text,
        relationship -> Text,
        statement_id -> Text,
        status -> Text,
        control_scopes -> Jsonb,
        issued_at -> Timestamptz,
        not_before -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
        supersedes_statement_id -> Nullable<Text>,
        revokes_statement_id -> Nullable<Text>,
        realm_commit_ref -> Nullable<Text>,
        proof_digest -> Nullable<Text>,
        delegation_ref -> Nullable<Text>,
        issuer_role -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    realm_owning_organizations (realm_id, organization_id) {
        realm_id -> Text,
        organization_id -> Text,
        linked_at -> Timestamptz,
    }
}

diesel::table! {
    recovery_policies (id) {
        id -> Uuid,
        principal_id -> Text,
        station_id -> Text,
        version -> Int4,
        acceptance_basis -> Jsonb,
        trust_domain -> Text,
        supersedes -> Nullable<Uuid>,
        expires_at -> Nullable<Timestamptz>,
        issued_at -> Timestamptz,
        verification_method -> Text,
        raw_payload -> Jsonb,
        accepted_at -> Timestamptz,
    }
}

diesel::table! {
    policy_current_results (policy_id) {
        realm_id -> Text,
        policy_id -> Text,
        current_commit_id -> Text,
        current_stream_position -> Int8,
        current_event_id -> Text,
        value -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    recovery_sessions (id) {
        id -> Uuid,
        request_id -> Text,
        create_intent_digest -> Text,
        session_grant_id -> Text,
        session_grant_cnf_jkt -> Text,
        principal_id -> Text,
        station_id -> Text,
        requesting_device_id -> Text,
        requesting_device_public_key_did -> Text,
        trust_domain -> Text,
        policy_id -> Uuid,
        policy_version -> Int4,
        identity_model -> Text,
        current_device_generation_ref -> Int8,
        accepted_stream_head -> Jsonb,
        policy_payload -> Jsonb,
        authority_context -> Jsonb,
        publication_authority_context -> Jsonb,
        publication_authority_context_digest -> Text,
        challenge -> Text,
        state -> Text,
        proof_payload -> Nullable<Jsonb>,
        transaction_id -> Nullable<Uuid>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    security_transaction_backup_erase_progress (transaction_id) {
        transaction_id -> Uuid,
        canonical_request -> Binary,
        outcome -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    security_transaction_step_attempts (transaction_id, step) {
        transaction_id -> Uuid,
        step -> Text,
        canonical_request -> Binary,
    }
}

diesel::table! {
    security_transaction_step_outcomes (transaction_id, step) {
        transaction_id -> Uuid,
        step -> Text,
        canonical_request -> Binary,
        response -> Jsonb,
        participant_outcome -> Nullable<Jsonb>,
    }
}

diesel::table! {
    security_transactions (id) {
        id -> Uuid,
        kind -> Text,
        principal_id -> Text,
        station_id -> Text,
        authorizing_device_id -> Nullable<Text>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        request_digest -> Text,
        prepared_plan -> Jsonb,
        prepared_plan_digest -> Text,
        accepted_steps -> Jsonb,
        revoke_proposal -> Nullable<Jsonb>,
        revoke_command_outcome -> Nullable<Jsonb>,
        terminal_outcome -> Nullable<Jsonb>,
        canonical_request -> Binary,
    }
}

diesel::table! {
    retention_policies (realm_id) {
        realm_id -> Text,
        ttl_seconds -> Int8,
        updated_by -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    retention_tombstones (event_id) {
        event_id -> Bytea,
        realm_id -> Text,
        reason -> Text,
        policy_ttl_seconds -> Int8,
        expired_at -> Timestamptz,
        tombstoned_at -> Timestamptz,
        sealed -> Bool,
    }
}

diesel::table! {
    server_settings (key) {
        key -> Text,
        value -> Jsonb,
        updated_by -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    service_identity (id) {
        id -> Text,
        identity -> Jsonb,
    }
}

diesel::table! {
    principal_resolutions (principal_id, station_id) {
        principal_id -> Text,
        station_id -> Text,
        pcr_realm_id -> Text,
        genesis_event_id -> Text,
        current_event_id -> Text,
        projection -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    principal_resolution_events (principal_id, station_id, event_id) {
        principal_id -> Text,
        station_id -> Text,
        event_id -> Text,
        previous_event_id -> Nullable<Text>,
        method_history_head -> Text,
        event_json -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    service_method_states (service_id, service_kind) {
        service_id -> Text,
        service_kind -> Text,
        method_state -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    service_resolution_fork_quarantine (service_id, service_kind, version_id, conflicting_digest) {
        service_id -> Text,
        service_kind -> Text,
        version_id -> Text,
        accepted_digest -> Text,
        conflicting_digest -> Text,
        evidence -> Jsonb,
        quarantined_at -> Timestamptz,
    }
}

diesel::table! {
    service_route_cache (service_id, service_kind) {
        service_id -> Text,
        service_kind -> Text,
        entry -> Jsonb,
        cache_expires_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    service_identity_registrations (service_kind, public_base_url) {
        service_kind -> Text,
        public_base_url -> Text,
        service_id -> Text,
        version_id -> Text,
        inception_digest -> Text,
        outcome -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    sessions (id) {
        id -> Text,
        account_pk -> Int8,
        actor_id -> Text,
        device_id -> Text,
        audience -> Text,
        session_public_key -> Nullable<Text>,
        payload -> Jsonb,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    state_cell_ops (seq) {
        seq -> Int8,
        realm_id -> Text,
        seal_id -> Text,
        op_index -> Int8,
        cell_id -> Text,
        event_id -> Text,
        op_json -> Jsonb,
        appended_at -> Timestamptz,
    }
}

diesel::table! {
    state_control_events (event_digest) {
        event_digest -> Text,
        digest_suite -> Text,
        realm_id -> Text,
        event_json -> Jsonb,
        control_proposal_ack -> Nullable<Jsonb>,
        ingress_class -> Jsonb,
        command_unit_event_digests -> Jsonb,
        proposal_decisions -> Jsonb,
        pending_domain_effects -> Nullable<Jsonb>,
        inserted_at -> Timestamptz,
        is_pending -> Bool,
    }
}

diesel::table! {
    state_control_seal_schedule (realm_id) {
        realm_id -> Text,
        generation -> Int8,
        first_pending_at_ms -> Int8,
        next_attempt_at_ms -> Int8,
        last_attempt_at_ms -> Nullable<Int8>,
        claim_holder -> Nullable<Text>,
        claim_fence -> Int8,
        claim_until_ms -> Nullable<Int8>,
        consecutive_failures -> Int4,
        last_outcome -> Nullable<Text>,
        scan_cursor -> Nullable<Text>,
    }
}

diesel::table! {
    state_control_seal_repair_cursor (singleton) {
        singleton -> Bool,
        after_realm_id -> Nullable<Text>,
        updated_at_ms -> Int8,
    }
}

diesel::table! {
    state_seals (id) {
        id -> Text,
        digest_suite -> Text,
        realm_id -> Text,
        seal_id_preimage_bytes -> Bytea,
        accepted_seal_bytes -> Bytea,
        seal_json -> Jsonb,
        predecessor_ref -> Nullable<Text>,
        is_genesis -> Bool,
        inserted_at -> Timestamptz,
    }
}

diesel::table! {
    state_seal_effective_checkpoints (seal_id) {
        seal_id -> Text,
        realm_id -> Text,
        covered_event_digests -> Array<Text>,
        covered_seal_ids -> Array<Text>,
        state_json -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    state_seal_collision_variants (variant_id) {
        variant_id -> Int8,
        seal_id -> Text,
        digest_suite -> Text,
        seal_id_preimage_bytes -> Bytea,
        accepted_seal_bytes -> Bytea,
        realm_id -> Text,
        seal_json -> Jsonb,
        observed_at -> Timestamptz,
    }
}

diesel::table! {
    state_seal_quarantine_realms (seal_id, realm_id) {
        seal_id -> Text,
        realm_id -> Text,
    }
}

diesel::table! {
    state_seal_quarantine (seal_id) {
        seal_id -> Text,
        reason_code -> Text,
        quarantined_at -> Timestamptz,
    }
}

diesel::table! {
    state_seal_control_events (seal_id, event_digest) {
        seal_id -> Text,
        realm_id -> Text,
        event_digest -> Text,
        command_index -> Int8,
        member_index -> Int8,
        outcome -> Text,
        reason_code -> Nullable<Text>,
        accepted_event_bytes_digest -> Text,
        accepted_event_bytes -> Bytea,
        sealed_at -> Timestamptz,
        decision_overdue -> Bool,
    }
}

diesel::table! {
    governance_dependency_objects (realm_id, dependency_kind, object_digest) {
        realm_id -> Text,
        dependency_kind -> Text,
        object_digest -> Text,
        canonical_bytes -> Bytea,
        object_json -> Jsonb,
        inserted_at -> Timestamptz,
    }
}

diesel::table! {
    governance_unscoped_signer_evidence (dependency_kind, object_digest) {
        dependency_kind -> Text,
        object_digest -> Text,
        canonical_bytes -> Bytea,
        object_json -> Jsonb,
        inserted_at -> Timestamptz,
    }
}

diesel::table! {
    governance_dependency_edges (edge_id) {
        edge_id -> Int8,
        realm_id -> Text,
        seal_id -> Nullable<Text>,
        event_digest -> Nullable<Text>,
        dependency_kind -> Text,
        object_digest -> Text,
        edge_index -> Int8,
        inserted_at -> Timestamptz,
    }
}

diesel::table! {
    history_traversal_retentions (retention_digest) {
        retention_digest -> Text,
        realm_id -> Text,
        access_kind -> Text,
        retention_kind -> Text,
        access_digest -> Text,
        traversal_intent -> Jsonb,
        trusted_history_base_basis -> Jsonb,
        trusted_current_basis -> Jsonb,
        target_basis -> Jsonb,
        expires_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    history_traversal_retained_objects (object_kind, object_digest) {
        object_kind -> Text,
        object_digest -> Text,
        object_ref -> Text,
        canonical_bytes -> Bytea,
        object_json -> Jsonb,
        reference_count -> Int8,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    history_traversal_pins (retention_digest, object_kind, object_ref, object_digest) {
        retention_digest -> Text,
        object_kind -> Text,
        object_ref -> Text,
        object_digest -> Text,
        pin_index -> Int8,
        pinned_at -> Timestamptz,
    }
}

diesel::table! {
    history_key_requests (request_sequence) {
        request_sequence -> Int8,
        request_id -> Text,
        request_digest -> Text,
        request_receipt_digest -> Text,
        effective_scope_kind -> Text,
        realm_id -> Text,
        circle_id -> Nullable<Text>,
        requester_actor_id -> Text,
        requester_sender_domain -> Text,
        release_id -> Text,
        traversal_retention_digest -> Nullable<Text>,
        request_json -> Jsonb,
        request_receipt_json -> Jsonb,
        sealed_history_response_capability_json -> Nullable<Jsonb>,
        request_replica_digest -> Nullable<Text>,
        request_replica_json -> Nullable<Jsonb>,
        stored_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    history_key_response_streams (request_id) {
        request_id -> Text,
        response_capability_commitment -> Text,
        next_sequence -> Int8,
        acked_sequence -> Nullable<Int8>,
        acked_cursor -> Nullable<Text>,
        active_bytes -> Int8,
        compact_receipt_bytes -> Int8,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    history_key_responses (response_id) {
        response_id -> Text,
        request_id -> Text,
        source_sender_domain -> Text,
        source_record_digest -> Text,
        source_record_json -> Jsonb,
        manifest_admission_json -> Nullable<Jsonb>,
        manifest_digest -> Nullable<Text>,
        manifest_admission_digest -> Nullable<Text>,
        release_attestation_json -> Nullable<Jsonb>,
        release_service_signer_evidence_json -> Jsonb,
        sequence -> Int8,
        cursor -> Nullable<Text>,
        sent_at -> Timestamptz,
        reserved_at -> Timestamptz,
        expires_at -> Timestamptz,
        state -> Text,
        record_digest -> Nullable<Text>,
        record_json -> Nullable<Jsonb>,
        lost_record_digest -> Nullable<Text>,
        lost_record_json -> Nullable<Jsonb>,
        send_receipt_json -> Nullable<Jsonb>,
        active_bytes -> Int8,
        compact_receipt_bytes -> Int8,
        accepted_at -> Nullable<Timestamptz>,
        acked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    history_key_response_ack_tokens (ack_token) {
        ack_token -> Text,
        request_id -> Text,
        claims_json -> Jsonb,
        consumed_request_json -> Nullable<Jsonb>,
        issued_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    history_key_response_dispositions (request_id, sequence) {
        request_id -> Text,
        sequence -> Int8,
        response_id -> Text,
        entry_kind -> Text,
        entry_digest -> Text,
        status -> Text,
        acked_at -> Timestamptz,
    }
}

diesel::table! {
    history_key_response_tombstones (response_id) {
        response_id -> Text,
        source_record_digest -> Text,
        terminal_status -> Text,
        expired_at -> Timestamptz,
        retain_until -> Timestamptz,
    }
}

diesel::table! {
    pending_rhrk_acquisitions (acquisition_digest) {
        acquisition_digest -> Text,
        realm_id -> Text,
        effective_scope -> Jsonb,
        mls_group_id -> Text,
        epoch -> Int8,
        recovery_key_id -> Text,
        method_controller_principal_id -> Text,
        holder_service_id -> Text,
        container_event_ref -> Text,
        archive_tuple_digest -> Text,
        archive_replica_digest -> Text,
        archive_replica_bytes -> Bytea,
        archive_replica_json -> Jsonb,
        retention_digest -> Text,
        state -> Text,
        attempt_count -> Int8,
        next_attempt_at -> Timestamptz,
        claim_token -> Nullable<Text>,
        claim_until -> Nullable<Timestamptz>,
        ready_at -> Nullable<Timestamptz>,
        accepted_at -> Nullable<Timestamptz>,
        archive_sequence -> Nullable<Int8>,
        accepted_outcome_bytes -> Nullable<Bytea>,
        accepted_outcome_json -> Nullable<Jsonb>,
        last_error_code -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    state_seal_signing_positions (realm_id, notary_seq) {
        realm_id -> Text,
        configuration_ref -> Text,
        notary_seq -> Int8,
        predecessor_ref -> Nullable<Text>,
        digest_suite -> Text,
        body_digest -> Text,
        exact_body -> Bytea,
    }
}

diesel::table! {
    state_seal_signing_leases (realm_id, signer_slot) {
        realm_id -> Text,
        signer_slot -> Text,
        holder -> Text,
        lease_until_ms -> Int8,
        fence -> Int8,
    }
}

diesel::table! {
    seal_prepare_signing_fences (realm_id, signer_slot, predecessor_basis) {
        realm_id -> Text,
        signer_slot -> Text,
        predecessor_basis -> Text,
        request_hash -> Text,
        response_body -> Jsonb,
        body_digest -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    sync_cursor_handles (id) {
        id -> Text,
        binding_subject -> Nullable<Text>,
        device_id -> Nullable<Text>,
        session_id -> Nullable<Text>,
        service_id -> Text,
        filter_digest -> Nullable<Text>,
        purpose -> Text,
        positions -> Nullable<Jsonb>,
        target -> Nullable<Jsonb>,
        issued_at_ms -> Int8,
        expires_at_ms -> Int8,
    }
}

diesel::table! {
    sync_cursor_revocations (id) {
        id -> Uuid,
        cursor_digest -> Text,
        account_id -> Jsonb,
        device_id -> Nullable<Text>,
        session_id -> Nullable<Text>,
        scope -> Text,
        reason_code -> Text,
        revoked_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    webvh_documents (id) {
        id -> Text,
        did_document -> Jsonb,
        key_log_head -> Nullable<Text>,
        seq -> Int8,
        method_evidence -> Jsonb,
        fetched_at -> Timestamptz,
        expires_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    webvh_log_events (id) {
        id -> Text,
        did -> Text,
        seq -> Int8,
        operation -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::joinable!(account_localparts -> accounts (account_pk));
diesel::joinable!(account_lifecycle -> accounts (account_pk));
diesel::joinable!(invite_receive_policies -> accounts (account_pk));
diesel::joinable!(agent_participation -> agent_principals (agent_id));
diesel::joinable!(agent_sidecar_contexts -> agent_sidecars (sidecar_pk));
diesel::joinable!(federation_outbox_dead_letter -> federation_outbox (outbox_id));
diesel::joinable!(event_collision_variants -> canonical_events (event_pk));
diesel::joinable!(event_federation_outbox -> canonical_events (event_pk));
diesel::joinable!(canonical_events -> canonical_realms (realm_pk));
diesel::joinable!(projection_events -> canonical_realms (realm_pk));
diesel::joinable!(event_federation_outbox -> federation_outbox (outbox_id));
diesel::joinable!(account_status_propagation_targets -> account_status_propagations (account_status_record_id));
diesel::joinable!(projection_circle_members -> projection_circles (circle_pk));
diesel::allow_tables_to_appear_in_same_query!(
    agent_recipient_delivery_ack_tokens,
    account_status_affected_services,
    account_status_propagations,
    account_status_propagation_targets,
    account_data_changes,
    account_data_change_retention,
    account_datas,
    account_lifecycle,
    account_localparts,
    accounts,
    agent_membership_cleanup_intents,
    agent_participation,
    agent_principals,
    agent_sidecar_contexts,
    agent_sidecars,
    applet_managed_identities,
    applet_installations,
    applet_transactions,
    audit_logs,
    blobs,
    canonical_events,
    account_device_signer_evidence,
    forwarded_producer_device_evidence,
    canonical_realms,
    realm_authorities,
    realm_commits,
    realm_authority_handoffs,
    realm_state_snapshots,
    mls_welcome_deliveries,
    mimi_consent_correlations,
    contacts,
    contact_verified_mirrors,
    device_message_ack_tokens,
    device_message_idempotency,
    device_message_lost_watermarks,
    device_message_txns,
    device_messages,
    device_revocation_cleanup_intents,
    device_revocation_gate_receipts,
    device_revocation_linearization_heads,
    device_revocation_targets,
    devices,
    device_keys,
    event_collision_variants,
    event_federation_outbox,
    federation_frontier_confirmed_evidence,
    federation_frontier_exchange,
    federation_frontier_reduction_checkpoint,
    federation_frontier_resolution,
    federation_operations,
    federation_outbox,
    federation_outbox_dead_letter,
    handle_releases,
    idempotency_keys,
    seal_prepare_signing_fences,
    invite_locators,
    invite_receive_policies,
    key_backups,
    member_identity_handle_claims,
    messages,
    mls_key_packages,
    notifications,
    one_time_keys,
    organizations,
    peer_keypackage_claims,
    policy_documents,
    principal_resolution_events,
    principal_resolutions,
    policy_current_results,
    projection_circle_members,
    projection_circles,
    projection_events,
    projection_morphs,
    projection_spaces,
    projection_strands,
    push_devices,
    push_hard_logout_journal,
    push_registration_handoff_intents,
    realm_meta,
    realm_organizations,
    realm_owning_organizations,
    recovery_policies,
    recovery_sessions,
    security_transaction_backup_erase_progress,
    security_transaction_step_attempts,
    security_transaction_step_outcomes,
    security_transactions,
    retention_policies,
    retention_tombstones,
    server_settings,
    service_identity,
    service_identity_registrations,
    service_resolution_fork_quarantine,
    service_method_states,
    service_route_cache,
    sessions,
    publication_evidence,
    signal_relay,
    signal_relay_position,
    signal_relay_watermark,
    governance_dependency_edges,
    governance_dependency_objects,
    governance_unscoped_signer_evidence,
    history_traversal_pins,
    history_traversal_retained_objects,
    history_traversal_retentions,
    history_key_response_ack_tokens,
    history_key_response_dispositions,
    history_key_response_streams,
    history_key_requests,
    history_key_response_tombstones,
    history_key_responses,
    pending_rhrk_acquisitions,
    state_cell_ops,
    state_control_events,
    state_control_seal_repair_cursor,
    state_control_seal_schedule,
    state_seal_effective_checkpoints,
    state_seal_collision_variants,
    state_seal_control_events,
    state_seal_quarantine,
    state_seal_quarantine_realms,
    state_seal_signing_leases,
    state_seal_signing_positions,
    state_seals,
    sync_cursor_handles,
    sync_cursor_revocations,
    websocket_auth_challenges,
    websocket_auth_replay_ledger,
    webvh_documents,
    webvh_log_events,
);

diesel::table! {
    agent_approval_publications (approval_event_pk) {
        approval_event_pk -> Int8,
        publication_event_id -> Bytea,
        canonical_bytes -> Bytea,
    }
}
