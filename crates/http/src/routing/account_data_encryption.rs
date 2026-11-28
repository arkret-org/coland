use arkret_crypto::account_data_crypto::AccountDataEncryptedValue;
use arkret_identifiers::{RealmId, StrandId};
use arkret_wire::AccountDataKey;
use serde_json::{Map, Value};

const EXACT_ENCRYPTED_ACCOUNT_DATA_KEYS: &[&str] = &[
    AccountDataKey::ACCOUNT_BLOCKLIST,
    AccountDataKey::CLIENT_UI_STATE,
    AccountDataKey::COLLECTIONS_STICKERS,
    AccountDataKey::DND_SCHEDULE,
    AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
    AccountDataKey::PRESENCE_PREFERENCE,
    AccountDataKey::PRESENCE_VISIBILITY,
    AccountDataKey::PUSH_RULES,
    AccountDataKey::READ_RECEIPT_PREFERENCES,
];

const SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES: &[&str] = &[
    AccountDataKey::CONTACTS_ACTOR,
    AccountDataKey::CONTACTS_REALM,
    AccountDataKey::REMINDERS_V1,
    AccountDataKey::SCHEDULED_SEND_V1,
    AccountDataKey::SNOOZE_V1,
    AccountDataKey::SAVED_V1,
    AccountDataKey::DRAFT_V1,
    AccountDataKey::FILE_TRANSFER_V1,
    AccountDataKey::SEARCH_INDEX_MANIFEST_V1,
    AccountDataKey::VIEWS_PRIVATE,
    AccountDataKey::NOTIFICATIONS_INBOX,
];

// `ak.agent.participation.v1` is intentionally absent: per-scope Agent
// participation selection is Account-Authority-owned storage addressed by
// `(agent_id, target_scope)` through `ak.self.agent.participation.resource.*`,
// not an account-data key (zh/models/private-objects.md §4.1).
const AGENT_ENCRYPTED_ACCOUNT_DATA_PREFIXES: &[&str] = &[
    AccountDataKey::AGENT_DRAFT_V1,
    AccountDataKey::AGENT_SIDECAR_VIEW_STATE_V1,
];

const FORBIDDEN_PLAINTEXT_FIELDS: &[&str] = &[
    "body",
    "target_ref",
    "collection_title",
    "note",
    "message_payload",
    "content",
    "blind_tokens",
    "shard_key",
    "transfer_id",
    "blob_ref",
    "filename",
    "media_type",
    "plaintext_size_bytes",
    "content_digest",
    "recipient_device_ids",
    "content_key",
    "local_path",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountDataEncryptionError {
    InvalidKeyPattern,
    ValueMustBeObject,
    PlaintextField,
    MissingEncryptedCarrier,
    InvalidEnvelopeMetadata,
}

impl AccountDataEncryptionError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::InvalidKeyPattern => {
                "account_data.set key must use registered private key pattern"
            }
            Self::ValueMustBeObject => {
                "private account_data content must be an encrypted envelope object"
            }
            Self::PlaintextField => "private account_data content must not expose plaintext fields",
            Self::MissingEncryptedCarrier => {
                "private account_data content requires encrypted envelope metadata"
            }
            Self::InvalidEnvelopeMetadata => {
                "private account_data encrypted envelope metadata is invalid"
            }
        }
    }
}

pub(crate) fn encrypted_account_data_prefix(account_data_key: &str) -> Option<&'static str> {
    if let Some(key) = EXACT_ENCRYPTED_ACCOUNT_DATA_KEYS
        .iter()
        .copied()
        .find(|key| account_data_key == *key)
    {
        return Some(key);
    }
    if account_data_key
        .strip_prefix(AccountDataKey::TAGS_REALM)
        .is_some_and(|rest| rest.starts_with('.'))
    {
        return Some(AccountDataKey::TAGS_REALM);
    }
    if let Some(prefix) = SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES
        .iter()
        .copied()
        .find(|prefix| {
            account_data_key
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with(':'))
        })
    {
        return Some(prefix);
    }
    AGENT_ENCRYPTED_ACCOUNT_DATA_PREFIXES
        .iter()
        .copied()
        .find(|prefix| {
            account_data_key
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        })
}

pub(crate) fn validate_encrypted_account_data_key(
    account_data_key: &str,
) -> Result<(), AccountDataEncryptionError> {
    if EXACT_ENCRYPTED_ACCOUNT_DATA_KEYS.contains(&account_data_key) {
        return Ok(());
    }
    if account_data_key
        .strip_prefix(AccountDataKey::ACCOUNT_BLOCKLIST)
        .is_some_and(|rest| rest.starts_with('.'))
    {
        return Err(AccountDataEncryptionError::InvalidKeyPattern);
    }
    // Every parameterized namespace below registers a key *pattern* with a
    // mandatory tail. The bare namespace is therefore not a writable key, and
    // must not reach the permissive unregistered-key fallback at the end of
    // this function — that is the same fail-open shape
    // `RETIRED_ENCRYPTED_ACCOUNT_DATA_PREFIXES` guards against.
    if account_data_key == AccountDataKey::TAGS_REALM
        || SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES.contains(&account_data_key)
    {
        return Err(AccountDataEncryptionError::InvalidKeyPattern);
    }
    if let Some(realm_id) = account_data_key.strip_prefix("ak.tags.realm.") {
        return RealmId::new(realm_id.to_owned())
            .map(|_| ())
            .map_err(|_| AccountDataEncryptionError::InvalidKeyPattern);
    }
    if SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES
        .iter()
        .any(|prefix| {
            account_data_key
                .strip_prefix(*prefix)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with(':'))
        })
    {
        return arkret_models_collaboration::objects::productivity::validate_private_account_data_key(account_data_key)
            .map_err(|_| AccountDataEncryptionError::InvalidKeyPattern);
    }
    if let Some(rest) = account_data_key.strip_prefix(AccountDataKey::AGENT_DRAFT_V1) {
        return validate_agent_private_key_tail(rest);
    }
    if let Some(rest) = account_data_key.strip_prefix(AccountDataKey::AGENT_SIDECAR_VIEW_STATE_V1) {
        return validate_sidecar_view_state_key_tail(rest);
    }
    Err(AccountDataEncryptionError::InvalidKeyPattern)
}

#[cfg(test)]
pub(crate) fn validate_encrypted_account_data_value(
    account_data_key: &str,
    value: &Value,
) -> Result<(), AccountDataEncryptionError> {
    validate_encrypted_account_data_value_for_actor(account_data_key, value, None)
}

pub(crate) fn validate_encrypted_account_data_value_for_actor(
    account_data_key: &str,
    value: &Value,
    expected_actor_id: Option<&arkret_wire::ActorId>,
) -> Result<(), AccountDataEncryptionError> {
    if encrypted_account_data_prefix(account_data_key).is_none() {
        return Ok(());
    }
    let object = value
        .as_object()
        .ok_or(AccountDataEncryptionError::ValueMustBeObject)?;
    if object
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    if is_account_data_set_operation_payload(object) {
        reject_operation_plaintext_fields(object)?;
        for field in ["body", "encrypted_payload", "encrypted_content"] {
            if let Some(carrier) = object.get(field) {
                return validate_encrypted_carrier(account_data_key, carrier, expected_actor_id);
            }
        }
        return Err(AccountDataEncryptionError::MissingEncryptedCarrier);
    }
    reject_content_plaintext_fields(object)?;
    if validate_encrypted_carrier(account_data_key, value, expected_actor_id).is_ok() {
        return Ok(());
    }
    for field in ["encrypted_payload", "encrypted_content"] {
        if let Some(carrier) = object.get(field) {
            return validate_encrypted_carrier(account_data_key, carrier, expected_actor_id);
        }
    }
    if object.contains_key("ciphertext") {
        return Err(AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }
    Err(AccountDataEncryptionError::MissingEncryptedCarrier)
}

fn validate_agent_private_key_tail(rest: &str) -> Result<(), AccountDataEncryptionError> {
    let tail = rest
        .strip_prefix(':')
        .filter(|tail| !tail.is_empty())
        .ok_or(AccountDataEncryptionError::InvalidKeyPattern)?;
    if tail
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#'))
    {
        return Err(AccountDataEncryptionError::InvalidKeyPattern);
    }
    if let Some(actor_id) = tail.split(':').next()
        && actor_id.starts_with("ak:did_core:")
    {
        arkret_identifiers::DidCoreId::new(actor_id.to_owned())
            .map_err(|_| AccountDataEncryptionError::InvalidKeyPattern)?;
    }
    Ok(())
}

fn validate_sidecar_view_state_key_tail(rest: &str) -> Result<(), AccountDataEncryptionError> {
    let tail = rest
        .strip_prefix(':')
        .filter(|tail| !tail.is_empty())
        .ok_or(AccountDataEncryptionError::InvalidKeyPattern)?;
    let (controller_account_key, coordinates) = tail
        .split_once(':')
        .ok_or(AccountDataEncryptionError::InvalidKeyPattern)?;
    if controller_account_key.len() != 43
        || !controller_account_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AccountDataEncryptionError::InvalidKeyPattern);
    }
    let (realm_id, strand_suffix) = coordinates
        .rsplit_once(":ak:strand:")
        .ok_or(AccountDataEncryptionError::InvalidKeyPattern)?;
    RealmId::new(realm_id.to_owned()).map_err(|_| AccountDataEncryptionError::InvalidKeyPattern)?;
    StrandId::new(format!("ak:strand:{strand_suffix}"))
        .map_err(|_| AccountDataEncryptionError::InvalidKeyPattern)?;
    Ok(())
}

fn is_account_data_set_operation_payload(object: &Map<String, Value>) -> bool {
    object.get("key").and_then(Value::as_str).is_some()
}

fn reject_operation_plaintext_fields(
    object: &Map<String, Value>,
) -> Result<(), AccountDataEncryptionError> {
    if FORBIDDEN_PLAINTEXT_FIELDS
        .iter()
        .filter(|field| **field != "body")
        .any(|field| object.contains_key(*field))
    {
        Err(AccountDataEncryptionError::PlaintextField)
    } else {
        Ok(())
    }
}

fn reject_content_plaintext_fields(
    object: &Map<String, Value>,
) -> Result<(), AccountDataEncryptionError> {
    if object.iter().any(|(field, value)| {
        field_is_forbidden_plaintext(field) || contains_forbidden_field(value)
    }) {
        Err(AccountDataEncryptionError::PlaintextField)
    } else {
        Ok(())
    }
}

fn contains_forbidden_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(field, value)| {
            field_is_forbidden_plaintext(field) || contains_forbidden_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_field),
        _ => false,
    }
}

fn field_is_forbidden_plaintext(field: &str) -> bool {
    FORBIDDEN_PLAINTEXT_FIELDS.contains(&field)
}

fn validate_encrypted_carrier(
    account_data_key: &str,
    value: &Value,
    expected_actor_id: Option<&arkret_wire::ActorId>,
) -> Result<(), AccountDataEncryptionError> {
    validate_encrypted_envelope_metadata(account_data_key, value, expected_actor_id)
}

fn validate_encrypted_envelope_metadata(
    account_data_key: &str,
    value: &Value,
    expected_actor_id: Option<&arkret_wire::ActorId>,
) -> Result<(), AccountDataEncryptionError> {
    let envelope: AccountDataEncryptedValue = serde_json::from_value(value.clone())
        .map_err(|_| AccountDataEncryptionError::InvalidEnvelopeMetadata)?;
    let expected_actor_id = expected_actor_id.unwrap_or(&envelope.aad.actor_id);
    arkret_crypto::account_data_crypto::validate_account_data_encrypted_value(
        &envelope,
        expected_actor_id,
        account_data_key,
    )
    .map_err(|_| AccountDataEncryptionError::InvalidEnvelopeMetadata)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn private_key() -> &'static str {
        "ak.saved.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    }

    fn encrypted_envelope(account_data_key: &str) -> Value {
        let actor_id =
            crate::test_account_actor(&arkret_wire::Did::new("did:web:alice.example").unwrap());
        serde_json::to_value(
            arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
                &[7u8; 32],
                &actor_id,
                account_data_key,
                &json!({"private": true}),
                [9u8; 24],
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn conformance_marker() -> Value {
        json!({
            "client_side_conformance": {
                "encrypted_account_data": true,
                "profile_id": "ak.profile.e2ee_client.v1",
                "plaintext_schema_id": "ak.schema.personal_productivity.v1",
                "payload_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            },
            "content_type": "application/vnd.arkret.account-data+json",
            "ciphertext": "opaque-client-envelope"
        })
    }

    #[test]
    fn encrypted_account_data_accepts_spec_envelope_metadata() {
        validate_encrypted_account_data_value(private_key(), &encrypted_envelope(private_key()))
            .unwrap();
    }

    #[test]
    fn encrypted_account_data_rejects_cross_actor_aad() {
        let error = validate_encrypted_account_data_value_for_actor(
            private_key(),
            &encrypted_envelope(private_key()),
            Some(&crate::test_account_actor(
                &arkret_wire::Did::new("did:web:bob.example").unwrap(),
            )),
        )
        .unwrap_err();
        assert_eq!(error, AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }

    #[test]
    fn encrypted_account_data_rejects_client_side_marker() {
        let error = validate_encrypted_account_data_value(private_key(), &conformance_marker())
            .unwrap_err();
        assert_eq!(error, AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }

    #[test]
    fn encrypted_account_data_rejects_plaintext_fields() {
        let err = validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "filename": "private.pdf",
                "encrypted_payload": encrypted_envelope(private_key())
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn encrypted_account_data_rejects_incomplete_envelope_metadata() {
        let err =
            validate_encrypted_account_data_value(private_key(), &json!({"ciphertext": "opaque"}))
                .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }

    #[test]
    fn unregistered_account_data_is_not_reinterpreted() {
        validate_encrypted_account_data_value(
            "com.example.client.ui_state",
            &json!({"local_name": "Acme"}),
        )
        .unwrap();
    }

    #[test]
    fn standard_encrypted_account_data_requires_encrypted_carrier() {
        for key in [
            AccountDataKey::ACCOUNT_BLOCKLIST,
            AccountDataKey::CLIENT_UI_STATE,
            AccountDataKey::COLLECTIONS_STICKERS,
            AccountDataKey::DND_SCHEDULE,
            AccountDataKey::PRESENCE_VISIBILITY,
            AccountDataKey::PRESENCE_PREFERENCE,
            AccountDataKey::PUSH_RULES,
            AccountDataKey::READ_RECEIPT_PREFERENCES,
        ] {
            let err =
                validate_encrypted_account_data_value(key, &json!({"enabled": true})).unwrap_err();
            assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);
        }

        let err = validate_encrypted_account_data_value(
            "ak.contacts.realm.ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
            &json!({"local_name": "Acme"}),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);

        let err = validate_encrypted_account_data_value(
            AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
            &json!({"invite_event_id": "ak:event:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j"}),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);
    }

    const PRIVATE_VIEW_KEY: &str =
        "ak.views.private.ak:view:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    const NOTIFICATION_INBOX_KEY: &str =
        "ak.notifications.inbox.ak:notification:0196419b-0000-7000-8000-000000000002";

    #[test]
    fn private_view_and_notification_inbox_require_encrypted_envelope() {
        for key in [PRIVATE_VIEW_KEY, NOTIFICATION_INBOX_KEY] {
            validate_encrypted_account_data_key(key).unwrap();
            assert!(encrypted_account_data_prefix(key).is_some());
            validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();
        }

        // The whole point of `storage: encrypted_account_data` for
        // `ak.views.private.<view_id>`: title / query / layout are plaintext
        // the server must never accept.
        let err = validate_encrypted_account_data_value(
            PRIVATE_VIEW_KEY,
            &json!({
                "schema": "ak.schema.view.v1",
                "id": "ak:view:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "visibility": "private",
                "title": "Quarterly plan",
                "layout": {"columns": 3}
            }),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);

        let err = validate_encrypted_account_data_value(
            NOTIFICATION_INBOX_KEY,
            &json!({
                "notification_id": "ak:notification:0196419b-0000-7000-8000-000000000002",
                "state": "dismissed",
                "updated_hlc": "01904100-0000-7000-8000-000000000001"
            }),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::MissingEncryptedCarrier);
    }

    #[test]
    fn private_view_and_notification_inbox_reject_malformed_typed_id_tails() {
        for key in [
            "ak.views.private",
            "ak.views.private.",
            "ak.views.private.ak:realm:Af9DRPZ6jo28Ku6bsJX3iOs5fu2GLdPa5mI-lkvcujvM",
            "ak.views.private.quarterly-plan",
            "ak.notifications.inbox",
            "ak.notifications.inbox.",
            "ak.notifications.inbox.ak:view:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        ] {
            assert_eq!(
                validate_encrypted_account_data_key(key).unwrap_err(),
                AccountDataEncryptionError::InvalidKeyPattern,
                "{key}"
            );
        }
    }

    #[test]
    fn bare_parameterized_namespaces_are_not_writable_keys() {
        for key in SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES
            .iter()
            .copied()
            .chain([AccountDataKey::TAGS_REALM])
        {
            assert_eq!(
                validate_encrypted_account_data_key(key).unwrap_err(),
                AccountDataEncryptionError::InvalidKeyPattern,
                "{key}"
            );
        }
    }

    #[test]
    fn encrypted_sidecar_view_state_requires_the_full_key() {
        let active = "ak.agent.sidecar_view_state.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1:ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
        validate_encrypted_account_data_key(active).unwrap();
        assert_eq!(
            validate_encrypted_account_data_key(
                "ak.agent.sidecar_view_state.v1:did:web:alice.example"
            )
            .unwrap_err(),
            AccountDataEncryptionError::InvalidKeyPattern
        );
    }

    #[test]
    fn account_data_set_body_may_carry_encrypted_envelope() {
        validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "key": private_key(),
                "body": encrypted_envelope(private_key()),
                "updated_at": "2026-06-18T00:00:00.000Z"
            }),
        )
        .unwrap();

        let err = validate_encrypted_account_data_value(
            private_key(),
            &json!({
                "key": private_key(),
                "body": {"collection_title": "Leaks"},
                "updated_at": "2026-06-18T00:00:00.000Z"
            }),
        )
        .unwrap_err();
        assert_eq!(err, AccountDataEncryptionError::InvalidEnvelopeMetadata);
    }

    #[test]
    fn reminder_rejects_plaintext_note_and_target_ref() {
        let key = "ak.reminders.v1:local-reminder-1";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "reminder",
                "target_ref": "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "remind_at": "2026-06-19T08:00:00.000Z",
                "note": "private reminder note",
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": encrypted_envelope(key)
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn snooze_rejects_plaintext_target_ref() {
        let key = "ak.snooze.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "snooze",
                "target_ref": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "snooze_expires_at": "2026-06-19T09:00:00.000Z",
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": encrypted_envelope(key)
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn scheduled_send_rejects_plaintext_message_payload() {
        let key = "ak.scheduled_send.v1:ak:scheduled_send:01904100-0000-7000-8000-000000000001";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "kind": "scheduled_send",
                "planned_message_id": "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "send_at": "2026-06-19T08:00:00.000Z",
                "message_payload": {
                    "message_id": "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "content": {"kind": "ak.content.text", "body": "secret"}
                },
                "updated_hlc": "01904100-0000-7000-8000-000000000001",
                "encrypted_payload": encrypted_envelope(key)
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }

    #[test]
    fn search_index_manifest_rejects_plaintext_manifest_fields() {
        let key = "ak.search.index_manifest.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        validate_encrypted_account_data_key(key).unwrap();
        validate_encrypted_account_data_value(key, &encrypted_envelope(key)).unwrap();

        let err = validate_encrypted_account_data_value(
            key,
            &json!({
                "realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
                "shards": [{
                    "shard_key": "term-derived-key",
                    "blob_ref": "ak:blob:sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "ciphertext_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                }],
                "encrypted_payload": encrypted_envelope(key)
            }),
        )
        .unwrap_err();

        assert_eq!(err, AccountDataEncryptionError::PlaintextField);
    }
}
