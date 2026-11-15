use uuid::Uuid;

pub const EVENT_ID_BYTES: usize = 33;
pub const EVENT_DIGEST_BYTES: usize = 32;
pub const REALM_ID_BYTES: usize = 33;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EventIdentityParts {
    pub id: [u8; EVENT_ID_BYTES],
    pub digest_suite: u8,
    pub digest: [u8; EVENT_DIGEST_BYTES],
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RealmIdentityParts {
    pub id: [u8; REALM_ID_BYTES],
    pub digest_suite: u8,
    pub digest: [u8; EVENT_DIGEST_BYTES],
}

pub fn realm_identity_parts(realm_id: &str) -> Result<RealmIdentityParts, crate::PersistenceError> {
    let realm_id = arkret_identifiers::RealmId::new(realm_id.to_owned()).map_err(|error| {
        crate::PersistenceError::SchemaViolation(format!("malformed canonical Realm id: {error}"))
    })?;
    let id = realm_id.token_bytes();
    let header = id[0];
    let mut digest = [0_u8; EVENT_DIGEST_BYTES];
    digest.copy_from_slice(&id[1..]);
    Ok(RealmIdentityParts {
        id,
        digest_suite: header,
        digest,
    })
}

fn digest_suite_code(suite: &str) -> Option<u8> {
    match suite {
        "sha256" => Some(0x01),
        "blake3" => Some(0x02),
        _ => None,
    }
}

fn decode_lower_hex_32(value: &str) -> Option<[u8; EVENT_DIGEST_BYTES]> {
    if value.len() != EVENT_DIGEST_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0_u8; EVENT_DIGEST_BYTES];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => unreachable!("validated lowercase hex"),
        };
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Some(output)
}

/// Recover the 33-byte token behind any Event-derived typed id.
///
/// `kind` is the registry kind, not the prefix: `"circle"`, not `"ak:circle:"`.
/// Every Event-derived kind retypes the creating Event's token unchanged, so
/// one decoder serves all of them and the suite code plus canonical Base64URL
/// spelling are enforced in a single place.
pub fn parse_event_token(typed: &str, kind: &str) -> Option<[u8; EVENT_ID_BYTES]> {
    arkret_identifiers::decode_event_token(typed, &format!("ak:{kind}:"))
}

pub fn format_event_token(kind: &str, token: &[u8; EVENT_ID_BYTES]) -> String {
    arkret_identifiers::encode_event_token(&format!("ak:{kind}:"), *token)
}

pub fn event_token_part_expect_internal(typed: &str, kind: &str) -> [u8; EVENT_ID_BYTES] {
    parse_event_token(typed, kind).unwrap_or_else(|| {
        panic!("malformed typed {kind} wire ID at internal persistence boundary: {typed:?}")
    })
}

pub fn event_token_part_or_schema_violation(
    typed: &str,
    kind: &str,
) -> Result<[u8; EVENT_ID_BYTES], crate::PersistenceError> {
    parse_event_token(typed, kind).ok_or_else(|| {
        crate::PersistenceError::SchemaViolation(format!(
            "malformed typed {kind} wire ID: {typed:?}"
        ))
    })
}

pub fn parse_event_id(typed: &str) -> Option<[u8; EVENT_ID_BYTES]> {
    parse_event_token(typed, "event")
}

pub fn format_event_id(id: &[u8; EVENT_ID_BYTES]) -> String {
    format_event_token("event", id)
}

pub fn parse_event_digest(typed: &str) -> Option<(u8, [u8; EVENT_DIGEST_BYTES])> {
    let (suite, value) = typed.split_once(':')?;
    Some((digest_suite_code(suite)?, decode_lower_hex_32(value)?))
}

pub fn format_event_digest(suite_code: u8, digest: &[u8; EVENT_DIGEST_BYTES]) -> Option<String> {
    let suite = match suite_code {
        0x01 => "sha256",
        0x02 => "blake3",
        _ => return None,
    };
    let mut encoded = String::with_capacity(EVENT_DIGEST_BYTES * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Some(format!("{suite}:{encoded}"))
}

pub fn event_identity_parts(
    event_id: &str,
    event_digest: &str,
) -> Result<EventIdentityParts, crate::PersistenceError> {
    let id = parse_event_id(event_id).ok_or_else(|| {
        crate::PersistenceError::SchemaViolation(format!(
            "malformed canonical Event id: {event_id:?}"
        ))
    })?;
    let (digest_suite, digest) = parse_event_digest(event_digest).ok_or_else(|| {
        crate::PersistenceError::SchemaViolation(format!(
            "malformed canonical Event digest: {event_digest:?}"
        ))
    })?;
    let reserved_nibble = id[0] >> 4;
    if reserved_nibble != arkret_identifiers::EVENT_RESERVED_HIGH_NIBBLE {
        return Err(crate::PersistenceError::SchemaViolation(format!(
            "Event reserved header nibble must be zero, got 0x{reserved_nibble:x}"
        )));
    }
    let id_digest_suite = id[0] & 0x0f;
    if id_digest_suite != digest_suite || id[1..] != digest {
        return Err(crate::PersistenceError::Conflict(
            "event_id_digest_mismatch".to_owned(),
        ));
    }
    Ok(EventIdentityParts {
        id,
        digest_suite: id_digest_suite,
        digest,
    })
}

/// Validate the complete storage identity before any bucket lookup. The
/// canonical bytes are the digest-payload preimage, so a caller cannot force a
/// quarantine by pairing an existing id/digest string with unrelated bytes.
pub fn validated_event_identity_parts(
    event_id: &str,
    event_digest: &str,
    canonical_bytes: &[u8],
) -> Result<EventIdentityParts, crate::PersistenceError> {
    let parts = event_identity_parts(event_id, event_digest)?;
    let suite = match parts.digest_suite {
        0x01 => arkret_canonical::DigestSuite::Sha256,
        0x02 => arkret_canonical::DigestSuite::Blake3,
        _ => unreachable!("event_identity_parts rejects inactive suites"),
    };
    if arkret_canonical::digest(suite, canonical_bytes) != event_digest {
        return Err(crate::PersistenceError::Conflict(
            "event_id_digest_mismatch".to_owned(),
        ));
    }
    Ok(parts)
}

/// Validate a canonical Event identity together with the digest suite frozen
/// by its admission record. Durable callers must not recover this value from
/// the Event id after admission.
pub fn validated_event_identity_parts_for_suite(
    event_id: &str,
    event_digest: &str,
    canonical_bytes: &[u8],
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<EventIdentityParts, crate::PersistenceError> {
    let parts = validated_event_identity_parts(event_id, event_digest, canonical_bytes)?;
    let expected_code = match digest_suite {
        arkret_canonical::DigestSuite::Sha256 => 0x01,
        arkret_canonical::DigestSuite::Blake3 => 0x02,
    };
    if parts.digest_suite != expected_code {
        return Err(crate::PersistenceError::Conflict(
            "event_id_digest_suite_mismatch".to_owned(),
        ));
    }
    Ok(parts)
}

pub fn generate(kind: &str) -> String {
    arkret_identifiers::new_prefixed_uuid7(&format!("ak:{kind}:"))
}

pub fn parse_typed_uuid(typed: &str, expected_kind: &str) -> Option<Uuid> {
    let prefix = format!("ak:{expected_kind}:");
    Uuid::parse_str(typed.strip_prefix(&prefix)?).ok()
}

pub fn typed_uuid_part(typed: &str) -> Option<Uuid> {
    let mut parts = typed.splitn(3, ':');
    (parts.next()? == "ak").then_some(())?;
    parts.next()?;
    Uuid::parse_str(parts.next()?).ok()
}

pub fn typed_uuid_part_expect_internal(typed: &str) -> Uuid {
    typed_uuid_part(typed).unwrap_or_else(|| {
        panic!("malformed typed wire ID at internal persistence boundary: {typed:?}")
    })
}

pub fn format_typed_uuid(kind: &str, uuid: &Uuid) -> String {
    format!("ak:{kind}:{uuid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> String {
        format!("sha256:{}", format!("{byte:02x}").repeat(32))
    }

    #[test]
    fn event_identity_requires_suite_and_full_digest_binding() {
        let mut id = [0x11; EVENT_ID_BYTES];
        id[0] = 0x01;
        let event_id = format_event_id(&id);
        let parts = event_identity_parts(&event_id, &digest(0x11)).unwrap();
        assert_eq!(parts.id, id);
        assert_eq!(parts.digest_suite, 0x01);
        assert_eq!(parts.digest, [0x11; EVENT_DIGEST_BYTES]);

        let mismatch = event_identity_parts(&event_id, &digest(0x22)).unwrap_err();
        assert!(matches!(
            mismatch,
            crate::PersistenceError::Conflict(reason) if reason == "event_id_digest_mismatch"
        ));
    }

    #[test]
    fn event_id_parser_rejects_padding_malformed_alphabet_and_inactive_suite() {
        let mut id = [0x33; EVENT_ID_BYTES];
        id[0] = 0x01;
        let canonical = format_event_id(&id);
        assert_eq!(parse_event_id(&canonical), Some(id));
        assert!(parse_event_id(&format!("{canonical}=")).is_none());

        let mut malformed = canonical;
        malformed.pop();
        malformed.push('!');
        assert!(parse_event_id(&malformed).is_none());

        id[0] = 0x03;
        assert!(parse_event_id(&format_event_id(&id)).is_none());

        id[0] = 0x11;
        assert!(
            parse_event_id(&format_event_id(&id)).is_none(),
            "an active low-nibble suite must not make a non-zero Event reserved nibble valid"
        );
    }

    #[test]
    fn event_digest_rejects_unknown_suite_and_noncanonical_hex() {
        assert!(parse_event_digest(&digest(0xaa)).is_some());
        assert!(parse_event_digest(&digest(0xaa).to_uppercase()).is_none());
        assert!(parse_event_digest(&format!("sha512:{}", "00".repeat(32))).is_none());
    }

    #[test]
    fn realm_identity_preserves_reserved_header_suite_and_full_digest() {
        let event_id = arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x44; EVENT_DIGEST_BYTES],
        );
        let event_realm = arkret_identifiers::RealmId::from_event_id(&event_id);
        let event_parts = realm_identity_parts(event_realm.as_str()).unwrap();
        assert_eq!(event_parts.digest_suite, 1);
        assert_eq!(event_parts.digest, [0x44; EVENT_DIGEST_BYTES]);

        let mut unknown_class = event_parts.id;
        unknown_class[0] = 0x11;
        assert!(realm_identity_parts(&format_event_token("realm", &unknown_class)).is_err());
    }

    #[test]
    fn storage_identity_recomputes_the_digest_preimage_before_lookup() {
        let bytes = br#"{"covered":true}"#;
        let digest = arkret_canonical::sha256_bytes(bytes);
        let mut id = [0_u8; EVENT_ID_BYTES];
        id[0] = 0x01;
        id[1..].copy_from_slice(&digest);
        let event_id = format_event_id(&id);
        let event_digest = format_event_digest(0x01, &digest).unwrap();
        validated_event_identity_parts(&event_id, &event_digest, bytes).unwrap();
        let suite_error = validated_event_identity_parts_for_suite(
            &event_id,
            &event_digest,
            bytes,
            arkret_canonical::DigestSuite::Blake3,
        )
        .unwrap_err();
        assert!(matches!(
            suite_error,
            crate::PersistenceError::Conflict(reason) if reason == "event_id_digest_suite_mismatch"
        ));

        let error =
            validated_event_identity_parts(&event_id, &event_digest, br#"{"covered":false}"#)
                .unwrap_err();
        assert!(matches!(
            error,
            crate::PersistenceError::Conflict(reason) if reason == "event_id_digest_mismatch"
        ));
    }
}
