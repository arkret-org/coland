use super::super::*;
#[cfg(test)]
use super::payload_shape::validate_event_audience_fields;
#[cfg(test)]
use super::payload_shape::validate_pre_schema_wire_shape;
#[cfg(test)]
use super::payload_shape::validate_space_container_lifecycle_payload;

#[cfg(test)]
fn event_realm_id(object: &serde_json::Map<String, Value>) -> Result<String, EventValidationError> {
    // Spec zh/models/realm-and-space.md section 2.5.0: `ak.realm.create` is the
    // one kind that MUST NOT carry `realm_id`. The Realm's id is derived from
    // the genesis Event's own `event_id`, so carrying it would put a function
    // of the digest inside the digest preimage — there is no fixed point to
    // solve. Receivers derive it instead, which is also what makes `realm_id`
    // self-certifying against the genesis they were served.
    let is_realm_genesis = event_string_field(object, &["kind"])
        .is_some_and(|kind| kind == arkret_wire::EventKind::RealmCreate.as_str());

    if is_realm_genesis {
        if object.contains_key("realm_id") {
            let mut error = event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                arkret_wire::ErrorCode::SchemaViolation.as_str(),
                "ak.realm.create MUST omit realm_id; \
                 it is derived from the genesis event_id",
            );
            error.reason_code = Some(arkret_wire::ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED);
            return Err(error);
        }
        return derive_realm_id_from_event_id(object);
    }

    if let Some(realm_id) = event_string_field(object, &["realm_id"]) {
        if RealmId::new(realm_id.clone()).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "realm_id must use the ak:realm: typed prefix",
            ));
        }
        return Ok(realm_id.clone());
    }

    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "param_missing",
        "realm_id is required",
    ))
}

#[cfg(test)]
/// Derive this genesis Event's Realm id from its own signed content.
///
/// Two branches, both pure functions of the signed Event, so the id stays
/// self-certifying either way (spec `zh/models/realm-and-space.md` section
/// 2.5.0): every Realm, including a Principal Control Realm, is
/// `retype(event_id)`.
///
/// This is also the **first-contact check**: because the id is a function of
/// the Event, a receiver that is served a fabricated "Realm S" computes a
/// different id and never reaches the state that would let the forgery in.
fn derive_realm_id_from_event_id(
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let event_id = event_string_field(object, &["event_id"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "event_id is required to derive the Realm id",
        )
    })?;
    let event_id = arkret_wire::EventId::new(event_id.clone()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "event_id must use the ak:event: typed prefix",
        )
    })?;
    Ok(arkret_wire::derive_genesis_realm_id(&event_id).into_string())
}

#[cfg(test)]
mod event_derived_id_tests {
    use super::*;

    #[test]
    fn realm_genesis_uses_the_common_carried_object_id_reason() {
        let object = serde_json::json!({
            "kind": "ak.realm.create",
            "event_id": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "realm_id": "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
        })
        .as_object()
        .expect("object fixture")
        .clone();
        let error = event_realm_id(&object).expect_err("realm_id is reducer-derived");
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.code, "schema_violation");
        assert_eq!(
            error.reason_code,
            Some(arkret_wire::ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED)
        );
    }

    #[test]
    fn non_genesis_realm_id_with_reserved_header_bits_is_rejected() {
        let object = serde_json::json!({
            "kind": "ak.message.create",
            "realm_id": "ak:realm:_V1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
        })
        .as_object()
        .expect("object fixture")
        .clone();
        let error = event_realm_id(&object).expect_err("reserved header bits must fail closed");
        assert_eq!(error.code, "param_invalid");
    }
}

#[cfg(test)]
mod applet;
#[cfg(test)]
mod capability_grant;

#[cfg(test)]
mod features_schema;

#[cfg(test)]
mod proofs;

#[cfg(test)]
pub(crate) use features_schema::validate_event_schema_and_payload;
#[cfg(test)]
pub(crate) use proofs::validate_event_proofs;
