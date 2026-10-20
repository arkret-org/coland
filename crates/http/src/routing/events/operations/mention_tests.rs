mod audience_mention_tests {
    use serde_json::json;

    use super::super::*;

    #[test]
    fn audience_mention_accepts_here_as_strand_engaged() {
        let content = json!({
            "kind": "ak.content.composite",
            "body": "",
            "parts": [
                {
                    "kind": "ak.content.text",
                    "body": "Team heads up",
                    "audience_mentions": [{
                        "kind": "audience_mention",
                        "audience": "strand_engaged",
                        "mention_text_original": "@here"
                    }]
                }
            ]
        });

        validate_content_blocks(&content).unwrap();
        validate_mentions(&content).unwrap();
    }

    #[test]
    fn audience_mention_rejects_presence_online_without_profile() {
        let content = json!({
            "kind": "audience_mention",
            "audience": "strand_engaged",
            "mention_text_original": "@online"
        });

        assert_eq!(
            validate_mentions(&content),
            Err("presence-filtered audience mention requires an explicit profile")
        );
    }

    #[test]
    fn audience_mention_policy_requires_finite_limits_and_quota() {
        let policy = json!({
            "enabled": true,
            "allowed_audiences": ["strand_engaged"],
            "max_recipients": 5,
            "quota": {"max_operations": 2, "period": "PT1H"}
        });

        audience_mention_policy_allows(&policy, "strand_engaged", 5).unwrap();
        assert_eq!(
            audience_mention_policy_allows(&policy, "strand_engaged", 6),
            Err("audience_mention_recipient_count_exceeds_limit")
        );
    }
}

mod direct_mention_tests {
    use serde_json::json;

    use super::super::*;

    const STATION: &str = "ak:did_core:web:bob.station.example";

    #[test]
    fn message_admission_checks_the_complete_realm_mention_target() {
        let realm = arkret_identifiers::RealmId::new(
            "ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr",
        )
        .unwrap();
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-57d7d85564c5",
            )
            .unwrap(),
            realm.clone(),
            arkret_wire::EventKind::MessageCreate.as_str(),
            json!({
                "strand_id": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "track_name":"discussion",
                "content":{
                    "kind":"ak.content.text",
                    "body":"Hello @Helper",
                    "mentions":[{
                        "kind":"mention",
                        "subject_actor_id":{
                            "kind":"realm",
                            "realm_actor_id":{
                                "realm_id":realm,
                                "principal_id":"ak:did_core:webvh:z6mkfixtureBot"
                            }
                        }
                    }]
                }
            }),
        );
        validate_message_operation_payload(&operation).unwrap();
        operation.payload["content"]["mentions"][0]["subject_actor_id"]["realm_actor_id"]["realm_id"] =
            json!("ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5");
        assert_eq!(
            validate_message_operation_payload(&operation),
            Err("mention subject belongs to another Realm"),
        );
    }

    #[test]
    fn canonical_mention_accepts_complete_account_subject() {
        let content = json!({
            "kind": "ak.content.text",
            "body": "hello @bob",
            "mentions": [{
                "kind": "mention",
                "subject_account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixtureBob",
                    "station_id": STATION
                },
                "mention_text_original": "@bob"
            }]
        });

        validate_mentions(&content).unwrap();
        assert_eq!(
            mention_subject_account_ids(&content).unwrap(),
            vec![arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixtureBob").unwrap(),
                arkret_wire::DidCoreId::new(STATION).unwrap(),
            )]
        );
    }

    /// `identity-handles.md §3.8` — a mention subject is one complete account,
    /// so a bare principal carrier is not admissible at all.
    #[test]
    fn canonical_mention_rejects_bare_principal_subject() {
        let content = json!({
            "kind": "ak.content.text",
            "body": "hello @bob",
            "mentions": [{
                "kind": "mention",
                "subject_account_id": "ak:did_core:webvh:z6mkfixtureBob"
            }]
        });

        assert_eq!(validate_mentions(&content), Err("mention node is invalid"));
    }

    /// The same principal at another Station is a different subject: the
    /// collected account ids MUST NOT compare equal.
    #[test]
    fn same_principal_on_another_station_is_a_different_mention_subject() {
        let subject = |station: &str| {
            json!({
                "kind": "ak.content.text",
                "body": "hello @bob",
                "mentions": [{
                    "kind": "mention",
                    "subject_account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkfixtureBob",
                        "station_id": station
                    }
                }]
            })
        };
        let here = mention_subject_account_ids(&subject(STATION)).unwrap();
        let elsewhere =
            mention_subject_account_ids(&subject("ak:did_core:web:other.station.example")).unwrap();

        assert_eq!(here[0].principal_id, elsewhere[0].principal_id);
        assert_ne!(here, elsewhere);
    }

    #[test]
    fn canonical_mention_rejects_did_subject() {
        let content = json!({
            "kind": "ak.content.text",
            "body": "hello @bob",
            "mentions": [{
                "kind": "mention",
                "subject_account_id": {
                    "principal_id": "did:web:bob.example",
                    "station_id": STATION
                }
            }]
        });

        assert_eq!(validate_mentions(&content), Err("mention node is invalid"));
    }

    #[test]
    fn non_canonical_mention_shapes_are_rejected() {
        for entry in [
            json!("ak:did_core:webvh:z6mkfixtureBob"),
            json!({"type": "actor", "did": "did:web:bob.example"}),
            json!({"type": "strand", "strand_id": "ak:strand:x"}),
        ] {
            let content = json!({
                "kind": "ak.content.text",
                "body": "hello",
                "mentions": [entry]
            });

            assert_eq!(
                validate_mentions(&content),
                Err("mention node kind must be mention or audience_mention")
            );
        }
    }

    #[test]
    fn canonical_mention_in_composite_part_is_validated() {
        let content = json!({
            "kind": "ak.content.composite",
            "body": "",
            "parts": [
                {
                    "kind": "ak.content.text",
                    "body": "hello @bob",
                    "mentions": [{
                        "kind": "mention",
                        "subject_account_id": {
                            "principal_id": "did:web:bob.example",
                            "station_id": STATION
                        }
                    }]
                }
            ]
        });

        assert_eq!(validate_mentions(&content), Err("mention node is invalid"));
    }
}

mod reaction_and_window_policy_tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use serde_json::json;

    use super::super::*;

    fn reaction_op(kind: impl AsRef<str>, payload: serde_json::Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-57d7d85564c5",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr",
            )
            .unwrap(),
            kind.as_ref(),
            payload,
        )
    }

    #[test]
    fn reaction_on_message_target_is_accepted() {
        let op = reaction_op(
            arkret_wire::EventKind::ReactionAdd,
            json!({
                "target_ref": "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "key": "👍",
            }),
        );
        assert!(validate_reaction_target_kind(&arkret_wire::EventKind::ReactionAdd, &op).is_ok());
    }

    #[test]
    fn reaction_on_event_storage_id_is_rejected() {
        let op = reaction_op(
            arkret_wire::EventKind::ReactionAdd,
            json!({
                "target_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "key": "👍"
            }),
        );
        assert_eq!(
            validate_reaction_target_kind(&arkret_wire::EventKind::ReactionAdd, &op),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }

    #[test]
    fn reaction_on_non_message_target_is_rejected() {
        for target in [
            "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "ak:morph:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "ak:circle:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        ] {
            let op = reaction_op(
                arkret_wire::EventKind::ReactionAdd,
                json!({ "target_ref": target }),
            );
            assert_eq!(
                validate_reaction_target_kind(&arkret_wire::EventKind::ReactionAdd, &op),
                Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
                "target {target} must be rejected",
            );
        }
    }

    #[test]
    fn non_reaction_kinds_skip_target_check() {
        let op = reaction_op(
            arkret_wire::EventKind::MessageCreate,
            json!({ "target_ref": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19" }),
        );
        assert!(validate_reaction_target_kind(&arkret_wire::EventKind::MessageCreate, &op).is_ok());
    }

    #[test]
    fn realm_id_alias_forms_match() {
        assert!(!realm_ids_match(
            "ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr",
            "ak:space:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
        ));
        assert!(realm_ids_match("ak:realm:abc", "ak:realm:abc"));
        assert!(!realm_ids_match("ak:realm:abc", "ak:realm:def"));
    }

    #[test]
    fn policy_reason_code_maps_precondition_vs_capability() {
        assert_eq!(
            operation_policy_reason_code("reaction_outside_scope").1,
            "failed_precondition"
        );
        assert_eq!(
            operation_policy_reason_code("some other policy failure").1,
            "capability_denied"
        );
    }
}
