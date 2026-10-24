//! Real adapter regressions. Policy, commit and proof rows are seeded as
//! already admitted inputs; these tests exercise consumption, not
//! cryptographic admission.
use arkret_models_crypto as crypto;
use arkret_wire as wire;
use serde_json::json;

use super::*;

const SESSION: &str = "ak:recovery_session:01904100-0000-7000-8000-000000000021";
const BACKUP: &str = "ak:backup:01904100-0000-7000-8000-000000000022";
const REQUEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PRINCIPAL: &str = "ak:did_core:web:unlock-test.example";
const STATION: &str = "ak:did_core:web:station.example";

struct Fixture {
    _database: crate::test_database::TestDatabase,
    store: crate::key_backup::PgKeyBackupStore,
    policy: Value,
    backup: Value,
    holder: String,
    policy_expiry: chrono::DateTime<Utc>,
}

async fn insert_policy(pool: &crate::PgPool, policy: &Value) {
    // The authoritative admission layer is outside this storage-boundary test.
    // Keep the session Verified even for a later revoke, so the production
    // history gate itself must reject rather than relying on publication cleanup.
    let typed: arkret_models_crypto::RecoveryPolicy =
        serde_json::from_value(policy.clone()).unwrap();
    typed.validate_shape().unwrap();
    let acceptance_basis =
        wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(b"recovery-policy"));
    let mut conn = pg_conn(pool).await.unwrap();
    sql_query("INSERT INTO recovery_policies(id,principal_id,station_id,version,acceptance_basis,trust_domain,expires_at,issued_at,verification_method,raw_payload,accepted_at) VALUES($1,$2,$3,$4,$5,'ak:trust_domain:station.example',$6,$7,'did:web:unlock-test.example#root',$8,$7)")
        .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(typed.policy_id.as_str()))
        .bind::<Text,_>(PRINCIPAL).bind::<Text,_>(STATION).bind::<crate::Integer,_>(typed.version as i32)
        .bind::<Jsonb,_>(serde_json::to_value(&acceptance_basis).unwrap())
        .bind::<Nullable<Timestamptz>,_>(typed.expires_at).bind::<Timestamptz,_>(typed.issued_at)
        .bind::<Jsonb,_>(policy.clone()).execute(&mut conn).await.unwrap();
    sql_query("INSERT INTO policy_current_states(realm_id,policy_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) VALUES($1,$2,$3,1,$4,$5,$6)")
        .bind::<Text,_>(wire::RealmId::from_event_id(&wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, arkret_canonical::sha256_bytes(b"recovery-policy-realm"))).as_str())
        .bind::<Text,_>(typed.policy_id.as_str())
        .bind::<Text,_>(acceptance_basis.as_str())
        .bind::<Text,_>(wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, arkret_canonical::sha256_bytes(b"recovery-policy-event")).as_str())
        .bind::<Jsonb,_>(policy)
        .bind::<Timestamptz,_>(typed.issued_at)
        .execute(&mut conn).await.unwrap();
}

impl Fixture {
    async fn new() -> Self {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let now = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let policy_expiry = now + chrono::Duration::minutes(10);
        let account = json!({"principal_id":PRINCIPAL,"station_id":STATION});
        let signature = arkret_canonical::base64url_encode([7u8; 64]);
        let policy = json!({
            "schema":"ak.schema.recovery_policy.v1",
            "policy_id":"ak:policy:01904100-0000-7000-8000-000000000001",
            "account_id":account,"version":1,"supersedes_id":null,
            "trust_domain":"ak:trust_domain:station.example","methods":[{"kind":"did_root"}],
            "issued_at":(now-chrono::Duration::minutes(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis,true),
            "expires_at":policy_expiry.to_rfc3339_opts(chrono::SecondsFormat::Millis,true),
            "signature_proof":{"verification_method":"did:web:unlock-test.example#root","signature_algorithm":"Ed25519","signature":signature}
        });
        let typed_policy: arkret_models_crypto::RecoveryPolicy =
            serde_json::from_value(policy.clone()).unwrap();
        typed_policy.validate_shape().unwrap();
        let challenge =
            wire::Base64UrlString::new(arkret_canonical::base64url_encode([42u8; 32])).unwrap();
        let proof = crypto::RecoverySessionProofSubmitRequestBody {
            proof: crypto::RecoverySessionProof::DidRoot(crypto::DidRootProofBody {
                kind: crypto::DidRootProofKind::DidRoot,
                challenge: challenge.clone(),
                verification_method: wire::DidUrl::new("did:web:unlock-test.example#root").unwrap(),
                signature_algorithm: crypto::RecoverySignatureAlgorithm::Ed25519,
                signature: wire::Base64UrlString::new(signature.clone()).unwrap(),
            }),
        };
        proof.proof.validate_shape().unwrap();
        let proof_payload = serde_json::to_value(&proof).unwrap();
        let proof: crypto::RecoverySessionProofSubmitRequestBody =
            serde_json::from_value(proof_payload.clone()).unwrap();
        let device = wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000023").unwrap();
        let backup = crypto::KeyBackup {
            backup_id: wire::BackupId::new(BACKUP).unwrap(),
            actor_id: wire::ActorId::account(typed_policy.account_id.clone()),
            device_id: Some(device.clone()),
            backup_kind: crypto::BackupKind::SecretStorage,
            mixed_secret_storage: false,
            backup_version: "kb_1".into(),
            created_at: now,
            updated_at: None,
            expires_at: None,
            encryption: crypto::KeyBackupEncryption {
                recipient_method: crypto::KeyBackupRecipientMethod::SecretStorageKey,
                recipient_key_ref: Some("backup-key".into()),
                hpke_suite: None,
                kdf: None,
                aead: crypto::KeyBackupAead {
                    name: crypto::KeyBackupAeadName::Xchacha20Poly1305,
                    aead_profile: None,
                    nonce_salt: None,
                    nonce: Some(
                        wire::Base64UrlString::new(arkret_canonical::base64url_encode([0u8; 24]))
                            .unwrap(),
                    ),
                    enc: None,
                    extra: Default::default(),
                },
                key_commitment: None,
                extra: Default::default(),
            },
            domain_separation: crypto::KeyBackupDomainSeparation {
                subdomain: "arkret_secret_storage_v1".into(),
                aead_aad_extensions: Default::default(),
            },
            contents: vec![crypto::SecretStorageContentIndex {
                item_kind: crypto::SecretStorageItemKind::RecoveryKeyShare,
                secret_id: "share".into(),
            }],
            ciphertext: wire::Base64UrlString::new(arkret_canonical::base64url_encode([0u8; 24]))
                .unwrap(),
            ciphertext_digest: wire::Hash::new(arkret_canonical::sha256_digest([0u8; 24])).unwrap(),
            plaintext_commitment: None,
            signature_proof: crypto::KeyBackupSignatureProof {
                device_id: device.clone(),
                verification_method: wire::DidUrl::new("did:web:unlock-test.example#root").unwrap(),
                signature_algorithm: crypto::KeyBackupSignatureAlgorithm::Ed25519,
                signature: wire::Base64UrlString::new(signature.clone()).unwrap(),
                device_authorize_event_id: wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [80u8; 32],
                ),
            },
            retention: None,
            series_id: wire::BackupSeriesId::new(
                "ak:backup_series:01904100-0000-7000-8000-000000000024",
            )
            .unwrap(),
            series_sequence: 0,
            supersedes_id: None,
            supersedes_digest: None,
            recovery_policy_ref: None,
            source_commit_ref: Some(crypto::KeyBackupSourceCommitRef {
                realm_commit_id: wire::RealmCommitId::from_digest([79u8; 32]),
                device_generation_ref: 1,
            }),
            extra: Default::default(),
        };
        backup.validate().unwrap();
        let backup = serde_json::to_value(backup).unwrap();
        assert!(backup.get("source_ref").is_none());
        assert_eq!(backup["source_commit_ref"]["device_generation_ref"], 1);
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [81; 32],
        ));
        // The unlock authority is anchored on one committed Event of the PCR
        // Realm stream, addressed by its `CommittedEventRef`. A total commit
        // order replaced the accepted-Seal basis: there is no lattice to join,
        // so "still current" is the single question of whether this exact
        // commit still sits at this exact stream position.
        let stream_ref = wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let basis_event_id =
            wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [82u8; 32]);
        let basis_commit_id = wire::RealmCommitId::from_digest([83u8; 32]);
        let basis_commit = wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: basis_commit_id.clone(),
            realm_id: realm.clone(),
            stream_ref: stream_ref.clone(),
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: basis_event_id.clone(),
            governance_generation: 0,
            authority_ref: wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                basis_event_id.clone(),
            ),
            committed_at: now,
            signature: wire::DetachedObjectSignature {
                context: wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: wire::DidUrl::new("did:web:station.example#authority")
                    .unwrap(),
                signed_digest: wire::Hash::new(REQUEST).unwrap(),
                created_at: now,
                signature: wire::Base64UrlString::new(signature.clone()).unwrap(),
            },
        };
        basis_commit.validate_shape().unwrap();
        let authority_policy = crypto::AuthoritySetPolicy {
            schema: wire::SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: wire::AuthoritySetId::RECOVERY_IDENTITY_REANCHOR_V1.to_owned(),
            policy_kind: wire::AuthoritySetPolicyKind::PrincipalControl,
            scope_ref: wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            // The materialized policy now names the commit that produced it
            // instead of an offline source descriptor and its digest.
            source_commit_id: basis_commit_id.clone(),
            authorization_rules: vec![crypto::AuthoritySetAuthorizationRule {
                rule_id: "identity_recovery".to_owned(),
                issuer_role: crypto::AuthoritySetIssuerRole::IdentityRecovery,
                allowed_actions: vec![crypto::RECOVERY_PUBLICATION_ALLOWED_ACTION.to_owned()],
                issuers: vec![crypto::AuthoritySetAuthorizationIssuer {
                    verification_method: wire::DidUrl::new("did:web:unlock-test.example#root")
                        .unwrap(),
                }],
                threshold: 1,
            }],
        };
        let publication_context = crypto::PublicationAuthorityContext {
            authority_commit_id: basis_commit_id.clone(),
            scope_ref: authority_policy.scope_ref.clone(),
            authority_set_policy: authority_policy,
            allowed_actions: vec![crypto::RECOVERY_PUBLICATION_ALLOWED_ACTION.to_owned()],
        };
        publication_context.validate_shape().unwrap();
        let publication_context_digest =
            wire::Hash::new(arkret_canonical::canonical_sha256(&publication_context).unwrap())
                .unwrap();
        let cnf = arkret_canonical::base64url_encode([3u8; 32]);
        let grant = arkret_wire::SessionGrantId::from_issuance_digest([4u8; 32]);
        let holder = format!("{grant}:{cnf}");
        let public_session = crypto::RecoverySession {
            schema: wire::SchemaId::RECOVERY_SESSION_V1.to_owned(),
            request_id: wire::RequestId::new("ak:request:01904100-0000-7000-8000-000000000025")
                .unwrap(),
            recovery_session_id: wire::RecoverySessionId::new(SESSION).unwrap(),
            session_grant_id: grant,
            session_grant_cnf_jkt: wire::Base64UrlString::new(cnf.clone()).unwrap(),
            account_id: typed_policy.account_id.clone(),
            requesting_device_id: device,
            requesting_device_public_key_did: wire::DidKey::new(
                "did:key:z6MkwVDfCg9LbbY6xjH3EZk8YSFQZujV5Y4y1ZWeER9tDiN3",
            )
            .unwrap(),
            trust_domain: typed_policy.trust_domain.clone(),
            policy_id: typed_policy.policy_id.clone(),
            policy_version: typed_policy.version,
            identity_model: crypto::RecoveryIdentityModel::PcrPolicy,
            current_device_generation_ref: 1,
            realm_stream_head: wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 0,
                commit_id: basis_commit_id.clone(),
            },
            publication_authority_context: publication_context,
            publication_authority_context_digest: publication_context_digest,
            challenge,
            state: crypto::RecoverySessionState::Verified,
            proof_summary: Some(crypto::RecoverySessionProofSummary {
                kind: crypto::RecoveryProofKind::DidRoot,
                proof_digest: wire::Hash::new(
                    arkret_canonical::canonical_sha256(&proof.proof).unwrap(),
                )
                .unwrap(),
                verification_method: Some(
                    wire::DidUrl::new("did:web:unlock-test.example#root").unwrap(),
                ),
            }),
            transaction_id: None,
            rejection_reason_code: None,
            expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            updated_at: now,
        };
        public_session.validate_shape().unwrap();
        let mut session = serde_json::to_value(&public_session).unwrap();
        serde_json::from_value::<crypto::RecoverySession>(session.clone()).unwrap();
        // Map the complete validated public DTO to the SQL record columns.
        for field in [
            "schema",
            "recovery_session_id",
            "account_id",
            "proof_summary",
            "rejection_reason_code",
        ] {
            session.as_object_mut().unwrap().remove(field);
        }
        let accepted_stream_head = session
            .as_object_mut()
            .unwrap()
            .remove("realm_stream_head")
            .unwrap();
        session["accepted_stream_head"] = accepted_stream_head.clone();
        session["authority_context"] =
            serde_json::to_value(coland_storage::RecoveryAuthorityContext {
                realm_id: realm.clone(),
                authority_generation: 0,
                authority_ref: basis_commit.authority_ref.clone(),
                realm_stream_head: serde_json::from_value(accepted_stream_head).unwrap(),
            })
            .unwrap();
        session["id"] = json!(ids::typed_uuid_part_expect_internal(SESSION));
        session["create_intent_digest"] = json!(REQUEST);
        session["principal_id"] = json!(PRINCIPAL);
        session["station_id"] = json!(STATION);
        session["policy_id"] = json!(ids::typed_uuid_part_expect_internal(
            typed_policy.policy_id.as_str()
        ));
        session["policy_payload"] = policy.clone();
        session["proof_payload"] = proof_payload;
        assert_eq!(
            arkret_canonical::base64url_decode(&signature)
                .unwrap()
                .len(),
            64
        );
        insert_policy(&pool, &policy).await;
        let mut conn = pg_conn(&pool).await.unwrap();
        sql_query("INSERT INTO recovery_sessions SELECT * FROM jsonb_populate_record(NULL::recovery_sessions,$1)")
            .bind::<Jsonb,_>(session).execute(&mut *conn).await.unwrap();
        let basis_token = ids::event_token_part_expect_internal(basis_event_id.as_str(), "event");
        sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,received_at,committed_at) VALUES($1,1,$2,$3,$4,$5,'ak.realm.genesis','\\x00'::bytea,'{}','committed',$6,$6)")
            .bind::<crate::Binary,_>(basis_token.to_vec())
            .bind::<crate::Binary,_>(basis_token[1..].to_vec())
            .bind::<Text,_>(STATION)
            .bind::<Text,_>(realm.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(&wire::ScopeRef::Realm{realm_id:realm.clone()}).unwrap())
            .bind::<Timestamptz,_>(now).execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,0,NULL,pk,0,$5,$6 FROM canonical_events WHERE id=$7")
            .bind::<Text,_>(basis_commit_id.as_str())
            .bind::<Text,_>(realm.as_str())
            .bind::<Text,_>(arkret_canonical::canonical_json_string(&stream_ref).unwrap())
            .bind::<Jsonb,_>(serde_json::to_value(&stream_ref).unwrap())
            .bind::<Jsonb,_>(serde_json::to_value(&basis_commit).unwrap())
            .bind::<Timestamptz,_>(now)
            .bind::<crate::Binary,_>(basis_token.to_vec())
            .execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO key_backups(id,payload,actor_id) VALUES($1,$2,$3)")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(BACKUP))
            .bind::<Jsonb, _>(&backup)
            .bind::<Text, _>(
                serde_json::from_value::<arkret_wire::ActorId>(backup["actor_id"].clone())
                    .unwrap()
                    .to_string(),
            )
            .execute(&mut *conn)
            .await
            .unwrap();
        let (digest, charge) = object_charge(&backup).unwrap();
        sql_query("INSERT INTO key_backup_unlock_authorities(authority_id,identity_key,account_id,device_id,kind,challenge,expires_at,remaining_bytes,verified_at,rate_per_minute) VALUES($1,$1,$2,'ak:device:01904100-0000-7000-8000-000000000023','recovery_session','{}',$3,$4,$5,4)")
            .bind::<Text,_>(SESSION).bind::<Text,_>(arkret_canonical::canonical_json_string(&account).unwrap())
            .bind::<Timestamptz,_>(now+chrono::Duration::hours(1)).bind::<BigInt,_>(charge).bind::<Timestamptz,_>(now).execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO key_backup_unlock_entries(authority_id,backup_id,object_digest,charge) VALUES($1,$2,$3,$4)")
            .bind::<Text,_>(SESSION).bind::<Text,_>(BACKUP).bind::<Text,_>(digest).bind::<BigInt,_>(charge).execute(&mut *conn).await.unwrap();
        drop(conn);
        Self {
            _database: database,
            store: crate::key_backup::PgKeyBackupStore { pool },
            policy,
            backup,
            holder,
            policy_expiry,
        }
    }

    async fn add_policy(&self, version: u32, revoke: bool) {
        let mut policy = self.policy.clone();
        policy["version"] = json!(version);
        policy["policy_id"] = json!(format!("ak:policy:01904100-0000-7000-8000-{version:012}"));
        policy["supersedes_id"] = json!(format!(
            "ak:policy:01904100-0000-7000-8000-{:012}",
            version - 1
        ));
        if revoke {
            policy["methods"] = json!([]);
        }
        insert_policy(&self.store.pool, &policy).await;
    }

    async fn consume(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<Value> {
        self.store
            .consume_unlock_entry(coland_storage::KeyBackupUnlockCommand {
                basis: &coland_storage::KeyBackupUnlockBasis::RecoverySession,
                authority_id: SESSION,
                backup: self.backup.clone(),
                request_digest: REQUEST,
                holder: &self.holder,
                ip: "127.0.0.1",
                now,
                daily_limit: 64,
            })
            .await
    }

    async fn ledger(&self) -> Value {
        let mut conn = pg_conn(&self.store.pool).await.unwrap();
        sql_query("SELECT jsonb_build_object('remaining',a.remaining_bytes,'request',e.request_digest,'holder',e.holder,'consumed',e.consumed_at IS NOT NULL,'session_state',s.state) AS payload FROM key_backup_unlock_authorities a JOIN key_backup_unlock_entries e USING(authority_id) JOIN recovery_sessions s ON s.id=$2 WHERE a.authority_id=$1")
            .bind::<Text,_>(SESSION).bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(SESSION))
            .get_result::<JsonPayloadRow>(&mut conn).await.unwrap().payload
    }
}

#[tokio::test]
async fn recovery_unlock_pg_rotation_preserves_frozen_authority_and_exact_retry() {
    let fixture = Fixture::new().await;
    fixture.add_policy(2, false).await;
    assert_eq!(fixture.consume(Utc::now()).await.unwrap(), fixture.backup);
    let consumed = fixture.ledger().await;
    assert_eq!(consumed["remaining"], 0);
    assert_eq!(consumed["request"], REQUEST);
    assert_eq!(consumed["holder"], fixture.holder);
    assert_eq!(fixture.consume(Utc::now()).await.unwrap(), fixture.backup);
    assert_eq!(
        fixture.ledger().await,
        consumed,
        "exact retry cannot charge twice"
    );
}

#[tokio::test]
async fn recovery_unlock_pg_revoke_then_reenable_rejects_first_consumption() {
    let fixture = Fixture::new().await;
    fixture.add_policy(2, true).await;
    fixture.add_policy(3, false).await;
    let before = fixture.ledger().await;
    assert_eq!(before["session_state"], "verified");
    let error = fixture.consume(Utc::now()).await.unwrap_err();
    assert!(error.to_string().contains("revoked"), "{error}");
    assert_eq!(
        fixture.ledger().await,
        before,
        "rejected request must not consume allowance"
    );
}

#[tokio::test]
async fn recovery_unlock_pg_exact_retry_rechecks_historical_policy_revocation() {
    let fixture = Fixture::new().await;
    fixture.consume(Utc::now()).await.unwrap();
    let before = fixture.ledger().await;
    fixture.add_policy(2, true).await;
    fixture.add_policy(3, false).await;
    let error = fixture.consume(Utc::now()).await.unwrap_err();
    assert!(error.to_string().contains("revoked"), "{error}");
    assert_eq!(
        fixture.ledger().await,
        before,
        "terminal record remains intact but cannot authorize disclosure"
    );
}

#[tokio::test]
async fn recovery_unlock_pg_exact_retry_rechecks_frozen_policy_expiry() {
    let fixture = Fixture::new().await;
    fixture.consume(Utc::now()).await.unwrap();
    let before = fixture.ledger().await;
    // Advance the production API's evaluation instant, not wall-clock sleeping.
    // The session/allowance lasts an hour; only the frozen policy expires here.
    let error = fixture
        .consume(fixture.policy_expiry + chrono::Duration::seconds(1))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("expired"), "{error}");
    assert_eq!(fixture.ledger().await, before);
}
