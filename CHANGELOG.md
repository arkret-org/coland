# coland — changelog

All notable wire-affecting changes to the coland Station are
recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/)
and the project tracks Arkret v1 spec revisions.

## R3.4 — Spec sync 2026-05-31 (arkret-spec @ c2848a4)

- Synced protocol-facing names and fixtures to `c2848a4`: event envelope schema naming, `_ids` grant constraints, accountability principal vocabulary, `ak:rtc_participant:` media participants, agent session start fields, and key-backup signature algorithm naming where applicable.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3.3 — Spec sync 2026-05-28 (arkret-spec @ cced4b8)

- R3.3 spec sync — pin to arkret-spec @ cced4b8 (AKP-0011 shareable object addressing / `ak.find.directory.read.resolve_target.v1`: N/A for this service; object-address resolution belongs to the Directory Service).

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3.2 — Spec sync 2026-05-28 (arkret-spec @ b56cab1)

- Roster v2: `identity_state_digest` → `member_display_state_digest`; added disclosure-gated `subject_id` / `handle_claim_digests` / `handle_claims` / `handle_claims_limited` (omitted together unless subject disclosed).
- `ak.member.identity.update` payload `identity_state_digest` → `identity_payload_digest`; `expected_state_digest` uses the segment-inclusive effective-set formula; effective set stays multi-valued (no last-writer-wins).
- New wire validators reject MemberIdentity `primary_handle`/`handles[]` (`member_identity_handle_field_forbidden`) and handle-claim `service_handle` / non-principal subject.
- Real handle-claim evidence population + Realm subject_id disclosure policy deferred `TODO(R3.2.1)` (fails closed).

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3 — Spec sync 2026-05-27 (arkret-spec @ b47ff6ec)

- HTTP-1: `POST /api/v1/rtc/token` (ak.self.call.media.exchange.issue_token.v1) mounted as a 501 stub in `src/routing/system/rtc.rs`; real TTL / participant_binding / service_signature issuer logic deferred to R3.1.
- HTTP-2: agent route canonicalised — `/agents/{id}/deactivate` only, no `/revoke` path remains.
- HTTP-4: recovery policy / receipt endpoints (`POST /api/v1/identity/recovery-policy`, `POST /api/v1/identity/recovery-receipt`) mounted as 501 stubs in `src/routing/identity/recovery.rs`.
- ERR-1: protocol reason codes are emitted from concrete validation and handler paths; obsolete round-scoped grouping helpers are not part of the runtime surface.
- PROF-1: `ak.profile.media_service_binding.v1` advertised in `ak.server.read.describe.supported_profiles` (`src/wire.rs`).

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## [Unreleased]

### AKP-0007 — Circle primitive rollout (P2A; arkret-spec floor `2b0d70d`)

Aggressive mode; no compatibility shim. Tracks the SDK's P1 baseline
(`circle-rollout` branch) and consumes the seven `ak.circle.*` durable event
kinds, six `ak.circle.*` capability actions, and six new failed-precondition
reason codes registered in `arkret-spec` `9cb47c1..2b0d70d`.

- **BREAKING** `Strand.discussion_realm_ref` is no longer accepted on the wire.
  Cross-Realm discussion routing has been removed (AKP-0007 hard
  delete; intra-Realm discussion boundaries now live on a Circle via
  `scope_circle_id`). The reducer's `strand_discussion_realms` projection
  field, the `discussion_realm_patch` dispatch, and the `ak.realm.destroy`
  cross-Realm discussion-edge cascade have all been deleted outright.
- Migration `20260526000000_drop_discussion_realm_ref` drops the removed
  `projection_strands.discussion_realm_ref` column when present.
- New `/api/v1/circles/*` admin surface
  (`POST/GET/DELETE` Circle CRUD + members + scope-rotate / archive /
  tombstone). Reducer enforces the strict-subset invariant
  `Circle.members ⊆ Realm.members` and the four canonical AKP-0007
  reasons (`circle_realm_mismatch`, `circle_not_active`,
  `circle_already_terminal`, `circle_member_must_be_realm_member`).
- 7 active `ak.circle.*` event kinds (`create` / `update` / `archive` /
  `restore` / `tombstone` / `member.state` / `anchor_commit`) wired into
  the reducer dispatch (`anchor_commit` is reducer-derived per
  `NON_REDUCER_EVENT_KINDS`).
- New diesel migrations:
  `20260526010000_add_circles` (`projection_circles` +
  `projection_circle_members`), `20260526020000_add_scope_circle_id`
  (`scope_circle_id` on Strand / Morph / Space; `default_scope_circle_id`
  + `child_scope_policy` on Space; `effective_scope` on
  `projection_events`). Bidirectional migrations; `down` is provided for
  diesel symmetry only — see `DEPLOYMENT.md` §11 for the disk-sizing
  estimate.
- Authz: `allowed_circle_ids` constraint type added to the local
  evaluator. Required by the six `ak.circle.*` capability actions per
  the spec's `required_constraints` declaration.
- 6 AKP-0007 sub-reason codes re-exported via `crate::error::reasons::*`
  (`circle_realm_mismatch`, `circle_not_active`,
  `circle_member_must_be_realm_member`, `scope_rebind_forbidden`,
  `metadata_encryption_floor_violation`).
- Read path now surfaces `effective_scope` on event metadata when the
  envelope or payload pins a `scope_circle_id`.
- `confidential_discussion_of` Relation kind accepted by the reducer
  with a new `confidential_discussions_of(strand_id)` query helper.
- Dockerfile gains `HEALTHCHECK`, `tini` PID-1 init, and a
  `COLAND_METRICS_BIND` default so the metrics endpoint surfaces under
  the new sidecar port `9698`.

### Round R4 — protocol review closures (2026-05-20; arkret-spec `2a4d39b..a77b995`)

Aggressive mode; no compatibility shim. Closes 8 protocol-review commits
on the reducer / federation / state-machine surfaces. See
[`../_todos.md`](../_todos.md) for the workstream context.

- **BREAKING** `ak.realm.create` reducer now captures and locks `trust_domain`
  as immutable Realm state. Subsequent mismatching events reject with
  `cross_domain_replay_rejected`.
- **BREAKING** `ServiceDescribe` v2: `ak.server.read.describe.v1` /
  `ak.self.account.read.describe.v1` / `ak.edge.applet.read.describe.v1` both return
  the 17-field canonical envelope (including `trust_domain`,
  `plaintext_visibility`, `claimed_profiles`, `verified_profiles`,
  `development_mode`); `development_mode=true` with non-empty
  `verified_profiles` warns.
- **BREAKING** `/events/frontier` split by `peer_role` query param into the
  three discriminated shapes `account_client` / `federation_peer` /
  `anonymous_health`. The `anonymous_health` response strips `receipts` and
  `actor_seq_upper_bounds`.
- **BREAKING** `/events/subscribe` NDJSON now emits typed
  `EventsSubscribeFrame{kind}`; `dropped` frames MUST carry a `cursor`
  (otherwise downgrade to `resync_required`).
- **BREAKING** `/events/submit` split into the discriminated oneOf
  `single` / `batch` / `federation`. Federation form requires the 6-field
  `FederationServiceBindingRef`; missing fields reject as `schema_violation`.
- **BREAKING** Federation S2S transport verifies and signs the three new
  headers `Source-Trust-Domain` / `Destination-Trust-Domain` /
  `Request-Canonical-Digest`; mismatch reject as `cross_domain_replay_rejected`.
- **BREAKING** Federation idempotency cache key now combines
  `source_did` / `dest_did` / `request_canonical_digest` / `idempotency_key` /
  `origin_key_state_digest`. Cache hits after key-state change return the
  cached body with diagnostic `reason_code=historical_only` (no side
  effects); cache hits re-run capability checks.
- **REMOVED LEGACY** the former device-hierarchy publish reducer enforced CAS
  (`expected_previous_generation == current && new_generation == current + 1`),
  evaluated before signature verification.
- **BREAKING** `audit_policy_version_digest` switched to the 4-arg form
  `{realm_id, trust_domain, audit_disclosure, audit_assurance}`; old
  2-arg receipts no longer verify. `AuditRywReceipt` now carries
  `trust_domain`.
- **BREAKING** `/blob/presign` requires `realm_id` for Realm-owned blobs;
  reducer cross-checks against blob metadata.
- **BREAKING** `ak.space.archive` / `restore` / `tombstone` accept the new
  `space_state_transition_payload` / `space_object_tombstone_payload`
  shapes; removed top-level `target_ref` rejects as `schema_violation`.
- **BREAKING** `ConsentRevoke` reducer requires `observed_dots[]`; implicit
  cascade rejects as `schema_violation`.
- **BREAKING** `ak.strand.update` / `ak.strand.tracks_patch` reducer uses
  CAS-register semantics on cell-subject `strand_id` (bottom=reject; empty
  field-set rejects).
- **Added** Late key recovery path emits
  `ak.audit.policy_access{access_kind=e2ee_late_recovery,
  late_recovery_original_event_id}`.
- **BREAKING** `agent_id` and `applet_id` MUST be DID-shaped (applet also
  accepts `ak:applet:<uuidv7>`); non-DID values reject.
- **Added** DID method-name regex sweep tightened to
  `^did:[a-z0-9]+:[^\s]+$` across all parsers and fixtures.

### Round R2/R3 (2026-05-20; arkret-spec `8b7978d`) — 17 wire-breaking tasks

Aggressive mode — there is no compatibility shim for any of the changes
below. Producers on the old wire MUST upgrade.

#### Added

- **`crate::round23` module** — consolidated reducer/validation helpers
  for every Round R2/R3 normative requirement (T01–T23).
- **`AppConfig.trust_domain`** field plumbed from `COLAND_TRUST_DOMAIN`
  env var (default derived from `service_id`). Required by the
  the now-removed legacy device-hierarchy reset replay defence (T08).
- **13 new `ErrorCode` variants** mirroring the new spec registry:
  `RelaxedWindowExceedsCeiling`, `E2eeRelaxedDisallowedInComplianceProfile`,
  `CrossDomainReplayRejected`, `ResetEventIdMismatch`, `RealmTerminalState`,
  `AuditAgentAttestationMismatch`,
  `AuditPurposeMismatch`, `LegalHoldActive`, `BlobRedacted`,
  `MediaPlaintextServiceNotAuthorised`, `MlsGovernanceBindingStale`,
  `ExpiredInviteToken`, `LateRecoveryRejectedMembership`.
- **Account deactivation fanout projection** (`DeactivationFanoutProjection`)
  tracking the 7 fanout domains with `outcome=partially_completed` when
  some succeed and some fail (T07).
- **Late key recovery state machine** (`LateRecoveryState`) with the
  4-condition accept gate (membership / policy / key-share-origin /
  audit-emit-queued) and `late_recovery_rejected_membership` reject for
  revoked actors (T16).
- **Federation idempotency service-key binding** persisted on transaction
  records (`origin_key_state_digest`, `local_peer_policy_digest`) +
  `historical_only=true` marker for post-key-revoke replays (T14).
- **Identity_link cache `policy_frontier_digest`** helper +
  `IdentityLinkInvalidationTrigger` enum for the five eager-invalidation
  classes (T13).
- **Consent revoke `scope=any` cascade** table + 5-channel cache
  invalidation list (T17).

#### Changed (wire-breaking)

- **`POST /api/v1/events` ephemeral kind reject** — the 12 ephemeral
  kinds (`ak.call.signal`, `ak.presence`, `ak.typing`, `ak.receipt.read`,
  `ak.key.verification.*`) hard-reject with `schema_violation`. Senders
  MUST switch to `ak.schema.ephemeral_envelope.v1` (broadcast forms)
  or `ak.schema.device_message.v1` (to-device key verification) (T02).
- **`POST /api/v1/events` receipt-object reject** — `ak.event_batch_receipt`
  hard-rejects as Event.kind; it is a receipt object only (T23).
- **`POST /api/v1/events` terminal Realm reject** — any non-audit-class
  event on a Realm whose `ak.realm.destroy` has been applied returns
  `realm_terminal_state` (409) (T07).
- **REMOVED LEGACY device-hierarchy reset payload** — `trust_domain` and
  `reset_event_id` are now required wire fields. Verification order is
  `cross_domain_replay_rejected` → `reset_event_id_mismatch` →
  `signature_invalid` (T08).
- **`ak.realm.policy_bundle` reducer** — `relaxed_window_max_ms`
  hard-rejects above 300 000 ms (`relaxed_window_exceeds_ceiling`);
  `ak.profile.e2ee_relaxed.v1` is mutually exclusive with the audit
  compliance profiles (`e2ee_relaxed_disallowed_in_compliance_profile`);
  `media_service_decrypts=true` requires the triple binding
  (policy_bundle ∧ plaintext_visible_services ∧ MLS governance
  policy_root) or surfaces `media_plaintext_service_not_authorised` /
  `mls_governance_binding_stale` (T09 + T12).
- **`POST /api/v1/seals` frontier validation** — every entry in
  `Seal.frontier[]` MUST match `sha256:<64 lowercase hex>`; the removed
  `ak:event:<uuid>` form hard-rejects (T04).
- **`GET /api/v1/blob/get` fail-closed gates** — E2EE, legal-hold,
  redacted, and actor_private blobs return the registered error code
  rather than a presign URL. Responses now carry
  `Cache-Control: private, no-store` and `Referrer-Policy: no-referrer`;
  presign URL query strings are scrubbed from tracing/logs (T11).
- **Federation idempotency cache hit** re-runs the capability check
  (origin DID validity + destination match) before serving the cached
  response — protects against replays after peer key revocation (T14).
- **Cursor handle minimum length** raised from 16 → 22 base64url
  characters (≥128-bit entropy); shorter handles reject as
  `cursor_integrity_invalid` (T03).
- **`ak.audit.ryw_receipt`** is durable-event-eligible only when
  `ak.profile.attested_audit.e2ee.v1` is active in the Realm profile
  set (T23).

#### Migration

- Operators MUST set `COLAND_TRUST_DOMAIN` (or rely on the
  `service_id`-derived default) before processing the removed legacy reset
  events. The boot path validates the value via the SDK
  `TrustDomainId` regex.
- Producers MUST move ephemeral kinds off `ak.self.events.command.submit.v1`; the
  endpoint no longer accepts them under any compatibility flag.
- Producers MUST add `trust_domain` and `reset_event_id` to every
  removed legacy reset payload (matching the enclosing
  `Event.event_id`).
