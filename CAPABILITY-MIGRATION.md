# Authority-Commit Capability Migration

This checklist separates protocol replacement from product removal. A product
capability stays present unless its specification was explicitly removed. A
module may be deleted only when every responsibility in it belongs exclusively
to the superseded distributed-consistency mechanism.

A box is checked only when the implementation path and the test that proves it
are both named on the line. "Wired" means reachable from a crate root: a file
that no `mod` declaration reaches is orphaned, not migrated, and its capability
counts as absent.

## Orphaned modules

Measured by enumerating `src/**/*.rs` per crate and subtracting the set reachable
from the crate root along `mod` declarations, including `#[path]` targets
(`cargo bin` targets excluded, since Cargo reaches those without a `mod`).

**Resolved 2026-09-18/19.** The 2026-09-16 measurement found 15 files and judged
every one of them "Rewire — the capability is in the specification". That
judgement was made from the file names. Checking each module against the SDK and
against the rest of the tree reverses it: in every case the capability **had
already been migrated into a different file**, and the orphan is the
pre-migration copy that was left on disk when its `mod` line went away. The
count was also understated — the reachability scan used was not transitive, so
the children of an orphaned parent were wrongly counted as reachable. A
transitive closure gives 25 files, not 15.

| commit | what went | files | lines |
|---|---|---|---|
| `147630d33` | `timeline_order` + the two ordering tables | 2 | 1,616 |
| `0f81aea25` / `fa20b0cd9` | `sync_cursor/current_detail` + tests | 2 | 659 |
| `0ed83faac` | the ten remaining old-mechanism groups | 23 | 7,308 |

What remains orphaned:

| crate | orphan files | lines |
|---|---|---|
| `coland-http` | 1 | 323 |
| all others | 0 | 0 |

The one survivor is `http/routing/authority_commit.rs` (323 lines), and it is
the only entry from the 09-16 table whose "Rewire" verdict stands: it *is* the
current-protocol route file. It needs `mod authority_commit;` plus a
`router_build.rs` entry, and wiring it means simultaneously removing the eleven
`/_arkret/self/seals/*` routes that are still serving. That switches the runtime
protocol face and moves every wire assertion in cotest, so it is held for a
separate round. **Until then the authority-commit HTTP surface does not exist at
runtime.**

### Why each deleted group was not a rewire

Each line names the successor that already carries the capability.

| group | lines | successor already in the tree |
|---|---|---|
| `current_data` (5 files) | 1,813 | `RealmStateSnapshot.current_state_entries: Vec<TypedCurrentRow>` (SDK `wire/src/authority_commit.rs:479`). The orphan imports `arkret_wire::cbs::{ProjectedCellWrite, ProjectedOp}`, which the SDK no longer defines, and resolves conflicts by "greater causal depth wins". |
| `current_results` (2) | 345 | `sync_cursor.rs:168-256`, where `current_detail_page` is already rewired. `CurrentResultEntry` is gone from the SDK. |
| `mls_public_state` (4) | 1,560 | `MlsStateInstallation`, which is **coland's own** type at `crates/storage/src/authority_commit.rs:53`, carried by `AuthorityCommitTransaction.mls_state` (`:48`). It has zero hits in the SDK; an earlier draft of this table cited `wire/src/authority_commit.rs:355-390` for it, which is `RealmAuthorityBundle`. `EventCommitRequest` no longer carries `mls_public_genesis` / `mls_public_producer`. |
| `devices/confirmed_history` (2) | 707 | `devices.rs`, which writes `devices.verification_state` directly. The orphan's input type `ConfirmedDeviceControlProjection` was deleted from the trait crate in `c30ce6384`. |
| `device_revocations/historical` (2) | 406 | nothing needed: it read `EventCommitRequest.historical_producer`, a field the protocol removed. |
| `device_revocations/material_cleanup` (1) | 66 | `device_revocations.rs:256-300`, where both methods were rewritten from `covering_seal_id` to `committed_ref`. |
| `principal_resolution/{current,genesis}` (4) | 762 | `principal_resolution.rs:131-143`, live caller at `post_commit.rs:235`. |
| `events/approval_publications` (1) | 458 | `publication_evidence.rs:55`. |
| `events/recovery_terminal_tests` (1) | 1,116 | `validate_recovery_commit_pair` — see the pair rule below. |
| `events/transaction_locks` (1) | 75 | the three `FOR UPDATE` sites in `authority_commit.rs:149,199/273,305`. |

### Two capabilities with a declared surface and no implementation (2026-09-19)

Both were found while unwinding the timeline and ack residue in
`coland-storage` / `coland-services`, and neither is residue: each is a
current-protocol surface that is declared and never implemented.

1. **`AuthorityProtocolPort` has no production implementation.** The trait is
   declared at `services/src/authority_commit.rs:135`, and its only `impl` in
   the entire workspace is the test stub `NeverCalled` at
   `http/src/routing/authority_commit.rs:245`. The eleven routes in that file
   pull the port out of the Depot, so `POST /_arkret/self/streams/scan` has no
   backend at all. The storage-side half now exists --
   `AuthorityCommitApplication::scan_stream`, validating `StreamScanRequest` in
   and `StreamScanOutcome` out -- but the signing Station half does not.
2. **The three batch-commit units are cut in the middle.** `EventStore` no
   longer declares `put_realm_bootstrap_batch_atomic`,
   `put_direct_conversation_founding_batch_atomic` or
   `put_identity_anchor_batch_atomic` (0 hits in `crates/storage`), while
   `services` still calls each of them once. These are Realm genesis, Direct
   Conversation founding and the identity anchor unit: three product paths, not
   protocol plumbing. Their successor has to be
   `AuthorityCommitStore::commit_transaction`, which needs someone to sign the
   `RealmCommit` -- the same missing Station as above.

Two contract tests are in a related state and were deliberately **not** deleted,
because deleting them would be trading coverage for a green build:

- `assert_consent_projection_commit_contract` rests on the removed cell model
  (`ConsentCellStore` / `ConsentCellRecord` / `arkret_identifiers::CellRef`).
  The capability does have a successor -- `ConsentGrantStore`
  (`storage/src/contacts.rs:353`), `ConsentGrantRecord` and
  `ConsentProjectionCommit.grant` -- so the test needs rewriting onto the grant
  model, not removing.
- Device-revocation settlement now travels as
  `DeviceRevocationTransition.revoke_ref: CommittedEventRef`
  (`storage/src/device_revocations.rs:41`) instead of a covering Seal plus a
  `ControlProposalAck`. That path currently has no contract test at all.

### Two things that must not vanish with the files

1. **The MLS public-genesis lane is residue, but only its columns are - the
   lane itself is still half-wired and will not compile.**
   `coland_storage::MlsPublicGenesisRecord`
   (`crates/storage/src/mls_public_state.rs:14-21`) carries
   `producer_signing_key` and `producer_device_authorization` beside the full
   `source_event` envelope. Those two are a denormalised cache: the accepted
   Event is producer-signed (`zh/crypto-media/encryption-and-audit.md` §5.1) and
   the specification puts the frozen producer key in the Event's own portable
   provenance, not in a server-side projection (`zh/identity/key-management.md`
   L288: verify the historical producer proof with the `producer_signing_key_did`
   frozen in it, never by re-resolving current controller device state). Neither
   column name occurs anywhere under `spec/v1` at all, machine-readable artifacts
   included -- note the artifacts live at `spec/v1/artifacts/{schemas,registry}/`,
   not at `spec/v1/schemas`.
   Deleting the postgres half was therefore correct, and the successor is
   `MlsStateInstallation` (`crates/storage/src/authority_commit.rs:53`, a
   coland type, not an SDK one).
   What is *not* done is the rest of the lane, which still names input fields
   that `EventCommitRequest` (`crates/storage/src/unit_of_work.rs:84-103`) no
   longer has:
   - `services/src/events.rs:765` `EventCommitCommand.mls_public_genesis` and
     `services/src/persistence_events.rs:92` forwarding it;
   - `services/src/events.rs:1681` the `public_genesis_candidate` trait method
     and its `persistence_events.rs:718-727` body, which calls a
     `mls_commits().public_genesis_candidate` that no storage trait declares;
   - `http/.../submit/commit_prepare.rs:126,286`,
     `submit/ghost_provision.rs:379`, `submit/sidecar_ensure.rs:158`;
   - `storage/src/contract_tests.rs`, five fixtures setting both fields.
   These are compile errors today, not working code.
2. **Eight tables are now permanently empty.** `current_result_versions`,
   `current_result_heads`, `current_data_*` (4), `current_selector_origins`,
   `agent_approval_publications`, `device_history_projections`,
   `mls_public_genesis_states` and `mls_public_commit_states` have no writer
   left. They cannot simply be dropped from `up.sql` and `schema.rs`: two live
   sites still name them — `sync_cursor/retention.rs:185` sweeps
   `current_result_versions`, and
   `test-support/tests/account_device_control_storage.rs:180,315` still asserts
   `device_history_projections` reaches 1. That last assertion is the one that
   matters: it asserts a product behaviour, so it has to be re-pointed at
   `devices.verification_state` rather than deleted.

### Recovery completion is two commits, never one

`RecoveryTransaction` completion is **two consecutive `CommittedEventRef`s on
the same PCR Realm stream**. Because one `RealmCommit` carries exactly one
`event_ref`, those two references necessarily name **two different commits**:
same `stream_ref`, which must be `CommitStreamRef::Realm`; `stream_position`
differing by exactly 1; `commit_id` different; `event_id` different. The
authoritative implementation is `validate_recovery_commit_pair` in
`../arkret-rust-sdk/crates/wire/src/recovery_authority.rs`. Any local code that
reads the two positions out of a *single* commit fails closed forever and is a
bug, not a shortcut. As of this writing coland contains no such implementation;
`http/routing/identity/recovery/security_transaction_endpoints.rs` still builds
the attestation from the retired `terminal_commit_digest`,
`device_authorization_event_id` and `first_generation_seal_id` fields and has
to be rewritten onto `reanchor_event_ref` / `device_authorization_event_ref`.

### Relation current value is stream order, never causal depth

A relation's current value is the typed current result produced by the **last
accepted `ak.relation.resolve` on that relation's stream**, ordered by the
Station's `stream_position`, with concurrency resolved by an `expected_revision`
CAS. There is no "greater causal depth wins" rule and no causal-register join.
Verified 2026-09-16: `crates/domain/src/reducer/` contains no `(depth, EventId)`
comparison — every remaining `depth` in the reducer is capability delegation
`max_authority_depth`, an unrelated product concept. The only surviving causal
ordering is `timeline_order.rs` and the `realm_timeline_order` table above.

## Protocol invariants

- [x] Producer `Event` carries no predecessor or local ordering metadata.
  `crates/domain/src/reducer.rs` projects `StreamRow` only;
  `crates/storage/src/authority_commit.rs::AuthorityCommitTransaction::validate`
  rejects a commit whose stream disagrees with the Event scope.
- [x] Realm, Circle, and Sidecar each use an independent `CommitStreamRef`.
  `realm_commits.stream_key` is the serialized `CommitStreamRef`, and
  `realm_commits_position_key UNIQUE (stream_key, stream_position)` makes a
  global position unrepresentable
  (`crates/storage-postgres/migrations/00000000000000_initial/up.sql`).
- [x] Only the current governance Station appends `RealmCommit`.
  `crates/storage-postgres/src/authority_commit.rs::commit_transaction_in_connection`
  compares the commit signature's controller against `realm_authorities.service_id`
  under the same row lock.
- [x] Persistence rejects a stale authority generation under the same row lock
  used to inspect and advance a stream tail. `locked_authority` takes
  `realm_authorities … FOR UPDATE` before the tail `SELECT … FOR UPDATE`, and a
  generation mismatch returns `AuthorityCommitWriteOutcome::StaleAuthority`.
- [x] Accepted MLS state and recipient Welcome deliveries share the Event commit
  transaction. `mls_group_states` and `mls_welcome_deliveries` are written
  inside `commit_transaction_in_connection`.
- [x] Authority handoff binds a snapshot and the complete sorted set of stream
  heads. `PgAuthorityCommitStore::install_handoff`.
- [ ] Join/bootstrap serves the verified current authority bundle, snapshot, and
  every independent stream tail. The storage side exists
  (`AuthorityCommitStore::{authority_handoffs, latest_snapshot, realm_stream_heads}`),
  but no service or route assembles them: `crates/services/src/sync.rs` still
  imports the removed SDK type
  `governance::realm_join_bootstrap::RealmJoinBootstrapAssembly`, and
  `crates/http/src/routing/authority_commit.rs` is not declared by any `mod`,
  so the authority-commit HTTP surface is unreachable.

## Product capabilities to preserve and migrate

Every item below needs its projection and storage code to consume accepted
`StreamRow`/`CommittedEventRef` inputs, never producer-Event order or a
peer-merge graph.

- [x] Accepted-Event durable boundary. `crates/storage-postgres/src/unit_of_work.rs`
  installs the queued Event, its `RealmCommit`, device-pairing CAS,
  device-revocation gate and target, Contact and consent projections, Contact
  completion intent, projection rows, federation outbox rows, and the
  idempotency reservation in one `conn.transaction`. Batch-level Applet
  installation, Applet authoring preview, Agent membership cascade, and
  moderation franking-nonce effects commit in that same transaction.
- [~] Account lifecycle, sessions, account data, and contacts. Storage is wired
  and `crates/services/src/identity.rs` now compiles: consent grants are
  addressed by `ConsentId`, account status reads come from
  `arkret_models_collaboration::account_status`, and the §6.1 counterparty
  comparison survives as exact `ConsentPeer` equality. The HTTP surface is
  still unverified because `coland-services` (lib) does not build.
- [~] DID, service identity, device inventory, pairing, and revocation. Storage
  is wired and the `DeviceRevocationStore` delegation now matches the
  single-transaction trait (`target_for_event`, `commit_revocation`). Agent
  runtime activation is gated on the authorize Event's `CommittedEventRef` plus
  its `AgentLifecycleState` instead of a `SealBasis` and an
  `AwaitingAcceptedFrontier` state. `crates/http/src/routing/identity/agents/
  pairing.rs` still carries the retired activation model and is unverified,
  because `coland-http` is never reached by `cargo check`.
- [~] Realm lifecycle, organization ownership, policy, and directory reads.
  `crates/domain/src/reducer/apply_realm_*.rs` are wired and compile; their
  tests are not ported yet.
- [~] Invitations, join policy, history-access policy, and join bootstrap.
  `apply_invites.rs` and `apply_history_access.rs` are wired and compile. Join
  bootstrap itself is still missing its assembler (see the unchecked invariant
  above).
- [~] Circles, Sidecars, Spaces, Strands, Morphs, and applet integration.
  `crates/domain/src/reducer/apply_objects/` is wired and compiles. The Sidecar
  projection no longer carries an encryption profile; a Sidecar scope activates
  RFC 9420 through its own accepted `ak.mls.genesis`.
- [~] Messages, moderation, notifications, push, Signals, and WebSocket sync.
  `apply_messages.rs` and `apply_moderation.rs` are wired and compile.
  `crates/storage-postgres/src/timeline_order.rs` ordered by producer causal
  depth and was deleted in `147630d33` together with the `realm_timeline_order`
  and `realm_timeline_pending_edges` tables. Message paging still has to be
  rebuilt as a keyset over `realm_commits.stream_position` on one
  `CommitStreamRef`; the storage half is gone, the trait and service halves are
  not yet written.
- [ ] Blob upload/download and object storage.
- [ ] MLS key packages, commits, installed state, and Welcome delivery. The
  commit/Welcome transaction exists and `crates/domain/src/reducer/mls.rs` is
  wired, but `apply_keypackage_claim` was deleted without a replacement: the
  KeyPackage compare-and-swap claim is a ledger projection, not an Event
  reducer, and `MlsEffect::KeyPackageClaimed` plus its tests still reference
  the removed function. `crates/storage-postgres/src/mls_public_state.rs`
  was deleted in `0ed83faac`: it read `EventCommitRequest.mls_public_genesis` /
  `mls_public_producer`, fields the protocol removed, and `MlsStateInstallation`
  is its successor. The one thing it carried that `MlsStateInstallation` does
  not is the producer-device binding recorded above. Proposals are inlined into the Commit, so
  `apply_remove_proposal` is correctly gone; Welcome is a producer-signed
  `MlsWelcomeDelivery`, so `apply_welcome_enqueue` is correctly gone.
- [~] Key backup, recovery sessions, and security transactions.
  `apply_key_backup.rs` is wired and compiles. Recovery completion still has to
  move onto the two-distinct-commits pair rule stated above.
- [ ] Federation delivery needed to reach a Realm's current Station.
- [ ] Administration, health, metrics, configuration, and runtime startup.

## Removed protocol-only surfaces

- [x] Cell/Seal state join and Seal construction helpers: replaced by Station
  admission followed by an authority-signed stream commit.
- [ ] ~~CBS/conformance basis fixtures: they existed only to synthesize Seal
  authority.~~ **The premise is wrong and this box was ticked in error**
  (corrected 2026-09-18). `arkret_wire::cbs` was never a fixture module. It is
  the Cell-write projection data model, and it is load-bearing in this
  repository right now: `ProjectedCellWrite`, `ProjectedOp`, `LatticeOpType`,
  `LatticeOp`, `ProjectionEffect`. The live consumers are the accepted operation
  projection pipeline (`http/src/routing/events/projection/apply.rs`), the
  governance proof builder and the submit value path -- product capability, none
  of it Seal synthesis.
  **Second correction, 2026-09-19**: the file-and-reference counts first written
  here (19 files, 49 references, including `storage-postgres` (1)) counted
  orphans as live. The storage-postgres consumer was
  `storage-postgres/src/current_data.rs`, which reached no crate root and has
  since been deleted in `0ed83faac`; the live storage-postgres count is 0, and
  "the postgres `current_data` writer" was never a live consumer. Re-measure
  against the transitive `mod` closure, not against `grep -rl`.
  The module is gone from the SDK (`crates/wire/src/lib.rs` has no `pub mod
  cbs`; `ProjectedCellWrite` / `ProjectedOp` / `LatticeOp` have zero hits
  anywhere in the SDK). Its successors are `arkret_wire::patch::Patch` plus
  `arkret_models_collaboration`'s `TypedCurrentRow`, which have a **different
  shape**, so this is a port, not a deletion. The four compile errors the
  triage counted are only the ones Cargo reaches before it aborts at
  `coland-services`; they are not the size of the job.
- [x] HLC and producer causal predecessor handling: ordering now belongs to the
  selected independent commit stream.
- [x] Peer frontier exchange/reduction and Move/Seal federation: a Realm has one
  current write authority.
- [x] Network history-key request/response and RHRK acquisition: join and catch-up
  use current-authority snapshot plus stream tails.
- [x] Governance-history streaming endpoints: exact committed references and
  bounded stream scans replace that network surface.
- [x] Seal preparation, notary scheduling, Bottom handling, and Seal GC: these
  jobs have no object to produce in the authority-commit protocol.
- [x] Two-phase pending-domain-effect staging
  (`unit_of_work/domain_effects.rs`): it existed only to replay Contact and
  consent intents at a later Seal decision. The Station now admits and commits
  in one transaction, so the effects are applied directly.
- [x] Control-proposal authority ack lane (landed 2026-09-18, `fa20b0cd9`):
  `POST /_arkret/self/control-proposal-acks` and the two
  `control-proposal-decisions` routes, `MaintenancePort`'s two ack methods,
  `SyncStoreRegistry::control_proposal_authority_acks`, the
  `PgControlProposalAuthorityAckStore` contract test, the
  `control_proposal_authority_acks` table and its `diesel::table!` block. Every
  upstream link was already deleted before this, so the routes were serving a
  store trait that no longer existed; there was no product capability behind
  the lane to preserve. Note that `schema.rs`'s
  `control_proposal_ack -> Nullable<Jsonb>` column is a **different thing** --
  it is on the ingress side and is entangled with the projection seam, so it
  stays until `projection.rs` is ported.
- [~] The `coland-http` ingress ack lane (measured 2026-09-19). The two modules
  it is built on, `crate::notary` and `crate::control_proposal`, **no longer
  exist as files**: `find src -path '*notary*' -o -path '*control_proposal*'`
  returns nothing. "Notary" also has **zero hits in the whole of
  `arkret-spec/spec/v1/zh`**, and `authz/cbs-profiles.md`, cited by name in
  `submit/control_ack.rs`, is not in the tree either. So every `crate::notary::`
  and `crate::control_proposal::` path in this crate resolves to nothing; these
  are not calls that need porting, they are calls into a deleted mechanism.
  Fifteen files still contain them:

  | file | refs | status |
  |---|---|---|
  | `event_log/governance_proof.rs` | 11 | **held** -- also carries the Seal-frontier question under ruling |
  | `event_log/submit/control_ack.rs` | 8 | delete whole (211 lines); it is the lane's entry point |
  | `event_log/endpoints.rs` | 5 | **held** -- same ruling |
  | `event_log/submit/identity_anchor.rs` | 4 | unwind |
  | `event_log/submit/ghost_provision.rs` | 4 | unwind |
  | `identity/agent_pcr.rs` | 3 | unwind |
  | `identity/recovery/security_transaction_endpoints.rs` | 2 | unwind |
  | `spaces/directory/realm_resolution.rs`, `interop/moderation.rs`, `interop/mimi/payload.rs`, `identity/account/social/contact_write.rs`, `identity/account.rs`, `event_log/submit/value.rs`, `event_log/submit/realm_bootstrap.rs`, `conformance/handlers.rs` | 1 each | unwind |

  `arkret_wire::ControlProposalAck`, `ControlProposalAckKind`,
  `ControlProposalDecisionCommitOutcome` and `SealBasis` likewise have **zero
  hits in the SDK**, so the types threaded through
  `submit.rs`, `commit_prepare.rs`, `post_commit.rs`, `value.rs`,
  `identity_anchor.rs`, `agent_membership_cascade.rs`, `state/app_state.rs` and
  `conformance/realm_fixture.rs` have no definition either. The receiver-minted
  Ack has no successor object: in the authority-commit protocol an admitted
  Control Move is evidenced by the accepted Event plus its signed `RealmCommit`,
  and nothing else is issued.
  This is marked `[~]` and not `[x]` because two of the fifteen files are held
  behind the open Seal-frontier ruling, so the lane cannot be closed in one
  pass.

  **The successors are known; the wiring is not there.** Two distinct uses hide
  behind "notary", and only one of them needs a ruling:

  1. `NotaryWorker::current_notary_value_for_events(state, &realm, &[])` is
     "who is this Realm's current authority". The successor is live end to end
     already: `storage/src/authority_commit.rs:121 current_authority` ->
     `services/src/authority_commit.rs:69` -> `storage-postgres/src/authority_commit.rs:453`,
     reading `realm_authorities`. The SDK even renamed the user-visible symptom:
     `DirectConversationSendBlocker::NotaryUnavailable` is gone and
     `CurrentAuthorityUnavailable` is in its place
     (`models-collaboration/src/direct_conversation.rs:29-42`). So
     `identity/account.rs:1887`, `spaces/directory/realm_resolution.rs:803`,
     `conformance/handlers.rs:439` and `submit/value.rs:1296` are ports with a
     named target, not open questions.
     **What blocks them is that `AppState` cannot reach that service.** It has
     `notary_signing_key`, `notary_verifying_key` and `notary_signing_key_origin`
     baked into it and no authority-commit accessor at all; `current_authority`
     has zero call sites in the whole of `coland-http`. This is the same
     unwired seam as the orphaned `routing/authority_commit.rs`, so the ack
     unwind and the route wiring have to land together.
  2. `crate::notary::ensure_realm_seal_head(state, &realm)` is the Seal frontier,
     used by `interop/moderation.rs:147`, `interop/mimi/payload.rs:64` and
     `identity/account/social/contact_write.rs:709`. Those three join
     `governance_proof.rs` and `event_log/endpoints.rs` behind the open ruling,
     bringing the held count to five of fifteen.

  `submit/realm_bootstrap.rs:315` (`mint_control_proposal_acks`) is neither: it
  mints the retired object and is a straight delete.
- [~] The six SDK modules `coland-http` still imports that no longer exist
  (measured 2026-09-19 by extracting every `arkret_*::<module>` path in
  `crates/http/src` and testing each against the SDK tree). 148 references in
  total. **Four of the six are ports with a named target; only the lease family
  is genuinely blocked.**

  | missing module | http files / refs | verdict |
  |---|---|---|
  | `arkret_models_collaboration::governance_dependencies` | 19 / 36 | **port, but not the one it looks like.** See the note below: the evidence type survives, the lookup-by-digest store does not. |
  | `arkret_wire::cbs` | 12 / 40 | **port.** Successors are `arkret_wire::patch::Patch` and `TypedCurrentRow`, different shape. |
  | `arkret_wire::cbs_proof_bundle` | 10 / 31 | **delete.** The SDK ledger adjudicates `EventFederationSubmission` and `CbsProofBundle` as removed: "CBS is a removed unit". |
  | `arkret_models_collaboration::direct_conversation_ops` | 8 / 19 | **mixed.** `DirectConversationFoundingAuthorityEvidence` (11 refs) is a port onto `models-collaboration/src/objects/direct_conversation.rs:330` -- another stale SDK gap line, corrected in `bbca85ef`. `DirectConversationFoundingFederationSubmission` (2) goes with CBS. `DirectConversationFoundingPlan` (2) has zero hits in the SDK and zero `founding_plan` hits in `direct-conversation-operations.schema.json`; it is a local name with no protocol object. |
  | `arkret_models_collaboration::history_key` | 6 / 13 | **delete, except one.** RHRK is an adjudicated removal. `DirectorySourceRefAccess` only moved house, to `arkret_models_discovery::directory`. |
  | `arkret_wire::offline_publication` | 5 / 9 | **blocked.** `AuthorizationLease` and `IngressReceipt` are still normative (`zh/overview/glossary.md`, `zh/identity/security-transactions.md` L213) and the SDK ledger still carries them as an open gap; `AuthoritySetRef`, `LeaseBasisRef` and `RiskTier` have zero SDK hits too. coland cannot close these without the SDK, and must not hand-roll them locally. |

  The lesson for the next pass: two of the four ports read as "blocked on the
  SDK" only because the SDK's own gap ledger had gone stale, in both cases
  because the type had landed under a path the gap line did not name. Check the
  SDK tree, not the SDK ledger.

  **`governance_dependencies` in detail, because it has two halves and only one
  of them is an import problem.**
  The payload type survives: `arkret_models_identity::AuthenticatedSignerResolutionEvidence`
  (`models-identity/src/authenticated_signer_resolution_evidence.rs:58`, exported
  at `lib.rs:19,50`), and `submit/device_gate.rs:44-47` already matches on it
  directly. The SDK gap ledger listed it as open only because it looked under
  `models-collaboration`; corrected upstream in `acdc61a5`.
  What does **not** survive is the *lookup*. `GovernanceDependencySelector` plus
  `state.persistence().governance_dependency_store().get_unscoped_signer_evidence(&selector)`
  is a side table keyed by content digest. Its coland half was deleted
  deliberately, not by accident: `c30ce6384` removed
  `crates/storage/src/governance_history.rs`, which defined
  `GovernanceDependencyWrite`, and `coland_storage::GovernanceDependencyWrite`
  now has no definition anywhere while `services/src/{events,persistence_events,projection}.rs`
  still name it in eleven signatures.
  The successor is stated by the SDK itself, at
  `authenticated_signer_resolution_evidence.rs:105-115`: every input to
  `build_signer_resolution_evidence` is supplied by the caller, the helper
  "reads no clock, holds no key and consults no service, so the same inputs
  always produce the same bytes and therefore the same `SignerEvidenceRef`", and
  "a resolving Station calls it after it has already resolved the key against
  `authority_commit_id`; the evidence records that resolution, it does not
  perform one." So a receiver no longer looks evidence up by digest: it resolves
  the key against the proof's `authority_commit_id`, rebuilds the evidence and
  compares with `matches_ref` (`:99`). The digest-keyed store is the old
  mechanism, and the eleven `GovernanceDependencyWrite` signatures in services
  are residue of it.
  Signer evidence that legitimately remains *stored* is the Agent-scoped kind
  (`storage/src/agents.rs:48-49`, `agent_principal.rs:55-58`), which is a
  different thing: current evidence for a live Agent, not a historical lookup
  table.
- [x] Audited-E2EE compliance profiles: `ak.profile.attested_audit_e2ee.v1` and
  `ak.profile.disclosed_audit_e2ee.v1` are gone from the specification and the
  SDK, so `AUDIT_COMPLIANCE_PROFILES` is removed from
  `crates/domain/src/kinds.rs` and `crates/services/src/operation_semantics.rs`.

### The checkboxes above are about code, not about what is mounted

Measured 2026-09-17 by following `mod` declarations from `coland-http`'s crate
root. The Seal surface is still **served**. `router_build.rs:335`
(`arkret_protocol_router`) pushes `events::router()` under `self` and
`events::peer_router()` under `peer`; `events/mod.rs:6` declares `mod event_log`;
`event_log.rs:176` re-exports `endpoints::router`; and
`event_log/endpoints.rs:255-269` registers:

| live route | handler |
|---|---|
| `POST /_arkret/self/seals` | `submit_event_seal` |
| `QUERY /_arkret/self/seals/frontier` | `seals_frontier` |
| `QUERY /_arkret/self/seals/pending-control` | `pcr_pending_control` |
| `POST /_arkret/self/seals/prepare` | `prepare_pcr_seal` |
| `POST /_arkret/self/seals/prepare-fence-result` | `prepare_pcr_seal_fence_result` |
| `POST /_arkret/self/seals/mls-governance-proof` | `governance_proof::mls_governance_proof` |
| `POST /_arkret/self/seals/mls-accepted-artifact` | `mls_accepted_artifact::read` |
| `POST /_arkret/self/seals/mls-welcome-refs` | `mls_welcome_refs::read` |
| `POST /_arkret/self/seals/history-authority` | `history_authority::read` |
| `QUERY /_arkret/peer/seals/frontier` | `peer.rs:179 peer_seals_frontier` |
| `QUERY /_arkret/self/events/frontier` | `events_frontier` |

2026-09-21 update: the `seals/history-authority` row above is a historical
measurement, not a current route. Decision 0055 and the formal
`governance/history-visibility.md` §3.1 retire this independent Seal/CellRef
history oracle. Current history discovery, stream scan and readable-floor
authorization remain separate registered surfaces.
The two `seals/mls-*` read rows are historical as well: the current
`sync/client-sync.md` §10.0 retires those Seal queries while retaining the
producer-signed Welcome recipient queue, retry, account delivery and ACK.
The `seals/pending-control`, `seals/prepare`, `seals/prepare-fence-result` and
`seals` command rows are likewise retired by `sync/service-http-binding.md`:
device revocation pending state remains a durable proposal/RealmCommit result
fold, not a Seal or Notary query result.

Meanwhile `routing/authority_commit.rs` — which declares `self/events`,
`self/streams/scan`, `peer/streams/resolve`, `peer/realm-authority/handoff` and
`open/realm-authority/bundle` — has no `mod` declaration anywhere and is not
compiled. A grep confirms `streams/scan`, `streams/resolve`,
`realm-authority/handoff` and `realm-authority/bundle` appear nowhere else in
the crate, so those four paths do not exist at runtime at all.

**So the deployed protocol surface is still the removed one, and its replacement
is the file nobody compiles.** The `[x]` marks above are honest about the
mechanisms being deleted from the specification; they are not evidence about
this crate.

Two things follow that are easy to get wrong:

- `authority_commit.rs` carries its own `#[cfg(test)]` block, including
  `current_routes_are_registered_without_a_legacy_recovery_surface` and
  `every_current_route_rejects_an_invalid_sdk_body_before_delegating`. Neither
  has ever run: an unreachable module's tests are not compiled, so they are not
  reported as skipped either. Do not read those test names as coverage.
- Identifier counts for this crate, for scale rather than as a work estimate:
  535 `Seal`-family occurrences, 585 `frontier`, 114 `cell_writes`, 112
  `CellRef` in `crates/http/src` alone. These were checked by hand against
  ordinary English — there is no plain-English "seal" in the sample; every hit
  is a protocol identifier (`seal_basis` 127, `seal_id` 69, `SealId` 54,
  `seal_ref` 49, `SealBasis` 23, `covering_seal_id` 16, and so on).

Wiring `mod authority_commit;` on its own would therefore mount the new surface
*beside* the old one rather than replacing it. The two have to move together.

## Mixed modules that must be split, not deleted

- [x] Event admission and atomic unit-of-work code. Rebuilt in
  `crates/storage-postgres/src/unit_of_work.rs`; the shared
  `*_in_connection` entry points are
  `authority_commit::{queue_event_in_connection, commit_transaction_in_connection}`,
  `projection::append_projection_batch_in_connection`,
  `federation::enqueue_federation_outbox_in_connection`,
  `idempotency::record_idempotency_in_connection`, and
  `device_revocations::commit_revocation_in_connection`.
- [x] Projection/current-result materialization. `current_data.rs`,
  `current_results.rs` and `timeline_order.rs` were the pre-migration copies and
  are deleted (`147630d33`, `0ed83faac`); the live path is
  `RealmStateSnapshot.current_state_entries` plus the already-rewired
  `sync_cursor.rs:168-256`. `state_resolution/` no longer exists.
- [ ] Federation delivery and outbox code. The outbox is atomic with the commit;
  `federation.rs` still carries frontier-exchange functions that have no
  protocol object to produce.
- [ ] Sync cursor and notification delivery code.
- [ ] Server bootstrap/runtime and test-support fixtures.
- [x] PostgreSQL schema: the authority/stream/snapshot tables now live directly
  in `migrations/00000000000000_initial/up.sql` rather than in a follow-on
  delta migration, the schema contract is `authority-commit-v1`, and
  `consent_cells (cell_id)` became `consent_grants (consent_id)` so the table
  matches the queries in `crates/storage-postgres/src/contacts.rs`.
- [x] Six tables whose Rust store had already moved to the authority-commit
  shape while the migration kept the Seal-era columns now match their queries:
  `publication_evidence (event_id, committed_ref, accepted_at)`,
  `device_revocation_targets (event_id, selector, committed_ref, committed_at)`,
  `device_revocation_cleanup_intents (event_id, committed_ref, selector, …)`,
  `device_revocation_gate_receipts (… request_json, status_json …)`,
  `recovery_policies.acceptance_ref`, and
  `recovery_sessions.{accepted_stream_head, authority_context}`. Every one of
  those stores named a column the database did not have, so each call failed at
  runtime. Proved by applying `up.sql` to a scratch database and diffing
  `information_schema.columns` against every `INSERT INTO` in the crate; the
  audit now reports no production-path mismatch. `crates/storage-postgres/src/schema.rs`
  was updated in the same shapes, and the two stale indexes that still named the
  dropped columns were removed.
- [ ] PostgreSQL schema, remaining work: the initial migration still creates 28
  Seal, Cell, control-proposal, history-key, RHRK, and frontier tables. They
  cannot be dropped until the live modules that still name them
  (`federation.rs`, `events.rs`, `idempotency.rs`, `recovery.rs`,
  `crates/services/src/persistence_operations.rs`,
  `crates/test-support/src/fault_injection.rs`) lose those code paths. An
  independent check confirms they are already dead data: no `INSERT` anywhere in
  the crate writes `agent_accepted_seal_signers`, `control_proposal_authority_acks`,
  `event_collision_variants`, `mls_frontier_inputs`, `pending_rhrk_acquisitions`,
  the six `history_key_*` tables, the three `history_traversal_*` tables, or the
  two `state_control_seal_*` tables.
- [x] `push_devices.device_authorization` is NOT such a column and must keep its
  `NOT NULL`. `crates/storage-postgres/src/push.rs` writes it on every
  registration and reads it back for rotation, authenticated reads, and
  revocation cleanup. It holds the server-verified `DeviceRevocationGateSelector`
  derived from the authenticated caller, which is why it is absent from
  `push_register_device_request_body`: it is not a request field. Dropping it
  would break `discovery/push-notifications.md` §3.3 and §3.4, which make device
  revocation MUST take effect on an existing registration.

## Verification gates

- [ ] All workspace targets format successfully with nightly rustfmt.
- [ ] `cargo check --workspace --all-features` passes. `coland-domain`,
  `coland-storage` and `coland-storage-postgres` are clean; `coland-services`
  reports 256 errors, which blocks `coland-http` and `coland-server`. The
  dominant causes are the removed `arkret_lattice_registry` and
  `arkret_state::state` Cell surfaces and the SDK types listed under
  "Upstream SDK gaps" below.
- [ ] `cargo test --workspace --all-features --no-fail-fast` passes.
- [ ] Forbidden protocol identifiers are absent from current code, schema, test,
  and migration surfaces.
- [ ] Route and storage contract tests prove preserved product capabilities remain
  registered.
- [x] `migrations/00000000000000_initial/up.sql` applies to an empty database
  with `ON_ERROR_STOP=1` and exits 0.

## Upstream SDK gaps that block coland

These types are referenced by coland code that must be rewired and do not exist
in `arkret-rust-sdk` today. Coland must not define local substitutes.

- `governance::realm_join_intake::{RealmJoinBootstrapAssembly, RealmJoinBootstrapOutcome,
  RealmJoinBootstrapRequestBody, RealmJoinGovernanceFacts}` — blocks
  `crates/services/src/sync.rs` and the join/bootstrap route.
- `agent_operations::{AgentSidecarState, AgentSidecarEncryptionProfile}` — blocks
  `crates/domain/src/reducer/apply_objects/sidecar.rs`.
- `governance::agent_membership_cascade::AgentControllerMembershipBinding`,
  `AgentCleanupRecord`, `MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS` — the last two
  currently have local copies in `crates/storage/src/agent_membership_cascades.rs`
  that must be deleted once the SDK carries them again.
- `sync_frames::demand_sync::{RealmDetailBaseline, ACCOUNT_SYNC_MAX_TIMELINE_LIMIT}`
  and `sync_frames::client_sync::timeline_predecessors`.
- `arkret_models_crypto::{MlsAcceptedLeafAuthorization, MlsEpochHead}`.
- `arkret_models_identity::AuthenticatedSignerResolutionEvidence`.

### Agent signer evidence: the whole module is gone, and prose requires it

Measured 2026-09-17 against `arkret-rust-sdk` main. Every symbol below is a
zero-hit across the entire SDK, `generated/` included:

| Missing SDK symbol | coland references |
|---|---|
| `models_identity::agent_signer_evidence::AgentLifecycleStatus` | 23 |
| `models_identity::agent_signer_evidence::AgentSignerEvidence` | 15 |
| `models_identity::agent_signer_evidence::CurrentAgentSignerEvidence` | 6 |
| `models_identity::agent_signer_evidence::AgentKeyCellEntry` | 3 |
| `arkret::build_agent_signer_evidence` | 2 |
| `arkret_signatures::agent_evidence::agent_authorization_cell_ref` | 2 |
| `arkret_signatures::agent_evidence::sign_agent_authority_state_attestation` | 1 |
| `arkret_signatures::agent_evidence::agent_admission_evidence_digest` | 1 |

53 references, almost all in
`crates/http/src/routing/identity/agents/evidence.rs` (1501 lines), with the
rest in `agents/pairing.rs`, `agents/common.rs`, `agents/tests.rs` and
`identity/current_signer_evidence.rs`.

**This is not dead code.** `identity/mod.rs:7` declares `mod agents`,
`agents.rs:77` declares `mod evidence` — the whole chain is in the compile
graph, so these are live product surfaces that cannot build, not orphans.

**Prose requires one of them by name.** `spec/v1/zh/identity/key-management.md:182`
makes the Station the owner of Agent pairing material and says activation MUST
build *exactly one* `CurrentSignerEvidence::Agent` from the frozen
authorization / lifecycle / governance-Station / account-authority closure using
the SDK's `build_agent_signer_evidence`, and that the Authority consumes only
that exact outcome — it MUST NOT rebuild and compare, and MUST NOT substitute a
fresh timestamp or signature. Without the SDK function there is no way to honour
"exactly one, built once, by the Station".

Note `models-identity/src/agent_signer_evidence.rs` **does exist** in the SDK
and carries `AgentAuthorizedSigningKey`, `ControllerAccountGateAttestation` and
friends. So this is a *partial* restoration, not an untouched module: the
gate-attestation half came back and the signer-evidence half did not. Do not
read the file's existence as evidence that the capability is present.

Reference implementation: `e309b047^:crates/signatures/src/agent_evidence.rs`
(1470 lines, about 40 public items). Two cautions when restoring it:

- `AgentKeyCellEntry` and `agent_authorization_cell_ref` carry `Cell`, which is
  removed vocabulary under the authority-commit clean break. Rebuild them under
  the typed current result naming, do not copy the old names back.
- `SignerKeyQueryOutcome`, `AccountSubscribeSnapshotResult` and
  `ModerationQueueItem` are NC-TYPE-001 violations in the same area (`Result` is
  not in the closed wrapper-word table; `Outcome` and `Row` are). Fix them in
  the same pass rather than propagating them.

Also stale and misleading:
`arkret-rust-sdk/crates/models-identity/src/agent_signer_evidence.rs:130-141`
hardcodes a schema id string and comments that the registry row has not landed.
It has — `arkret-spec/spec/v1/artifacts/registry/contract-registry.json:3537`.

### BackupSeriesErase worker carrier

The public BackupSeriesErase operation was retired by `arkret-spec ddcfd6ec`.
SecurityRotation still erases the old backup series as an internal worker
action. Its durable request, progress row, status and outcome types live in
`crates/storage/src/backup_series_erase.rs`; they are not exported by the SDK
or exposed through HTTP. The protocol retains
`BackupSeriesEraseConfirmation`, whose digest projection is defined by the
formal SecurityRotation contract.

`arkret_wire::UnsignedRecoveryCompletionAttestationBody` has already moved to
`{reanchor_event_ref, device_authorization_event_ref}`;
`crates/http/src/routing/identity/recovery/security_transaction_endpoints.rs`
still supplies the removed `terminal_commit_digest`,
`device_authorization_event_id` and `first_generation_seal_id`. It must pass the
two `CommittedEventRef` values and rely on the SDK's own
`validate_recovery_commit_pair` rather than re-checking the pair locally.

## Measured status, 2026-09-18

```
cargo check --workspace --all-targets --keep-going --message-format short
```

`--keep-going` is not optional. Without it Cargo aborts the whole build at the
first failing unit, which is why every earlier number in this file understated
the workspace: the units after `coland-services` were never reached at all.

| unit | errors | delta vs 09-16 |
|---|---|---|
| `coland-domain` (lib) | 0 | |
| `coland-domain` (lib test) | 392 | -32 |
| `coland-storage` (lib) | 0 | |
| `coland-storage` (lib test) | 35 | 0 |
| `coland-storage-postgres` (lib) | **0** | was 3 undetected E0609 |
| `coland-storage-postgres` (lib test) | 84 | not previously measured |
| `coland-storage-postgres` (integration tests) | 170 | `store_contracts` 111, `durable_plane_restart` 48, `account_global_sync` 11 |
| `coland-services` (lib) | **160** | -7 |
| `coland-services` (lib test) | 199 | -67 |
| `coland-http` | **still never checked** | blocked on `coland-services` (lib) |
| `coland-server` | **still never checked** | same |

Workspace total with `--keep-going`: **853** errors across 8 failing units.

What `fa20b0cd9` actually closed: `coland-storage-postgres` (lib) 3 -> 0,
`hydration.rs` 1 -> 0, `persistence_operations.rs` 12 -> 7 (the remainder is
timeline only), and the two `E0407` in the same file. It did **not** move
`projection.rs`, and it was not meant to.

### The three remaining `coland-services` (lib) clusters are not residue

- `projection.rs` -- the Cell-write projection seam. Every `control_*` method on
  it routes through `self.control_event_store()`, and
  `arkret_state::state::store::ControlEventStore` no longer exists upstream, so
  `put_pending_control_event`, `put_pending_control_unit`,
  `control_event_by_digest`, `control_proposal_snapshot` and
  `pending_control_records` are **all** broken -- not only the ack ones. The
  capability those methods provide survives in the protocol; the store under
  them has to be rebuilt in coland. Together with the `cbs` port above this is
  one design round, not a sweep.
- `events.rs` / `persistence_events.rs` -- the same seam seen from the event
  side.
- `sync.rs` / `persistence_operations.rs` -- `TimelineOrderPosition` /
  `TimelineWindowScan`. These types did not exist at the merge base
  `e309e0463` either; they are residue of the **earlier** large deletion, not
  of this round. The replacement design (keyset on `realm_commits.stream_position`
  over a single `CommitStreamRef`) cannot be implemented yet: the frame shape it
  has to feed is undefined in the specification. See
  `arkret-work/tasks/spec-open/`.

## Superseded: measured status, 2026-09-16

Commands and their real output, so the next session starts from numbers rather
than from an impression. `cargo check` is run with `--all-targets`, because a
green library check says nothing about the tests that prove the capability.

```
cargo check --workspace --all-targets --message-format short
```

| unit | errors | note |
|---|---|---|
| `coland-domain` (lib) | 0 | |
| `coland-domain` (lib test) | 424 | 160 in `reducer/tests/cells_realm.rs` alone |
| `coland-storage` (lib) | 0 | |
| `coland-storage` (lib test) | 35 | `contract_tests.rs` |
| `coland-storage-postgres` (lib) | 0 | |
| `coland-storage-postgres` (integration tests) | 160 | `store_contracts` 106, `durable_plane_restart` 43, `account_global_sync` 11 |
| `coland-services` (lib) | **167** | was 216 at the start of this session |
| `coland-services` (lib test) | 266 | |
| `coland-http` | **never checked** | Cargo stops at the failing `coland-services` library, so this crate has not been type-checked once during the migration. |
| `coland-server` | **never checked** | same reason |

Where the 167 remaining `coland-services` library errors are:

| file | errors | what it needs |
|---|---|---|
| `projection.rs` | 94 | the Cell-write projection seam: `arkret_state::state`, `arkret_schema::project_registered_cell_writes*`, `prepare_seal_in_context`, `SealBasis`, `composite_subject`, the `MlsKeypackage`/`MlsWelcome`/`MlsProposal` event kinds |
| `events.rs` | 32 | `ControlProposalAck`, `GovernanceDependencyWrite`, `MlsSecurityFrontierLeaf`, `RealmBootstrapCommitOutcome`, `RecoveryTerminalCommitWrite` |
| `sync.rs` | 16 | the frozen timeline window: `TimelineOrderPosition`, `TimelineWindowScan` |
| `persistence_operations.rs` | 12 | same timeline window, plus the control-proposal ack port |
| `persistence_events.rs` | 12 | same as `events.rs` |
| `hydration.rs` | 1 | `validate_realm_bootstrap_unit`; the SDK now validates one genesis Event (`validate_realm_genesis_event`) rather than a multi-Event unit |

The `coland-http` figure is the important one. Nothing in that crate has been
compiled since the migration began, and a grep finds 328 references to the
retired encryption-floor / content-scheme / encryption-profile vocabulary across
40+ files there, plus a 2,177-line
`routing/identity/recovery/security_transaction_endpoints.rs` still built on
Seals. Treat "the workspace has N errors" as a lower bound until
`coland-services` (lib) reaches zero.

### Upstream dependency

`arkret-rust-sdk` has several agents landing the fourth round of restorations
concurrently, and its working tree went red twice during this session
(`arkret-mls::exporter_kdf` importing `arkret_wire::CallRecordingId`, then
`arkret-models-identity::signer_key_operations` against `CommittedEventRef` /
`StationSigningKey`). Both cleared on their own. Measure coland only when the
SDK workspace is green, or the numbers mean nothing.

### Schema

`schema.rs` and the initial migration now agree column for column: enumerating
every `diesel::table!` and every `CREATE TABLE` finds **0** declared columns and
**0** declared tables the database does not have. The five that were wrong were
`device_revocation_gate_receipts.{target_device_authorize_event_id,
target_device_generation_ref}` (also spelled into the primary key) and
`federation_frontier_confirmed_evidence.{resolution_kind, resolution_digest,
resolved_at}`, where the table actually has `local_resolution_kind`,
`local_resolution_digest`, `local_normalized_at`, `peer_alignment_digest` and
`peer_aligned_at`.

The old-protocol tables are still created: Seal, Cell, control-proposal,
history-key, RHRK, frontier, and the two timeline-order tables. They cannot be
dropped while `federation.rs`, `events.rs`, `idempotency.rs`, `recovery.rs`,
`services/src/persistence_operations.rs` and `test-support/src/fault_injection.rs`
still name them.
