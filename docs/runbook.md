# coland runbook

## Move a self-hosted Station public base

Keep the PostgreSQL database, durable KeyStore, identity bundle directory and
trust domain. Stop the business listener before applying the cut. Prepare TLS
and routing for the target HTTPS origin. Changing `COLAND_PUBLIC_BASE_URL` alone
reports registration-key drift and does not authorize an identity successor.
Using the existing deployment configuration and credentials, run:

```sh
coland service-identity migrate-base --from https://old.example/ --to https://new.example/ --preflight
coland service-identity migrate-base --from https://old.example/ --to https://new.example/
```

To move only the service endpoint while retaining its DID hosting location,
add `--preserve-did-host` to both commands. Keep the original DID metadata
routes available; this mode signs an endpoint successor without relocating the
DID. Both modes retain the same service core and require the control key.

Preflight verifies the stored native head and possession of its precommitted
next control key and prints public target material without writing a successor.
Apply signs a same-core WebVH successor, changes the Station endpoint and native
DID host, and atomically updates native history, registration mapping, receipt
and runtime identity. Complete signed receipt history is durable in Postgres.
Configure the target public base and start the listener with the same custody.
Confirm Describe and authenticated service resolution against native history;
peers refresh through normal endpoint discovery and the existing verifier.
No PCR governor, Account or Realm is moved.

A failed database cut leaves the old accepted identity current. A bundle-write
failure after an accepted cut can be repaired by repeating the exact command;
it reports `already_current` without signing another version. Do not restore an
older bundle over a newer accepted key floor. Returning to an earlier origin
requires another signed successor.

During transition, the old origin may serve retained canonical `did.jsonl`
history from the same durable store. Registration-key drift continues serving
the accepted identity; Describe advertises its signed current endpoint. Drift
alone does not retire a listener. After consumers discover the target, retire
the old business entry explicitly through listener or reverse-proxy routing.
Keep DID metadata routes available for every user identity still rooted there.
When proxying those routes, preserve the original HTTP Host so native hosting
can select the exact accepted URL independently of the business base.
Only each owner can sign its legal DID relocation; the service migration cannot
sign for users. Retain immutable history and old registration mappings. The command requires the self-hosted Provider;
an external Provider requires its own authenticated signed successor publication.

On-call recipes for common coland incidents. Pair with the
Prometheus alert rules in `examples/prometheus-alerts.yml`.

## Common error codes

coland returns canonical SDK error codes on every refusal. The most
operator-relevant ones:

| Code | Where | Operator response |
| --- | --- | --- |
| `migrations_pending` (top-level on `/readyz`) | `routing::system::describe::readyz` | Soft block — wait. If it persists more than 60 s on a healthy Postgres, check the diesel boot log for a partial migration. |
| `database_unreachable` (top-level on `/readyz`) | same | Verify `DATABASE_URL`, check Postgres logs, confirm the coland process can reach the listed host. |
| `cross_domain_replay_rejected` | Federation intake | A peer replayed an event whose `trust_domain` does not match this deployment's `COLAND_TRUST_DOMAIN`. Confirm the peer's `Source-Trust-Domain` header is correct. |
| `cursor_expired` | account / events subscribe | Client cursor older than the configured window. Client must re-subscribe with `from=null`. |
| `handle_in_grace_period` | identity handle claim | Handle was released too recently. Wait out `HANDLE_GRACE_PERIOD_SECONDS` or pick a different handle. |
| `retry_budget_exhausted` (DLQ row reason) | Federation outbox | Peer was unreachable for `MAX_ATTEMPTS` transport retries. Inspect with `coland-federation-outbox list --dead-letters`, then `inspect <id>`. |
| `semantic_retry_budget_exhausted` (DLQ row reason) | Federation outbox | The peer kept answering `dependency_missing` past `MAX_SEMANTIC_ATTEMPTS` resubmissions. The missing dependency is on the peer side — do not keep replaying; resolve the dependency first (`sync/federation.md` §4.1). |
| `egress_policy_denied` (`policy_suppressed` state) | Federation outbox | The local egress policy blocked the peer. The row is **not** dead-lettered: fix the policy and the dispatcher revalidates it automatically on the next pass, because the policy version changed. |

## Log search recipes

Production deployments default to structured JSON logs (see
DEPLOYMENT.md §7). The recipes below assume `jq`-friendly output;
adjust for your log aggregator.

```bash
# Every audit-append failure since the last 1 h, with reason.
journalctl -u coland --since "1 hour ago" -o cat \
  | jq -c 'select(.target == "audit" and .level == "ERROR")'

# Federation outbox dead-letters in the last 24 h.
journalctl -u coland --since "24 hours ago" -o cat \
  | jq -c 'select(.target == "federation_outbox" and (.fields.event | contains("dead-letter")))'

# Every 5xx response by operation id.
journalctl -u coland --since "1 hour ago" -o cat \
  | jq -c 'select(.fields.status >= 500) | {op: .fields.op, status: .fields.status, ts: .timestamp}'

# Replay-window rejections (signature too old / too new).
journalctl -u coland --since "30 minutes ago" -o cat \
  | jq -c 'select(.fields.reason == "replay_window")'
```

If the deployment uses Loki, the equivalent LogQL queries are:

```logql
{service="coland"} |= "audit_append_failure"
{service="coland"} |= "dead-letter"
{service="coland"} | json | status >= 500
```

## Metrics dashboard and alerts

Import `docs/grafana-operational-dashboard.json` into Grafana for the
release-blocking operations view. It covers the four alert families that
usually need immediate operator action: egress denies, digest mismatches,
federation retry/dead-letter health, and audit append failures.

Recommended PromQL alert expressions:

```promql
# Outbound calls blocked by the configured egress policy.
sum by (reason, target_class) (increase(coland_egress_denied_total[10m])) > 0

# Payload integrity mismatch on an admission path.
sum by (scope) (increase(coland_digest_mismatch_total[10m])) > 0

# Federation retry budget exhausted or terminal 4xx dead-lettering.
sum by (state) (
  increase(coland_federation_retry_total{state=~"retry_budget_exhausted|terminal_http_status"}[15m])
) > 0

# A delivery intent nobody has managed to hand off for an hour.
coland_federation_outbox_oldest_pending_age_seconds > 3600

# One peer's backlog is growing while the rest are healthy.
sum by (peer) (coland_federation_outbox_state_depth{state=~"pending|leased"}) > 500

# A dispatcher replica keeps losing its lease mid-delivery (overrun or crash loop).
increase(coland_federation_outbox_lease_takeover_total[15m]) > 0

# Durable audit append failure.
increase(coland_audit_append_failures_total[5m]) > 0

# Eligible Control Seal work is not being drained.
coland_control_seal_oldest_eligible_age_seconds > 60

# A bounded Realm pass timed out.
increase(coland_control_seal_attempt_total{outcome="pass_timed_out"}[10m]) > 0

# Repair had to restore a transactionally missed schedule update.
sum(increase(coland_control_seal_repair_total{operation=~"inserted|generation_repaired"}[10m])) > 0
```

Operator actions:

| Alert | First query | Owner action |
|---|---|---|
| `coland_egress_denied_total` | `sum by (reason,target_class) (increase(coland_egress_denied_total[30m]))` | Confirm the target is expected. If it is a real dependency, add the explicit allow-list or public endpoint; otherwise treat as SSRF or peer misconfiguration. |
| `coland_digest_mismatch_total` | `sum by (scope) (increase(coland_digest_mismatch_total[30m]))` | Pull the rejected request logs for the same `scope`; compare client canonical bytes, `Content-Digest`, and SDK version. |
| `coland_federation_retry_total` | `sum by (state) (increase(coland_federation_retry_total[30m]))` | For `retry_scheduled`, inspect peer health. For terminal states, inspect the dead-letter row and replay only after the peer/config issue is fixed. |
| `coland_federation_outbox_oldest_pending_age_seconds` | `coland_federation_outbox_oldest_pending_age_seconds` | Something is owed to a peer and not moving. Check `coland_federation_retry_delay_seconds` — a long scheduled delay is the peer's `Retry-After`, a zero-progress `attempts` count is a stuck dispatcher. |
| `coland_federation_outbox_state_depth` | `sum by (state,peer) (coland_federation_outbox_state_depth)` | Distinguishes "one peer is down" from "the dispatcher is stuck". A rising `policy_suppressed` bucket means the local egress policy, not the peer. |
| `coland_federation_outbox_lease_takeover_total` | `increase(coland_federation_outbox_lease_takeover_total[30m])` | A replica's delivery outran its lease or the replica died. Correctness is preserved (the stale write is dropped), but sustained takeovers mean `LEASE_DURATION_SECS` is too short for this peer's latency. |
| `coland_audit_append_failures_total` | `increase(coland_audit_append_failures_total[10m])` | Check Postgres availability and audit-table permissions first; stop admin rollout if audit durability is unavailable. |
| `coland_federation_outbox_dead_letter_total` | `sum by (reason) (increase(coland_federation_outbox_dead_letter_total[30m]))` | Read the reasons, group by peer DID, coordinate with the peer, then replay explicitly (below). |
| `coland_control_seal_oldest_eligible_age_seconds` | `coland_control_seal_oldest_eligible_age_seconds` | Compare pending, eligible, claimed, expired-claim and in-flight gauges. If execution slots are free, inspect coordinator/store errors and process health. |
| `coland_control_seal_expired_claims` | `coland_control_seal_expired_claims` | Check process exits and pass/store deadline logs. Claims are safe to reclaim after expiry; a sustained non-zero value means reclaim is not keeping pace. |
| `coland_control_seal_attempt_total{outcome="pass_timed_out"}` | `increase(coland_control_seal_attempt_total{outcome="pass_timed_out"}[30m])` | Inspect the timed-out Realm and confirm later Realms and device-revocation cleanup continued. Do not extend the claim TTL to hide a blocking stage. |
| `coland_control_seal_repair_total` | `sum by (operation) (increase(coland_control_seal_repair_total[30m]))` | `inserted` or `generation_repaired` is a missed transactional write-path signal. Audit all three Control Event ingress paths before rollout. |

## Control Seal scheduler

The scheduler gauges are sampled directly from durable schedule state at scrape
time. `pending` is total derived work, `eligible` is immediately claimable,
`claimed` is owned under an unexpired fence, and `expired_claims` is reclaimable
work left by a stopped or overdue worker. Oldest ages are zero when their bucket
is empty. Repair insert/generation changes, pass timeouts, or a sustained oldest
eligible age are release-blocking until their source is understood.

## Federation outbox operator commands

Terminal rows are never replayed by a restart — that is deliberate, since a
dead letter means the peer rejected the request or the retry budget ran out.
Replay is an explicit, audited act:

```bash
# What is still owed, and what gave up.
cargo run --bin coland-federation-outbox -- list --state pending
cargo run --bin coland-federation-outbox -- list --dead-letters

# Why one row stopped (request reported by digest, not verbatim).
cargo run --bin coland-federation-outbox -- inspect <outbox-id|dead-letter-id>

# Replay after the peer/config issue is fixed. Re-validates the peer, the
# egress policy and the stored request, then mints a NEW intent with a NEW
# Idempotency-Key and stamps the audit onto the dead letter. Single-shot.
cargo run --bin coland-federation-outbox -- requeue <dead-letter-id> \
  --operator did:web:you.example --reason "peer endpoint restored"
```

There is no HTTP admin surface for this. Adding one would require a canonical
operation and an `/_arkret/...` binding in `arkret-spec` first; a private
`/_coland/...` route is not permitted.

## Restart strategy

coland is stateless apart from its in-process projection caches; restart
is always safe once `/readyz` is green.

1. Drain in-flight requests at the load balancer (LB removes the replica
   from the active pool but keeps existing connections alive).
2. Send `SIGTERM` (Kubernetes / systemd default). The Salvo server
   honors the shutdown signal and waits for in-flight requests to
   finish before closing the listener; the file appender's
   `_file_guard` flushes pending log writes on Drop.
3. Wait for the process to exit cleanly (≤ 30 s in normal conditions —
   the federation dispatcher tick is the long pole).
4. Start the new binary. Migrations run synchronously on boot; the
   new replica answers `/readyz` with
   `migrations_pending` until the diesel batch is complete.
5. Re-enable the replica at the LB only after `/readyz` returns 200.

Hard kill (`SIGKILL`) is safe but loses in-flight requests; clients
will retry against the next replica.

## Fault-injection examples

Useful for game-days and incident drills.

### 1. Force `migrations_pending` on a live replica

```bash
# Disable the replica's view of Postgres without disturbing peers.
# /readyz flips to 503 migrations_pending immediately.
sudo iptables -A OUTPUT -p tcp --dport 5432 -j DROP

# Restore.
sudo iptables -D OUTPUT -p tcp --dport 5432 -j DROP
```

### 2. Saturate the federation outbox

```bash
# Point a peer at a sink that returns 5xx for every request.
# Watch coland_federation_outbox_depth climb and the
# coland_federation_outbox_dead_letter_total counter advance after
# MAX_ATTEMPTS retries per row.
just db-shell
# inside psql: pull every still-owed row forward. `state` is the source of
# truth for "still owed"; do not infer it from a timestamp.
UPDATE federation_outbox SET next_attempt_at = 0
 WHERE state IN ('pending', 'leased');
```

### 3. Trigger the audit-append failure alert

```bash
# Make the audit table read-only and exercise an event that writes
# an audit row. Every refusal bumps
# coland_audit_append_failures_total.
just db-shell
# inside psql:
REVOKE INSERT ON projection_audit FROM coland;
# ...exercise the event...
GRANT INSERT ON projection_audit TO coland;
```

## Escalation pointers

- `CHANGELOG.md` `[Unreleased]` for the most recent wire deltas.
- `crates/*/tests/` and `crates/**/src/**#[cfg(test)]` for behavior-focused
  regression coverage.

---

## R3 operational additions

The sections below cover the R3 sync and later v1 updates
(`arkret-spec @ e3f6832d`). They are
intentionally separable from the earlier runbook above so that you can
on-call a fresh ops engineer who has not seen pre-R3 coland.

### Agent FSM transitions (pause / resume / deactivate)

coland is the canonical owner of the agent FSM. The state machine has three
nodes:

```text
  +---------+    pause    +--------+   deactivate  +-------------+
  | Active  | ----------> | Paused | ------------> | Deactivated |
  +---------+             +--------+               +-------------+
       ^                      |  ^                        ^
       |     resume           |  |                        |
       +----------------------+  +-- (reject if Deactivated)
```

Operationally:

- **pause** (`POST /agents/{agent_id}/pause`):
  - Soft-stop. Outstanding actor-stream events drain through the reducer.
    No new actor events accepted; the reducer surfaces `agent_paused` on
    writes.
  - Audit row goes to `projection_audit` with kind=`agent.pause`.
  - **Operational triage**: if you see a spike in `agent_paused` rejects on a
    realm, check whether an admin in `codmin` flipped the agent runtime
    profile; do not assume a misbehaving client.
- **resume** (`POST /agents/{agent_id}/resume`):
  - Reverse of pause; rejected with `agent_deactivated` if the state is
    Deactivated (terminal).
- **deactivate** (`POST /agents/{agent_id}/deactivate`):
  - Terminal. The historical `/revoke` alias is gone; alerts that still fire
    on `/revoke` paths are false positives — update the alert.
  - Inert reads remain allowed (so that auditors can backfill the agent's
    history). All writes return `agent_deactivated`.

Common ops actions:

| Symptom | Probable cause | Action |
|---|---|---|
| `agent_paused` storm on one realm | Admin policy change or pairing drift | Inspect last `ak.self.agent.pause` event for the principal; confirm with admin in codmin |
| `pairing_request_expired` | Pairing window elapsed; default 10 min | Re-issue `ak.gate.account.command.pair_agent_key.v1`; check NTP drift on client |
| `proof_invalid` on pairing | Canonical-digest mismatch — usually a client serializer bug | Pull the raw payload from `agent_pairing_attempts` table and diff JCS bytes |
| `verification_method_principal_mismatch` | DID resolved to a different principal than payload claims | Likely DID-doc misalignment in `coauth`; coordinate with that team |

Recovery strand / migration story for an agent that drifts: see `coauth`
runbook + `docs/admin-onboarding.md` in codmin.

### Recovery strand (policy + receipt issuance lifecycle)

R3 surfaces recovery as a first-class wire strand. Lifecycle:

```text
[client]                  [coland]                              [witnesses]
   | create policy           |                                       |
   |------------------------>|  ak.recovery.policy.create             |
   |                         |---------------------+                 |
   |                         |  policy_id, version |                 |
   |<------------------------|                     |                 |
   |                         |                     |                 |
   |  start recovery_session |                     |                 |
   |------------------------>|  ak:recovery_session:<uuid>            |
   |                         |                                       |
   |                         |  collect proofs (per proof_kinds)     |
   |                         |<--------------------------------------|
   |                         |                                       |
   |  complete session       |                                       |
   |------------------------>|  ak.recovery.session.complete          |
   |                         |   - emits RecoveryReceipt              |
   |<------------------------|                                       |
```

Witness types (`RecoveryProofKind`):

- `DeviceQuorum` — N-of-M device signatures.
- `RecoveryUnlock` — recovery-unlock token; usually a long-lived sealed
  envelope.
- `TrustedRecoveryService` — third-party service signature; subject to
  `recovery_witness_revoke_lagging` if the service's revocation feed is
  stale relative to the freshness window.
- `DidRoot` — the principal proves possession of the cold DID recovery
  authority for a policy-authorized recovery ceremony.

Operational behaviors:

- **`RecoveryReceipt` is the only artifact downstream services trust.**
  If a service is making decisions based on session-in-progress state, it
  is doing the wrong thing — file a bug.
- **Policy versioning is monotonic.** When you rotate a policy, the new
  policy MUST carry `policy_version = prev + 1`. Concurrent policy writes
  resolve via the canonical digest; the loser receives a structured reject
  and re-tries. Operators usually see this only during disaster-recovery
  drills.
- **Freshness window for witness revocation** is configured per realm
  (default 10 minutes). If a witness is revoked but the revocation hasn't
  propagated, you get `recovery_witness_revoke_lagging`. Triage:
  1. Confirm the witness revocation actually landed at the source-of-truth
     (`coauth` for principal-bound witnesses).
  2. Check `coland_witness_revoke_replication_lag_seconds`.
  3. If above SLO, the right answer is to widen the window temporarily and
     escalate to whoever owns the revocation replication, NOT to weaken the
     proof check.

### Media token issuer (rotating service_signature.kid, focus binding troubleshooting)

coland is the canonical issuer of media tokens. The wire surface is
`ak.self.call.media.exchange.issue_token.v1` (`POST /rtc/token`).

`service_signature.kid` rotation:

- KIDs follow `ak-media-issuer/{realm_id_short}/{yyyy}-{NN}` where NN is a
  monotone counter per realm-year.
- Active set is **previous + current + next** for at least one rotation
  cycle; tokens with `expires_at` inside their own kid's validity window
  are accepted.
- Rotation cadence: default 30 days; operationally pin shorter if you have
  evidence of issuer-key exposure.
- Rotation procedure:
  1. Generate the new kid offline; stage it in the kid-store with status
     `staged` (not yet issuing).
  2. Flip status to `current`; previous current becomes `previous`.
  3. After max token TTL (10 min hard ceiling), revoke the old `previous`.

Focus-binding troubleshooting matrix:

| Error | What to check |
|---|---|
| `focus_mismatch` | `ak.realm.media_service.foci[]` shape; the focus_id the client picked must be in the realm's current focus set. |
| `unknown_focus_type` | A backend the realm advertises but the client doesn't profile — confirm `ak.profile.media_service_binding.<backend>.v1` is in the client's declared profile set. |
| `token_issuer_unauthorised` | The `issuer_kid` decoded to an issuer not bound to this realm — usually a stale coland instance returning tokens for a realm it no longer hosts. |
| `participant_binding_invalid` | Canonical bytes / signature mismatch. Capture the raw `participant_binding` and re-verify locally; suspect a serializer bug on the issuer. |
| `participant_id_unrecognised` | Identity string failed to parse — usually a client passing through a backend-native identity instead of the canonical `ak:participant:<realm>:<actor>:<device>:<call>`. |
| `session_focus_already_committed` | Call is bound to a different focus already; the client must resume against that focus or end and re-initiate. |
| `e2ee_key_source_unauthorised` | Backend tried to source SFrame keys outside MLS-Exporter — this is a hard reject. Escalate to inkson if it persists. |
| `recording_artifact_pipeline_bypassed` | Recording landed outside the canonical pipeline. Check `floria` recording-export hooks. |
| `focus_unavailable_for_client` | Client profile set doesn't include the focus's backend profile. Negotiate down or update the client. |
