# Media Token Issuer

> Spec: `arkret-spec @ e3f6832d`, `ak.self.call.media.exchange.issue_token.v1` operation.
> Companion runbook: [`../runbook.md` → Media token issuer](../runbook.md#media-token-issuer-rotating-service_signaturekid-focus-binding-troubleshooting).
> SDK type reference:
> [`arkret-rust-sdk docs/architecture.md`](../../../arkret-rust-sdk/docs/architecture.md#call-media-cxcallmediatoken_exchange).

This document is the architectural reference for coland's role as the
**canonical media-token issuer** in the Arkret v1 protocol family. It is
the source of truth for: who issues, when floria proxies, focus_id derivation
rules, participant_binding canonical bytes, TTL policy, and kid rotation.

## Issuer roles

| Role | coland | floria |
|---|---|---|
| Canonical issuer of `MediaTokenResponse` | **Yes** | No (proxy only) |
| Holds the issuer key material | **Yes** | No |
| Signs `participant_binding` | **Yes** | No |
| Signs `service_signature` | **Yes** | No |
| Rotates `issuer_kid` | **Yes** | No |
| Exposes `POST /rtc/token` to clients | **Yes (direct)** | Yes (proxy in v1) |

In Arkret v1, coland is always the canonical signing authority. floria may
proxy the request from the client to coland (e.g. when push-side network
constraints make a direct client→coland call awkward), but floria never
forges, re-signs, or augments the token. Specifically:

- floria's proxy is *transparent*: byte-for-byte forward of the token from
  coland to the client.
- floria does NOT cache tokens. Each token is single-issue; caching would
  break the per-(realm, call, actor, device, focus) uniqueness invariant.
- floria does NOT see the participant_binding in plaintext at any persistent
  layer — its request log redacts the binding bytes.

The decision to proxy is made by the realm operator (via
`ak.profile.media_service_binding.v1` and floria deployment posture), not
by the client. Clients always request `/rtc/token` against the realm's
canonical endpoint; whether that endpoint is fronted by floria is a
deployment detail.

## `focus_id` derivation

Each focus in a realm's `ak.realm.media_service.foci[]` advertises a
canonical `focus_id` of the form:

```text
<backend>:<region>:<instance-disambiguator>
```

Examples:

- `livekit_eu-west-1` — a LiveKit pool in eu-west-1.
- `mediasoup_us-east-2:b` — a second Mediasoup pool in us-east-2.

Derivation rules:

1. `backend` MUST be one of the registered `MediaBackendKind` arms
   (`livekit`, `mediasoup`, `janus`, `arkret_native`, `moq_relay`). Unknown
   backends surface `unknown_focus_type` at exchange time.
2. `region` is a free-form lowercase tag MAX 32 chars matching
   `[a-z0-9-]+`. Region is opaque to coland — its only role is human
   readability and dispatch.
3. `instance-disambiguator` is optional. When present, it MUST match
   `[a-z0-9-]+` MAX 16 chars.
4. The total `focus_id` MUST be <= 96 octets and MUST round-trip through
   ASCII bytes (no UTF-8 multibyte).

coland refuses to issue a token for a `focus_id` that is not currently in
the realm's `ak.realm.media_service.foci[]` set, returning `focus_mismatch`.

## `participant_binding` canonical bytes

`ParticipantBinding` is defined with `scheme = "ak.media.participant_binding.v1"`:

```json
{
  "scheme": "ak.media.participant_binding.v1",
  "issuer_kid": "ak.media-issuer/example/2026-05",
  "realm_id": "ak:realm:...",
  "call_id": "ak:call:...",
  "focus_id": "livekit_eu-west-1",
  "actor_id": "ak:did_core:webvh:...",
  "device_id": "ak:device:...",
  "participant_id": "ak:participant:<realm>:<actor>:<device>:<call>",
  "expires_at": "2026-05-27T12:34:56.789Z",
  "sig": "<base64url>"
}
```

Canonical byte derivation for signing / verification:

1. Compute `inner = the binding object with the `sig` field removed`.
2. Apply RFC 8785 JCS to `inner`.
3. Hash with SHA-256.
4. Sign the digest under the issuer's signing key indexed by `issuer_kid`.
   Signature algorithm is Ed25519 unless overridden by the realm's profile
   set (the SDK's `ParticipantBinding` decoder rejects unknown algorithms).

Verification reverses the same chain. Any mismatch surfaces as
`participant_binding_invalid`. coland refuses to issue a binding whose
canonical bytes round-trip differs from the bytes its signer just signed —
this is the canonical defense against serializer drift between SDK and
coland.

`participant_id` is its own canonical string:

```text
ak:participant:<realm_short>:<actor_short>:<device_short>:<call_short>
```

where `_short` is the trailing-8-hex of each id's UUID portion. The full
ids live in their dedicated fields; the identity string is a join-time
human-readable correlation handle. Clients MUST verify the identity string
matches the canonical join string before connecting to the backend.

## TTL policy

| Aspect | Value | Rationale |
|---|---|---|
| Hard ceiling | 600s | Spec rule: token MUST NOT exceed 10 minutes. |
| SHOULD ceiling | 300s | Most production realms run 5-minute tokens. |
| Soft warning | issued > 300s | SDK logs a warning; metric `coland_media_token_long_ttl_total` ticks. |
| Renewal | client-side | Tokens are single-issue; renew = new `/rtc/token` call. |

If a client passes a `requested_ttl` greater than the hard ceiling, coland
returns the response with the capped `expires_at`. The token is valid for
the capped window, not the requested window. SDK's `validate_token_ttl()`
helper enforces the rule client-side.

## `service_signature.kid` rotation

The `kid` (Key ID) embedded in `service_signature` is the canonical name
coland uses to look up the signing key. Form:

```text
ak-media-issuer/<realm-short-or-deployment-label>/<yyyy>-<NN>
```

- `realm-short-or-deployment-label` is either the realm's 8-char short id
  (for realm-bound issuers) or a deployment label (for shared issuers
  serving multiple realms — only used in single-tenant deployments).
- `yyyy-NN` is the issuance epoch: 4-digit year + 2-digit counter,
  monotone-incrementing per epoch.

Active key set: **previous + current + next**. Tokens are accepted iff
their `expires_at` falls inside the validity window of the kid that signed
them, and the kid's status is one of `previous`, `current`, `next`.

Rotation cadence:

- Default: 30 days. After 30 days the next kid becomes current; the prior
  current becomes previous; the prior previous is revoked.
- Compromise rotation: immediate. Revoke compromised kid, drain all
  in-flight tokens via the hard 10-min ceiling, then proceed.

Procedure:

1. Stage the new kid (`status = staged`). coland will NOT issue under a
   staged kid.
2. Flip status to `current`; the prior current becomes `previous`.
3. After max token TTL (10 minutes), revoke the old `previous`.
4. Update issuer-key-set metric exporter so dashboards reflect the new
   counter.

## Failure modes (operator quick map)

| Error | Owner | First check |
|---|---|---|
| `focus_mismatch` | Realm config | `ak.realm.media_service.foci[]` shape |
| `unknown_focus_type` | Realm config / client profile | client's profile set; realm's advertised backend |
| `token_issuer_unauthorised` | Deployment | `issuer_kid` ↔ realm binding |
| `participant_binding_invalid` | Issuer or transport | round-trip canonical bytes against issuer log |
| `participant_id_unrecognised` | Client | canonical identity-string composition |
| `session_focus_already_committed` | Client | call already bound to another focus |
| `e2ee_key_source_unauthorised` | Backend | escalate to inkson; SFrame key derivation |
| `recording_artifact_pipeline_bypassed` | floria recording hook | canonical pipeline |
| `focus_unavailable_for_client` | Client profile | declared profile set vs realm focus backend |
