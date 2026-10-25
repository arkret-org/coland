//! Coland error integration for canonical Arkret SDK error codes.
//!
//! Wire-form error codes are owned by `arkret_wire::ErrorCode`; this module
//! only adds coland-specific Salvo rendering and typed endpoint plumbing.

use salvo::async_trait;
use salvo::http::StatusCode;
use salvo::prelude::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct ErrorExposure {
    pub development_mode: bool,
}

/// Construct an [`AppError`] with a canonical [`ErrorCode`] variant.
///
/// Two forms:
///
/// ```ignore
/// // Plain (or captured-interpolation) message:
/// return Err(app_error!(ParamInvalid, "bad space_id"));
/// return Err(app_error!(ParamInvalid, "invalid space_id: {err}"));
///
/// // Explicit-args `format!` variant:
/// return Err(app_error!(ParamInvalid, "invalid space_id: {}", err));
/// ```
///
/// The first argument is a bare variant identifier resolved against
/// [`crate::error::ErrorCode`] (i.e. `ParamInvalid`, not
/// `ErrorCode::ParamInvalid`). When the message argument is a string
/// literal it is forwarded through `format!` so captured-arg
/// interpolation (`{var}`) works in the single-arg form as well.
/// Non-literal `String`/`&str` expressions are passed through unchanged.
///
/// This replaces the boilerplate
/// `AppError::new(ErrorCode::X, format!("...", ...))` pattern that
/// otherwise litters every handler module. Prefer the macro over
/// `AppError::new(...)` in new code.
#[macro_export]
macro_rules! app_error {
    ($code:ident, $fmt:literal $(, $($arg:tt)*)?) => {
        $crate::error::AppError::new(
            $crate::error::ErrorCode::$code,
            format!($fmt $(, $($arg)*)?),
        )
    };
    ($code:ident, $msg:expr $(,)?) => {
        $crate::error::AppError::new($crate::error::ErrorCode::$code, $msg)
    };
}

pub use arkret_wire::ErrorCode;

/// Convert the SDK registry status into Salvo's `StatusCode`.
pub fn error_http_status(code: ErrorCode) -> StatusCode {
    StatusCode::from_u16(code.http_status()).expect("registry status codes are valid HTTP statuses")
}

fn request_id() -> String {
    arkret_identifiers::new_prefixed_uuid7("ak:request:")
}

pub(crate) fn render_problem_envelope(
    res: &mut Response,
    status: StatusCode,
    envelope: arkret_wire::problem_details::Problem,
) {
    let problem = envelope.with_status(status.as_u16());
    let mut salvo_problem = salvo::http::Problem::new(status)
        .kind(problem.problem_type)
        .title(problem.title)
        .detail(problem.detail)
        .with_extensions(
            problem
                .extensions
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        );
    if let Some(instance) = problem.instance {
        salvo_problem = salvo_problem.instance(instance);
    }
    res.render(salvo_problem);
}

pub fn render_error(res: &mut Response, status: StatusCode, code: &str, message: &str) {
    render_problem_envelope(
        res,
        status,
        arkret_wire::problem_details::Problem::from_code(code, message).with_instance(request_id()),
    );
}

pub fn render_error_with_detail(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: &str,
    reason_detail: &str,
) {
    render_problem_envelope(
        res,
        status,
        arkret_wire::problem_details::Problem::from_code(code, message)
            .with_instance(request_id())
            .with_extension(
                "reason_detail",
                serde_json::Value::String(reason_detail.to_owned()),
            ),
    );
}

pub fn render_error_with_reason_code(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: &str,
    reason_code: &str,
    reason_detail: Option<&str>,
) {
    debug_assert!(
        arkret_wire::ReasonCode::is_registered(reason_code),
        "unregistered reason code `{reason_code}`; internal discriminators belong on the \
         `reason_detail` channel"
    );
    let mut envelope = arkret_wire::problem_details::Problem::from_code(code, message)
        .with_instance(request_id())
        .with_extension(
            "reason_code",
            serde_json::Value::String(reason_code.to_owned()),
        );
    if let Some(reason_detail) = reason_detail {
        envelope = envelope.with_extension(
            "reason_detail",
            serde_json::Value::String(reason_detail.to_owned()),
        );
    }
    render_problem_envelope(res, status, envelope);
}

/// Render an SDK-owned error code through coland's standard error envelope.
pub fn render_error_code(code: ErrorCode, res: &mut Response, message: &str) {
    render_error(res, error_http_status(code), code.as_str(), message);
}

#[cfg(test)]
#[path = "error_status_registry_gate.rs"]
mod status_registry_gate;

#[cfg(test)]
mod tests {
    use super::*;

    async fn rendered_error(error: AppError) -> (Option<StatusCode>, serde_json::Value) {
        use salvo::test::ResponseExt as _;

        let mut response = Response::new();
        error
            .write(&mut Request::new(), &mut Depot::new(), &mut response)
            .await;
        let status = response.status_code;
        let mut problem: serde_json::Value = response.take_json().await.unwrap();
        problem.as_object_mut().unwrap().remove("instance");
        (status, problem)
    }

    #[tokio::test]
    async fn non_enumerable_not_found_has_exact_public_bytes_without_request_instance() {
        use salvo::test::ResponseExt as _;
        let mut bodies = Vec::new();
        for development_mode in [false, true, false] {
            let error = AppError::indistinguishable_not_found("third-party invite unavailable");
            assert_eq!(error.code, ErrorCode::NotFound);
            let mut response = Response::new();
            let mut depot = Depot::new();
            depot.insert_typed(ErrorExposure { development_mode });
            error
                .write(&mut Request::new(), &mut depot, &mut response)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
            let body = response.take_string().await.unwrap();
            let problem: arkret_wire::problem_details::Problem =
                serde_json::from_str(&body).unwrap();
            assert_eq!(problem.error_code(), Some(ErrorCode::NotFound));
            assert!(problem.instance.is_none());
            assert!(problem.extensions.is_empty());
            bodies.push(body);
        }
        assert!(
            bodies
                .windows(2)
                .all(|bodies| bodies[0].as_bytes() == bodies[1].as_bytes())
        );
    }

    #[tokio::test]
    async fn typed_constructors_preserve_registered_wire_and_context() {
        for code in ErrorCode::ALL {
            for context in [
                None,
                Some(arkret_wire::ErrorStatusContext::SessionIssuanceOrRefresh),
            ] {
                let mut original = AppError::new(*code, "exact diagnostic");
                let mut typed = AppError::from_rejection(*code, "exact diagnostic");
                if let Some(context) = context {
                    original = original.with_status_context(context);
                    typed = typed.with_status_context(context);
                }
                assert_eq!(
                    rendered_error(original).await,
                    rendered_error(typed).await,
                    "{code:?} / {context:?}",
                );
            }
        }
        let original = AppError::new(ErrorCode::FailedPrecondition, "exact diagnostic")
            .with_reason_code(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        let typed = crate::app_error!(FailedPrecondition, "exact diagnostic")
            .with_reason_code(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING);
        assert_eq!(rendered_error(original).await, rendered_error(typed).await);
    }

    #[test]
    fn sdk_error_codes_are_coland_source_of_truth() {
        assert!(
            !ErrorCode::ALL.is_empty()
                && ErrorCode::ALL
                    .iter()
                    .all(|code| ErrorCode::from_wire(code.as_str()) == Some(*code)),
            "every SDK registry entry must round-trip through its wire code",
        );
        assert_eq!(
            ErrorCode::from_wire("json_invalid"),
            Some(ErrorCode::JsonInvalid)
        );
        assert_eq!(
            ErrorCode::from_wire("capability_denied"),
            Some(ErrorCode::CapabilityDenied),
        );
        assert_eq!(
            error_http_status(ErrorCode::JsonInvalid),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            error_http_status(ErrorCode::CapabilityDenied),
            StatusCode::FORBIDDEN,
        );
    }

    #[test]
    fn with_wire_code_accepts_registered_top_level_codes() {
        let error =
            AppError::new(ErrorCode::Conflict, "bad").with_wire_code(ErrorCode::CAS_CONFLICT);
        assert_eq!(error.wire_code(), "cas_conflict");
        assert_eq!(error.code, ErrorCode::CasConflict);
    }

    #[test]
    fn wire_code_reclassification_always_renders_the_registry_status() {
        for code in ErrorCode::ALL {
            for base in [
                ErrorCode::ParamInvalid,
                ErrorCode::Conflict,
                ErrorCode::InternalError,
            ] {
                let error = AppError::new(base, "bad").with_wire_code(code.as_str());
                assert_eq!(error.wire_code(), code.as_str());
                assert_eq!(error.http_status(), error_http_status(*code), "{code}");
                let error = AppError::new(base, "bad").with_rejection_code(code.as_str());
                assert_eq!(error.wire_code(), code.as_str());
                assert_eq!(error.http_status(), error_http_status(*code), "{code}");
            }
        }
        let error = AppError::new(ErrorCode::Conflict, "denied")
            .with_status_context(arkret_wire::ErrorStatusContext::SessionIssuanceOrRefresh)
            .with_wire_code(ErrorCode::ACCOUNT_DEACTIVATED);
        assert_eq!(error.http_status(), StatusCode::FORBIDDEN);
    }

    #[test]
    #[should_panic(expected = "unregistered top-level error code")]
    fn with_wire_code_rejects_reason_codes_in_debug_builds() {
        // `proof_invalid` is a registered reason code, never a top-level one:
        // `error.code` is the RFC 9457 `type` tail and is bound to `codes[]`.
        let _ = AppError::new(ErrorCode::ParamInvalid, "bad")
            .with_wire_code(arkret_wire::ReasonCode::PROOF_INVALID);
    }

    #[test]
    #[should_panic(expected = "unregistered top-level error code")]
    fn with_wire_code_rejects_internal_discriminators_in_debug_builds() {
        let _ = AppError::new(ErrorCode::Conflict, "bad").with_wire_code("some_internal_state");
    }

    #[test]
    fn with_reason_code_accepts_registered_reason_codes() {
        let error = AppError::new(ErrorCode::SchemaViolation, "bad")
            .with_reason_code(arkret_wire::ReasonCode::UNKNOWN_FIELD);
        assert_eq!(error.reason_code.as_deref(), Some("unknown_field"));
    }

    #[test]
    #[should_panic(expected = "unregistered reason code")]
    fn with_reason_code_rejects_unregistered_strings_in_debug_builds() {
        let _ = AppError::new(ErrorCode::SchemaViolation, "bad")
            .with_reason_code("some_internal_discriminator");
    }

    #[test]
    fn with_internal_reason_routes_by_registry_membership() {
        // Registered reason code → reason_code channel.
        let error = AppError::new(ErrorCode::SchemaViolation, "bad")
            .with_internal_reason(arkret_wire::ReasonCode::UNKNOWN_FIELD);
        assert_eq!(error.reason_code.as_deref(), Some("unknown_field"));
        assert_eq!(error.reason_detail, None);
        // Registered error code equal to error.code → dropped; error.code
        // already classifies it.
        let error = AppError::new(ErrorCode::SchemaViolation, "bad")
            .with_internal_reason("schema_violation");
        assert_eq!(error.reason_code, None);
        assert_eq!(error.reason_detail, None);
        // A *different* registered error code keeps its classifying value on
        // the unstable channel instead of being silently dropped.
        let error = AppError::new(ErrorCode::CapabilityDenied, "denied")
            .with_internal_reason(arkret_wire::ErrorCode::REALM_FROZEN);
        assert_eq!(error.reason_code, None);
        assert_eq!(error.reason_detail.as_deref(), Some("realm_frozen"));
        // Unregistered internal discriminator → unstable reason_detail.
        let error = AppError::new(ErrorCode::SchemaViolation, "bad")
            .with_internal_reason("some_internal_discriminator");
        assert_eq!(error.reason_code, None);
        assert_eq!(
            error.reason_detail.as_deref(),
            Some("some_internal_discriminator")
        );
    }
}

// ── AppError + typed-endpoint integration ────────────────────────────────
//
// `AppError` is the typed error returned by handlers. It carries
// a canonical [`ErrorCode`] (registry-locked), a human-readable message, and
// an optional registry status context. `Writer` is implemented so the same value drives runtime
// rendering.

/// Typed error returned by handlers.
#[derive(Debug, Clone)]
pub struct AppError {
    frozen_problem: Option<Box<arkret_wire::problem_details::Problem>>,
    pub code: ErrorCode,
    pub message: Box<str>,
    /// Registry context for codes whose status varies by trust surface.
    pub status_context: Option<arkret_wire::ErrorStatusContext>,
    /// Stable protocol reason code rendered as the top-level Problem `reason_code` extension.
    /// Registry-locked to `registry/reason-code-registry.json`;
    /// [`AppError::with_reason_code`] enforces the lock in debug builds.
    pub reason_code: Option<Box<str>>,
    /// Free-form diagnostic explaining *why* this error fired.
    ///
    /// Surfaced through the rendered Problem as
    /// the top-level Problem `reason_detail` extension so on-call has something more
    /// specific than the canonical `code` to grep for. The shape is
    /// intentionally `Option<String>` (no enum, no schema) because the
    /// string is unstable across releases — clients MUST NOT parse this value and may only log or
    /// display it.
    pub reason_detail: Option<Box<str>>,
    /// Deployment-local diagnostic that is rendered only in development mode.
    ///
    /// Privacy-sensitive endpoints use this field to retain the concrete
    /// rejection cause while returning the same indistinguishable protocol
    /// error in production. When `COLAND_DEVELOPMENT_MODE=true`, the writer
    /// exposes it as the unstable the top-level Problem `reason_detail` extension diagnostic.
    pub private_detail: Option<Box<str>>,
    /// Typed members flattened into the top-level Problem extensions.
    ///
    /// Boxed and optional because it is empty on the overwhelming majority of
    /// errors: inline, the map's three words push `AppError` past clippy's
    /// 128-byte `result_large_err` threshold and widen every `AppResult` in
    /// the crate. `None` costs one word and allocates nothing.
    pub wire_details: Option<Box<std::collections::BTreeMap<String, serde_json::Value>>>,
}

impl AppError {
    pub(crate) fn from_frozen_problem(problem: arkret_wire::problem_details::Problem) -> Self {
        let mut error = Self::new(ErrorCode::FailedPrecondition, problem.detail.clone());
        error.frozen_problem = Some(Box::new(problem));
        error
    }

    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::from(arkret_server::ProtocolRejection::new(code, message))
    }

    /// Adapt a dynamically selected registry code through the shared SDK
    /// rejection model. Static codes should use [`crate::app_error!`].
    pub fn from_rejection(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::from(arkret_server::ProtocolRejection::new(code, message))
    }

    pub fn with_status_context(mut self, context: arkret_wire::ErrorStatusContext) -> Self {
        self.status_context = Some(context);
        self
    }

    fn from_protocol_rejection(rejection: arkret_server::ProtocolRejection) -> Self {
        Self {
            frozen_problem: None,
            code: rejection.code(),
            message: rejection.message().to_owned().into_boxed_str(),
            status_context: rejection.status_context(),
            reason_code: None,
            reason_detail: None,
            private_detail: None,
            wire_details: (!rejection.details().is_empty())
                .then(|| Box::new(rejection.details().clone())),
        }
    }

    /// Reclassify the rejection under a registered top-level wire code.
    ///
    /// The value MUST be a registered member of
    /// `registry/error-code-registry.json` `codes[]`: `error.code` is the tail
    /// of the RFC 9457 `type` URI, and api-conventions.md 5.1 binds that tail
    /// to the registry. The code replaces [`Self::code`] outright, so the HTTP
    /// status is always the registry status of the code that reaches the wire;
    /// a wire code can never be rendered under another code's status. A
    /// registered `reason_codes[]` member is NOT a top-level code - route it
    /// through [`Self::with_reason_code`]; an internal discriminator belongs on
    /// [`Self::with_internal_reason`].
    pub fn with_wire_code(mut self, wire_code: impl AsRef<str>) -> Self {
        let wire_code = wire_code.as_ref();
        match ErrorCode::from_wire(wire_code) {
            Some(code) => self.code = code,
            None => {
                if cfg!(debug_assertions) {
                    panic!(
                        "unregistered top-level error code `{wire_code}`; a registered reason \
                         code belongs on `with_reason_code` and an internal discriminator on \
                         `with_internal_reason`"
                    );
                }
                self.attach_internal_reason(wire_code);
            }
        }
        self
    }

    /// Attach a stable protocol reason code without replacing `error.code`.
    ///
    /// The value MUST be a registered member of the `reason_codes[]` section of
    /// `registry/error-code-registry.json`; the SDK projection enforces this
    /// in debug builds so an unregistered string cannot silently reach the
    /// wire. Route strings of unknown provenance through
    /// [`Self::with_internal_reason`] instead.
    pub fn with_reason_code(mut self, reason_code: impl Into<String>) -> Self {
        self.attach_reason_code(reason_code);
        self
    }

    /// `&mut` variant of [`Self::with_reason_code`] for sites that build the
    /// error in place.
    pub(crate) fn attach_reason_code(&mut self, reason_code: impl Into<String>) {
        let reason_code = reason_code.into();
        debug_assert!(
            arkret_wire::ReasonCode::is_registered(&reason_code),
            "unregistered reason code `{reason_code}`; internal discriminators belong on \
             `with_internal_reason`"
        );
        self.reason_code = Some(reason_code.into_boxed_str());
    }

    /// Route a downstream rejection's discriminator across all three channels.
    ///
    /// A rejection that crosses a module boundary arrives as a bare string
    /// whose registry membership is only known at runtime: reducer and
    /// admission lanes mix registered top-level codes, registered reason codes
    /// and internal discriminators in one `&str`. Dispatching on membership
    /// here reclassifies the error under a registered top-level code (and its
    /// registry status) while an unregistered discriminator can no longer
    /// reach `error.code`.
    pub fn with_rejection_code(mut self, value: impl AsRef<str>) -> Self {
        let value = value.as_ref();
        match ErrorCode::from_wire(value) {
            Some(code) => self.code = code,
            None => self.attach_internal_reason(value),
        }
        self
    }

    /// Route a reason string of unknown provenance onto the right channel: a
    /// registered reason code is attached as the top-level Problem `reason_code` extension; a
    /// registered error code equal to this error's own code is dropped (the
    /// Problem `type` already classifies the rejection); anything
    /// else — an internal discriminator or a *different* registered error
    /// code — lands on the unstable `reason_detail` diagnostic channel rather
    /// than masquerading as a stable protocol reason code.
    pub fn with_internal_reason(mut self, reason: impl AsRef<str>) -> Self {
        self.attach_internal_reason(reason);
        self
    }

    /// `&mut` variant of [`Self::with_internal_reason`].
    pub(crate) fn attach_internal_reason(&mut self, reason: impl AsRef<str>) {
        let reason = reason.as_ref();
        if arkret_wire::ReasonCode::is_registered(reason) {
            self.attach_reason_code(reason);
        } else if ErrorCode::from_wire(reason) != Some(self.code) {
            self.reason_detail = Some(reason.into());
        }
    }

    /// Attach a free-form diagnostic. See [`AppError::reason_detail`].
    ///
    /// The value is rendered into the wire envelope at
    /// the top-level Problem `reason_detail` extension and the OpenAPI schema annotates
    /// it as unstable / opaque.
    pub fn with_reason_detail(mut self, reason_detail: impl Into<String>) -> Self {
        self.reason_detail = Some(reason_detail.into().into_boxed_str());
        self
    }

    /// Attach a deployment-local diagnostic without changing the response.
    #[must_use]
    pub fn with_private_detail(mut self, private_detail: impl Into<String>) -> Self {
        self.private_detail = Some(private_detail.into().into_boxed_str());
        self
    }

    #[must_use]
    pub fn with_wire_detail(
        mut self,
        key: impl Into<String>,
        value: impl serde::Serialize,
    ) -> Self {
        if let Ok(value) = serde_json::to_value(value) {
            self.wire_details
                .get_or_insert_with(Box::default)
                .insert(key.into(), value);
        }
        self
    }

    /// Resolve the HTTP status from the canonical registry binding.
    pub fn http_status(&self) -> StatusCode {
        let status = self.status_context.map_or_else(
            || self.code.http_status(),
            |context| self.code.http_status_in(context),
        );
        StatusCode::from_u16(status).expect("registry status codes are valid HTTP statuses")
    }

    /// The Problem `type` URI tail: always the registered [`Self::code`].
    pub fn wire_code(&self) -> &str {
        self.code.as_str()
    }

    // ── Convenience constructors for the most-used codes. The full
    // `ErrorCode` set is always available via `AppError::new(code, msg)`.

    pub fn json_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::JsonInvalid, message)
    }
    pub fn param_missing(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ParamMissing, message)
    }
    pub fn param_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ParamInvalid, message)
    }
    /// Parsed input outside the declared schema contract: `schema_violation`
    /// at its registry status (422), never a `param_invalid` 400 renamed.
    pub fn schema_violation(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::SchemaViolation, message)
    }
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthenticated, message)
    }
    pub fn capability_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::CapabilityDenied, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    /// Freeze the public rejection for a non-enumerable lookup. Per-request
    /// correlation stays in transport/audit metadata rather than this body.
    pub fn indistinguishable_not_found(message: impl Into<String>) -> Self {
        let mut error = Self::not_found(message);
        error.frozen_problem = Some(Box::new(
            arkret_wire::problem_details::Problem::from_code(
                ErrorCode::NotFound.as_str(),
                error.message.as_ref(),
            )
            .with_status(ErrorCode::NotFound.http_status()),
        ));
        error
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, message)
    }
    pub fn unsupported_feature(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedFeature, message)
    }
    /// HTTP 415 for a canonical non-streaming JSON operation that carried a
    /// `Content-Encoding` header. See `zh/conformance/scalability-constraints.md` §2.1.4.
    pub fn unsupported_content_encoding(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedContentEncoding, message)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AppError {}

impl From<ErrorCode> for AppError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code, "")
    }
}

impl From<arkret_server::ProtocolRejection> for AppError {
    fn from(rejection: arkret_server::ProtocolRejection) -> Self {
        Self::from_protocol_rejection(rejection)
    }
}

#[async_trait]
impl Writer for AppError {
    async fn write(self, _req: &mut Request, depot: &mut Depot, res: &mut Response) {
        if let Some(problem) = self.frozen_problem.as_ref() {
            let status =
                StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            render_problem_envelope(res, status, (**problem).clone());
            return;
        }

        let status = self.http_status();
        let wire = self.wire_code().to_owned();
        let development_mode = depot
            .get_typed::<ErrorExposure>()
            .map(|exposure| exposure.development_mode)
            .unwrap_or(false);
        let redact_internal = self.code == ErrorCode::InternalError && !development_mode;
        if development_mode {
            tracing::warn!(
                status = status.as_u16(),
                wire_code = %wire,
                error_code = %self.code.as_str(),
                message = %self.message,
                reason_code = self.reason_code.as_deref(),
                reason_detail = self.reason_detail.as_deref(),
                private_detail = self.private_detail.as_deref(),
                "detailed application error"
            );
        } else if redact_internal {
            tracing::error!(
                status = status.as_u16(),
                wire_code = %wire,
                internal_message = %self.message,
                "internal error response redacted"
            );
        }
        let public_message = if redact_internal {
            "internal error"
        } else {
            self.message.as_ref()
        };
        // `private_detail` carries the useful cause for privacy-preserving
        // production errors such as Direct Conversation precondition failures.
        // Keep production responses indistinguishable, but make an explicitly
        // development-mode server actionable from the browser's response body.
        let wire_reason_detail = self.reason_detail.as_deref().or_else(|| {
            development_mode
                .then_some(self.private_detail.as_deref())
                .flatten()
        });
        if let Some(wire_details) = self.wire_details.filter(|details| !details.is_empty()) {
            let mut envelope =
                arkret_wire::problem_details::Problem::from_code(&wire, public_message)
                    .with_instance(request_id());
            for (key, value) in *wire_details {
                envelope = envelope.with_extension(key, value);
            }
            if let Some(reason_code) = self.reason_code.as_deref() {
                envelope = envelope.with_extension(
                    "reason_code",
                    serde_json::Value::String(reason_code.to_owned()),
                );
            }
            if let Some(reason_detail) = wire_reason_detail {
                envelope = envelope.with_extension(
                    "reason_detail",
                    serde_json::Value::String(reason_detail.to_owned()),
                );
            }
            render_problem_envelope(res, status, envelope);
        } else if let Some(reason_code) = self.reason_code.as_deref() {
            render_error_with_reason_code(
                res,
                status,
                &wire,
                public_message,
                reason_code,
                wire_reason_detail,
            );
        } else if let Some(reason_detail) = wire_reason_detail {
            render_error_with_detail(res, status, &wire, public_message, reason_detail);
        } else {
            render_error(res, status, &wire, public_message);
        }
    }
}

// `#[endpoint]` handlers return `Result<Json<T>, AppError>`; salvo-oapi already
// registers the `Ok` arm through `Json<T>`, and calls `EndpointOutRegister` on
// the error arm so the generated document advertises the failure shape. Every
// handler renders the same canonical RFC 9457 [`Problem`], so a single `default`
// response carrying that schema is the accurate contract regardless of which
// `ErrorCode` fired at runtime.
impl salvo::oapi::EndpointOutRegister for AppError {
    fn register(components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        let schema =
            <arkret_wire::problem_details::Problem as salvo::oapi::ToSchema>::to_schema(components);
        operation.responses.insert(
            "default",
            salvo::oapi::Response::new("Arkret RFC 9457 Problem Details")
                .add_content("application/problem+json", schema),
        );
    }
}
