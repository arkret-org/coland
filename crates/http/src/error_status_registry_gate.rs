//! Registry gate for every statically visible error-code/status pairing.
//!
//! `api-conventions.md` 5.1 binds each top-level `error.code` to exactly one
//! registry HTTP status (or the registered per-context statuses). `AppError`
//! derives the status from its code, but source code can still pair a code
//! with a hand-written status (`StatusCode::X, "code"`), reclassify an error
//! whose constructor names a different status (`AppError::conflict(..)
//! .with_wire_code("claim_failed")`), or hand an unregistered string to a raw
//! renderer. This gate reads `registry/error-code-registry.json` directly and
//! scans every coland source file for those shapes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::ErrorCode;

/// Registry status set per active top-level code: the default status plus
/// every registered `http_status_by_context` value.
fn registry_statuses() -> BTreeMap<String, (u16, BTreeSet<u16>)> {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("arkret-spec artifacts checkout is required for the error status gate");
    let path = artifacts.join("registry/error-code-registry.json");
    let registry: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("error-code-registry.json is JSON");
    registry["codes"]
        .as_array()
        .expect("registry codes[]")
        .iter()
        .filter(|entry| entry["status"] == "active")
        .map(|entry| {
            let code = entry["code"].as_str().expect("code").to_owned();
            let default = u16::try_from(entry["http_status"].as_u64().expect("http_status"))
                .expect("u16 status");
            let mut allowed = BTreeSet::from([default]);
            if let Some(contexts) = entry["http_status_by_context"].as_object() {
                allowed.extend(contexts.values().map(|status| {
                    u16::try_from(status.as_u64().expect("context status")).expect("u16 status")
                }));
            }
            (code, (default, allowed))
        })
        .collect()
}

fn status_by_name(name: &str) -> Option<u16> {
    Some(match name {
        "OK" => 200,
        "BAD_REQUEST" => 400,
        "UNAUTHORIZED" => 401,
        "FORBIDDEN" => 403,
        "NOT_FOUND" => 404,
        "METHOD_NOT_ALLOWED" => 405,
        "NOT_ACCEPTABLE" => 406,
        "CONFLICT" => 409,
        "GONE" => 410,
        "PRECONDITION_FAILED" => 412,
        "PAYLOAD_TOO_LARGE" => 413,
        "UNSUPPORTED_MEDIA_TYPE" => 415,
        "RANGE_NOT_SATISFIABLE" => 416,
        "UNPROCESSABLE_ENTITY" => 422,
        "PRECONDITION_REQUIRED" => 428,
        "TOO_MANY_REQUESTS" => 429,
        "INTERNAL_SERVER_ERROR" => 500,
        "NOT_IMPLEMENTED" => 501,
        "BAD_GATEWAY" => 502,
        "SERVICE_UNAVAILABLE" => 503,
        "GATEWAY_TIMEOUT" => 504,
        _ => return None,
    })
}

fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|error| {
            panic!("read {}: {error}", dir.display());
        }) {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    walk(&crates, &mut files);
    files.sort();
    files
        .into_iter()
        .filter(|path| {
            // The AppError API and its own panic tests, and this gate's
            // pattern literals, are not producer sites.
            !path.ends_with("http/src/error.rs")
                && !path.ends_with("http/src/error_status_registry_gate.rs")
        })
        .collect()
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn ident_at(text: &str, start: usize) -> &str {
    let end = text[start..]
        .bytes()
        .position(|byte| !is_ident_byte(byte))
        .map_or(text.len(), |offset| start + offset);
    &text[start..end]
}

fn skip_ws(text: &str, mut index: usize) -> usize {
    while text
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

/// A code argument: a string literal, or a path ending in `ErrorCode::X`
/// (either an `ErrorCode` variant or its `&'static str` constant).
enum CodeArg {
    Literal(String),
    Code(ErrorCode),
    Dynamic,
}

fn variant_code(variant: &str) -> Option<ErrorCode> {
    ErrorCode::ALL
        .iter()
        .copied()
        .find(|code| format!("{code:?}") == variant)
}

fn parse_code_arg(text: &str, start: usize) -> CodeArg {
    let start = skip_ws(text, start);
    let rest = &text[start..];
    if let Some(literal) = rest.strip_prefix('"') {
        let end = literal.find('"').expect("closed string literal");
        return CodeArg::Literal(literal[..end].to_owned());
    }
    let path_end = rest
        .bytes()
        .position(|byte| !(is_ident_byte(byte) || byte == b':'))
        .unwrap_or(rest.len());
    let path = &rest[..path_end];
    let Some(name) = path.rsplit_once("ErrorCode::").map(|(_, name)| name) else {
        return CodeArg::Dynamic;
    };
    if name
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
    {
        return ErrorCode::from_wire(&name.to_ascii_lowercase())
            .map_or(CodeArg::Literal(name.to_ascii_lowercase()), CodeArg::Code);
    }
    variant_code(name).map_or(CodeArg::Dynamic, CodeArg::Code)
}

/// The nearest `AppError` constructor that begins the expression `.with_*`
/// is chained onto, if it is statically visible in the same statement.
fn base_code(prefix: &str) -> Option<ErrorCode> {
    const CONVENIENCE: &[(&str, ErrorCode)] = &[
        ("AppError::json_invalid(", ErrorCode::JsonInvalid),
        ("AppError::param_missing(", ErrorCode::ParamMissing),
        ("AppError::param_invalid(", ErrorCode::ParamInvalid),
        ("AppError::schema_violation(", ErrorCode::SchemaViolation),
        ("AppError::unauthenticated(", ErrorCode::Unauthenticated),
        ("AppError::capability_denied(", ErrorCode::CapabilityDenied),
        ("AppError::not_found(", ErrorCode::NotFound),
        ("AppError::conflict(", ErrorCode::Conflict),
        ("AppError::internal(", ErrorCode::InternalError),
        (
            "AppError::unsupported_feature(",
            ErrorCode::UnsupportedFeature,
        ),
        (
            "AppError::unsupported_content_encoding(",
            ErrorCode::UnsupportedContentEncoding,
        ),
    ];
    let window_start = prefix.len().saturating_sub(1500);
    let window_start = (window_start..prefix.len())
        .find(|index| prefix.is_char_boundary(*index))
        .unwrap_or(prefix.len());
    let window = &prefix[window_start..];
    let mut best: Option<(usize, ErrorCode)> = None;
    let mut consider = |position: usize, code: Option<ErrorCode>| {
        if let Some(code) = code
            && best.is_none_or(|(current, _)| position > current)
        {
            best = Some((position, code));
        }
    };
    for (needle, code) in CONVENIENCE {
        if let Some(position) = window.rfind(needle) {
            consider(position, Some(*code));
        }
    }
    for needle in [
        concat!("AppError::", "new("),
        "AppError::from_rejection(",
        "app_error!(",
    ] {
        if let Some(position) = window.rfind(needle) {
            let argument = &window[position + needle.len()..];
            let argument = argument.trim_start();
            let code = if needle == "app_error!(" {
                variant_code(ident_at(argument, 0))
            } else {
                match parse_code_arg(argument, 0) {
                    CodeArg::Code(code) => Some(code),
                    CodeArg::Literal(_) | CodeArg::Dynamic => None,
                }
            };
            consider(position, code);
        }
    }
    let (position, code) = best?;
    // A statement boundary between the constructor and the chained call means
    // the receiver is some other value.
    (!window[position..].contains(';')).then_some(code)
}

fn line_of(text: &str, index: usize) -> usize {
    text[..index].bytes().filter(|byte| *byte == b'\n').count() + 1
}

/// Split the top-level comma-separated arguments of a call whose opening
/// parenthesis ends at `open`.
fn call_arguments(text: &str, open: usize) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut arguments = Vec::new();
    let mut start = open;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index += 1;
                while bytes[index] != b'"' {
                    if bytes[index] == b'\\' {
                        index += 1;
                    }
                    index += 1;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => {
                arguments.push(text[start..index].trim());
                return arguments;
            }
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                arguments.push(text[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    arguments
}

#[test]
fn sdk_error_codes_match_the_registry_statuses() {
    let registry = registry_statuses();
    let sdk = ErrorCode::ALL
        .iter()
        .map(|code| code.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        sdk,
        registry.keys().cloned().collect::<BTreeSet<_>>(),
        "SDK ErrorCode must be exactly the registry's active top-level codes"
    );
    for code in ErrorCode::ALL {
        let (default, allowed) = &registry[code.as_str()];
        assert_eq!(code.http_status(), *default, "{code}");
        for context in arkret_wire::ErrorStatusContext::ALL {
            assert!(allowed.contains(&code.http_status_in(*context)), "{code}");
        }
    }
}

#[test]
fn every_static_error_code_status_pairing_matches_the_registry() {
    let registry = registry_statuses();
    let registered = |code: &str| registry.contains_key(code);
    let mut violations = Vec::new();

    for path in source_files() {
        let text = std::fs::read_to_string(&path).expect("read source");
        let display = path
            .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join(".."))
            .unwrap_or(&path)
            .display()
            .to_string();
        let event_lane = display.replace('\\', "/").contains("/routing/events/");

        // Rule A: wire-code reclassification names an active code, and the
        // statically visible constructor already carries that code's status.
        for method in [".with_wire_code(", ".with_rejection_code("] {
            for (index, _) in text.match_indices(method) {
                let argument = parse_code_arg(&text, index + method.len());
                let wire = match argument {
                    CodeArg::Literal(literal) if registered(&literal) => {
                        ErrorCode::from_wire(&literal).expect("registered code")
                    }
                    CodeArg::Literal(literal) => {
                        if method == ".with_wire_code(" {
                            violations.push(format!(
                                "{display}:{}: `{literal}` is not an active top-level code",
                                line_of(&text, index)
                            ));
                        }
                        continue;
                    }
                    CodeArg::Code(code) => code,
                    CodeArg::Dynamic => continue,
                };
                if let Some(base) = base_code(&text[..index])
                    && base.http_status() != wire.http_status()
                {
                    violations.push(format!(
                        "{display}:{}: `{base}` ({}) reclassified as `{wire}` ({})",
                        line_of(&text, index),
                        base.http_status(),
                        wire.http_status()
                    ));
                }
            }
        }

        // Rule B: a hand-written status next to an active code is that
        // code's registry status.
        for (index, _) in text.match_indices("StatusCode::") {
            let name_start = index + "StatusCode::".len();
            let name = ident_at(&text, name_start);
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
                continue;
            }
            let after = skip_ws(&text, name_start + name.len());
            if text.as_bytes().get(after) != Some(&b',') {
                continue;
            }
            let code = match parse_code_arg(&text, after + 1) {
                CodeArg::Literal(literal) => literal,
                CodeArg::Code(code) => code.as_str().to_owned(),
                CodeArg::Dynamic => continue,
            };
            // Outside the Event admission lanes (which map unregistered
            // discriminators through their status onto a registered code), a
            // `(status, code, ..)` tuple is rendered verbatim.
            let rendered_tuple = !event_lane && text[..index].trim_end().ends_with('(');
            let entry = registry.get(&code);
            if entry.is_none() && !rendered_tuple {
                continue;
            }
            let Some(status) = status_by_name(name) else {
                violations.push(format!(
                    "{display}:{}: unknown StatusCode::{name}; extend the gate table",
                    line_of(&text, index)
                ));
                continue;
            };
            match entry {
                Some((default, allowed)) if !allowed.contains(&status) => {
                    violations.push(format!(
                        "{display}:{}: `{code}` paired with {status}, registry status {default}",
                        line_of(&text, index)
                    ));
                }
                Some(_) => {}
                None => violations.push(format!(
                    "{display}:{}: tuple renders unregistered code `{code}`",
                    line_of(&text, index)
                )),
            }
        }

        // Rule C: raw renderers put their code argument on the wire verbatim.
        for renderer in [
            "render_error(",
            "render_error_with_detail(",
            "render_error_with_reason_code(",
        ] {
            for (index, _) in text.match_indices(renderer) {
                if index > 0 && is_ident_byte(text.as_bytes()[index - 1]) {
                    continue;
                }
                let arguments = call_arguments(&text, index + renderer.len());
                if let Some(code) = arguments
                    .get(2)
                    .and_then(|argument| argument.strip_prefix('"'))
                    .and_then(|argument| argument.strip_suffix('"'))
                    && !registered(code)
                {
                    violations.push(format!(
                        "{display}:{}: `{renderer}` renders unregistered code `{code}`",
                        line_of(&text, index)
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "error code/status pairings diverge from error-code-registry.json:\n{}",
        violations.join("\n")
    );
}
