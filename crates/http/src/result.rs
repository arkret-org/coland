//! Typed result aliases used by HTTP handlers.

use salvo::prelude::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// The canonical JSON result shape returned by typed handlers.
pub type JsonResult<T> = Result<Json<T>, AppError>;

/// Plain result for handlers that drive the response by hand.
pub type AppResult<T> = Result<T, AppError>;

/// Empty-payload handlers still emit a JSON object.
pub type EmptyResult = JsonResult<EmptyOutcome>;

/// Wrap a value in `Json` for `?`-friendly handler returns.
pub fn json_ok<T>(value: T) -> JsonResult<T> {
    Ok(Json(value))
}

/// Return the canonical empty JSON object.
pub fn empty_ok() -> EmptyResult {
    json_ok(EmptyOutcome {})
}

/// Marker response type used by [`empty_ok`].
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct EmptyOutcome {}

/// The SDK response retains its schema while its publication owns a live cut.
pub struct GuardedJson<T> {
    value: Result<T, arkret_wire::problem_details::Problem>,
    guard: Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>,
}

pub type GuardedJsonResult<T> = Result<GuardedJson<T>, AppError>;

pub fn guarded_json_ok<T>(
    value: T,
    guard: Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>,
) -> GuardedJsonResult<T> {
    Ok(GuardedJson {
        value: Ok(value),
        guard,
    })
}

/// Publish an authorized absence with the same held cut as a successful body.
pub fn guarded_json_not_found<T>(
    guard: Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>,
) -> GuardedJsonResult<T> {
    let error = AppError::not_found("document Morph not found");
    let problem = arkret_server::ProtocolRejection::new(error.code, error.message.to_string())
        .into_problem(arkret_identifiers::new_prefixed_uuid7("ak:request:"));
    Ok(GuardedJson {
        value: Err(problem),
        guard,
    })
}

impl<T: salvo::oapi::ToSchema> salvo::oapi::ToResponses for GuardedJson<T> {
    fn to_responses(components: &mut salvo::oapi::Components) -> salvo::oapi::Responses {
        <Json<T> as salvo::oapi::ToResponses>::to_responses(components)
    }
}

impl<T: salvo::oapi::ToSchema> salvo::oapi::EndpointOutRegister for GuardedJson<T> {
    fn register(components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        <Json<T> as salvo::oapi::EndpointOutRegister>::register(components, operation);
    }
}

impl<T: Serialize + Send> salvo::Scribe for GuardedJson<T> {
    fn render(self, res: &mut salvo::Response) {
        let (value, mut guard) = match (self.value, self.guard) {
            (Ok(value), None) => {
                salvo::Scribe::render(Json(value), res);
                return;
            }
            (Err(problem), None) => {
                let status = salvo::http::StatusCode::from_u16(problem.status)
                    .expect("registry status codes are valid HTTP statuses");
                crate::error::render_problem_envelope(res, status, problem);
                return;
            }
            (value, Some(guard)) => (value, guard),
        };
        let (value, content_type) = match value {
            Ok(value) => (
                arkret_canonical::canonical_json_bytes(&value),
                "application/json; charset=utf-8",
            ),
            Err(problem) => {
                res.status_code(
                    salvo::http::StatusCode::from_u16(problem.status)
                        .expect("registry status codes are valid HTTP statuses"),
                );
                (
                    arkret_canonical::canonical_json_bytes(&problem),
                    "application/problem+json",
                )
            }
        };
        let bytes = match value {
            Ok(bytes) => bytes::Bytes::from(bytes),
            Err(_) => {
                salvo::Scribe::render(salvo::http::StatusError::internal_server_error(), res);
                return;
            }
        };
        res.headers_mut().insert(
            salvo::http::header::CONTENT_TYPE,
            salvo::http::HeaderValue::from_static(content_type),
        );
        res.stream(async_stream::stream! {
            if !guard.prepare_handoff().await {
                yield Err(std::io::Error::other("content delivery time authority changed"));
                return;
            }
            yield Ok::<bytes::Bytes, std::io::Error>(bytes);
            if guard.finish().await.is_err() {
                yield Err(std::io::Error::other("content delivery cut could not be released"));
            }
        });
    }
}

#[cfg(test)]
mod guarded_publication_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use futures_util::StreamExt;
    use salvo::Scribe as _;

    use super::guarded_json_not_found;

    struct HeldGuard {
        permit: tokio::sync::OwnedSemaphorePermit,
        finished: Arc<AtomicBool>,
        allowed: bool,
    }
    #[async_trait::async_trait]
    impl coland_storage::AccountContentDeliveryGuard for HeldGuard {
        fn permits_handoff(&self) -> bool {
            self.allowed
        }
        async fn finish(self: Box<Self>) -> coland_storage::PersistenceResult<()> {
            self.finished.store(true, Ordering::SeqCst);
            drop(self.permit);
            Ok(())
        }
    }

    #[tokio::test]
    async fn authorized_absence_releases_cut_only_after_actual_404_body_frame() {
        let lock = Arc::new(tokio::sync::Semaphore::new(1));
        let finished = Arc::new(AtomicBool::new(false));
        let guard = HeldGuard {
            permit: lock.clone().acquire_owned().await.unwrap(),
            finished: finished.clone(),
            allowed: true,
        };
        let mut response = salvo::Response::new();
        guarded_json_not_found::<serde_json::Value>(Some(Box::new(guard)))
            .unwrap()
            .render(&mut response);
        assert_eq!(
            response.status_code,
            Some(salvo::http::StatusCode::NOT_FOUND)
        );
        assert!(lock.clone().try_acquire_owned().is_err());
        let mut body = response.take_body();
        let frame = body.next().await.unwrap().unwrap().into_data().unwrap();
        let problem: arkret_wire::problem_details::Problem =
            serde_json::from_slice(&frame).unwrap();
        assert_eq!(problem.error_code(), Some(arkret_wire::ErrorCode::NotFound));
        assert!(!finished.load(Ordering::SeqCst));
        assert!(lock.clone().try_acquire_owned().is_err());
        assert!(body.next().await.is_none());
        assert!(finished.load(Ordering::SeqCst));
        assert!(lock.clone().try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn changed_time_authority_never_yields_a_404_absence_body() {
        let lock = Arc::new(tokio::sync::Semaphore::new(1));
        let finished = Arc::new(AtomicBool::new(false));
        let guard = HeldGuard {
            permit: lock.clone().acquire_owned().await.unwrap(),
            finished: finished.clone(),
            allowed: false,
        };
        let mut response = salvo::Response::new();
        guarded_json_not_found::<serde_json::Value>(Some(Box::new(guard)))
            .unwrap()
            .render(&mut response);
        let mut body = response.take_body();
        assert!(body.next().await.unwrap().is_err());
        assert!(!finished.load(Ordering::SeqCst));
        drop(body);
        assert!(lock.clone().try_acquire_owned().is_ok());
    }
}
