//! The no-network request helper (issue #9): `tower::ServiceExt::oneshot`
//! straight into the router.

use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use futures_core::Stream;
use serde_json::Value;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The same, carrying `Authorization: Bearer <token>`.
///
/// Every venture with a table whose access is not `public-read` needs
/// this, and so does every admin-guarded route — and the kit did not have
/// it, so three crates in this workspace each hand-rolled the same
/// builder over `tower::ServiceExt`. A venture cannot: `tower` is not one
/// of its dependencies, and telling an author to add one to test the
/// routes the harness generated is telling them to work around the kit.
///
/// # Panics
///
/// Panics when the router itself fails (never for ordinary responses).
pub async fn request_as(
    router: &axum::Router,
    method: Method,
    path: &str,
    bearer: &str,
    json: Option<&str>,
) -> TestResponse {
    use tower::ServiceExt;
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    let body = match json {
        Some(payload) => {
            builder = builder.header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Body::from(payload.to_owned())
        }
        None => Body::empty(),
    };
    let request = builder.body(body).expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    TestResponse::from(response).await
}

/// Sends a request through the router without a network. `json` (when
/// `Some`) becomes a JSON body with `content-type: application/json`.
///
/// # Panics
///
/// Panics when the router itself fails (never for ordinary responses).
pub async fn request(
    router: &axum::Router,
    method: Method,
    path: &str,
    json: Option<&str>,
) -> TestResponse {
    use tower::ServiceExt;
    let mut builder = Request::builder().method(method).uri(path);
    let body = match json {
        Some(payload) => {
            builder = builder.header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Body::from(payload.to_owned())
        }
        None => Body::empty(),
    };
    let request = builder.body(body).expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    TestResponse::from(response).await
}

/// Sends a request whose body is the given chunks, as a chunked
/// (no `content-length`) transfer — what a client uploading a stream
/// produces, and the only shape that exercises a route's
/// [`cratefield_core::RequestStream`] mid-stream ceiling rather than the
/// declared-length pre-check. `content-type` is set to
/// `application/octet-stream`.
///
/// # Panics
///
/// Panics when the router itself fails (never for ordinary responses).
pub async fn request_chunks(
    router: &axum::Router,
    method: Method,
    path: &str,
    chunks: Vec<Bytes>,
) -> TestResponse {
    use tower::ServiceExt;
    let body = Body::from_stream(Chunks {
        items: chunks.into_iter(),
    });
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )
        .body(body)
        .expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    TestResponse::from(response).await
}

/// A chunked request body: a `Vec<Bytes>` drained one chunk per poll. Written
/// out because the kit depends on `futures-core` only, not `futures-util`.
struct Chunks {
    items: std::vec::IntoIter<Bytes>,
}

impl Stream for Chunks {
    type Item = Result<Bytes, std::convert::Infallible>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().items.next().map(Ok))
    }
}

/// A fully-buffered test response.
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    body: Bytes,
}

impl TestResponse {
    /// Reads a response the caller drove itself (the conformance kit's
    /// parity probes build their own requests).
    pub(crate) async fn of(response: Response) -> Self {
        Self::from(response).await
    }

    async fn from(response: Response) -> Self {
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .expect("test body reads");
        Self {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }

    /// The body parsed as JSON.
    ///
    /// # Panics
    ///
    /// Panics when the body is not valid JSON.
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("body is JSON")
    }

    /// The raw body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }
}
