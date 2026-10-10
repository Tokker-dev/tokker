//! RFC 9457 problem+json errors (architecture section 6, issue #2).

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// The `type` URI of a problem that has no URI of its own to name (RFC
/// 9457 §4.2.1): a venture with no public URL, or a response rendered
/// outside any venture's context. The slug stays in the body's title and
/// in logs; callers branch on it where one exists.
pub const ABOUT_BLANK: &str = "about:blank";

/// An API error, serialized as `application/problem+json`.
///
/// `type` is the venture's stable slug URI (see
/// [`Problem::type_uri`]), `instance` is the request id, and the body
/// never leaks internals: 500s carry no stack, no source error, nothing
/// but the generic `internal` slug.
#[derive(Debug, Clone)]
pub struct Problem {
    pub slug: &'static str,
    pub status: StatusCode,
    pub title: &'static str,
    pub detail: Option<String>,
    pub instance: Option<String>,
    /// RFC 9457 §3.2 extension members, copied into the body beside the
    /// standard fields. A slug that carries structured data a caller acts
    /// on — a metered usage problem names its `meter`, `used` and
    /// `limit` (issue #588) — keeps it here, so it survives the harness's
    /// re-render under the serving venture's base, which rebuilds the body
    /// from the problem and nothing else. Boxed: inlined, the map would
    /// push `Problem` past clippy's 128-byte `result_large_err` limit and
    /// every `Result<_, Problem>` in the workspace would grow with it.
    extensions: Box<serde_json::Map<String, serde_json::Value>>,
}

impl Problem {
    pub fn new(def: &crate::problems::ProblemDef) -> Self {
        Self {
            slug: def.slug,
            status: def.status,
            title: def.title,
            detail: None,
            instance: None,
            extensions: Box::new(serde_json::Map::new()),
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Adds an RFC 9457 §3.2 extension member to the body.
    #[must_use]
    pub fn with_extension(
        mut self,
        name: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.extensions.insert(name.into(), value.into());
        self
    }

    /// Sets `instance` to the request's id.
    #[must_use]
    pub fn instance(mut self, request_id: &str) -> Self {
        self.instance = Some(request_id.to_string());
        self
    }

    pub fn internal() -> Self {
        Self::new(&crate::problems::SLUGS.internal)
    }

    pub fn validation_failed(detail: impl Into<String>) -> Self {
        Self::new(&crate::problems::SLUGS.validation_failed).with_detail(detail)
    }

    pub fn request_too_large() -> Self {
        Self::new(&crate::problems::SLUGS.request_too_large)
    }

    pub fn not_ready(detail: impl Into<String>) -> Self {
        Self::new(&crate::problems::SLUGS.not_ready).with_detail(detail)
    }

    pub fn not_found() -> Self {
        Self::new(&crate::problems::SLUGS.not_found)
    }

    /// The problem's `type` URI: the venture's base followed by the slug.
    ///
    /// The base is the *serving* venture's — [`crate::Venture::problem_type_base`]
    /// — never a constant of this crate: every venture names its problems
    /// under its own domain. A base of [`ABOUT_BLANK`] (the context-free
    /// default, and a venture with no public URL) yields `about:blank`
    /// itself: the slug has no URI to live under, and RFC 9457 §4.2.1
    /// reserves exactly that value.
    pub fn type_uri(&self, base: &str) -> String {
        if base == ABOUT_BLANK {
            return ABOUT_BLANK.to_owned();
        }
        format!("{base}{}", self.slug)
    }

    /// The RFC 9457 body, with `type` built under `base`. Shared by
    /// [`IntoResponse`] (the context-free default) and the harness layer
    /// that re-renders under the serving venture's base.
    pub(crate) fn body(&self, base: &str) -> serde_json::Value {
        let mut body = json!({
            "type": self.type_uri(base),
            "title": self.title,
            "status": self.status.as_u16(),
        });
        if let Some(detail) = &self.detail {
            body["detail"] = json!(detail);
        }
        if let Some(instance) = &self.instance {
            body["instance"] = json!(instance);
        }
        // Extension members ride the body last, so they cannot be mistaken
        // for (or overwrite) a standard field: the four above are the only
        // keys this crate writes, and a name colliding with one is the
        // caller's to avoid (RFC 9457 §3.2 keeps them disjoint).
        if let Some(object) = body.as_object_mut() {
            for (name, value) in self.extensions.iter() {
                object.insert(name.clone(), value.clone());
            }
        }
        body
    }

    /// Renders this problem as a response whose `type` names `base` — the
    /// serving venture's [`crate::Venture::problem_type_base`]. For a
    /// response built *outside* a harness router, where no layer stands
    /// behind it to name the venture: a runtime's pre-router short-circuit
    /// (the native host refusal, the Worker's body ceiling).
    pub fn into_response_with_base(self, base: &str) -> Response {
        let mut response = (self.status, Json(self.body(base))).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        // For the serving venture to re-render under its own base: a
        // response built here cannot know it. The harness's outermost
        // layer reads this extension; a response that reaches a caller
        // without one names `about:blank`, never another venture's domain.
        response.extensions_mut().insert(self);
        response
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        self.into_response_with_base(ABOUT_BLANK)
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} ({})",
            self.slug,
            self.title,
            self.status.as_u16()
        )
    }
}

impl std::error::Error for Problem {}

// Handler ergonomics: `?` on a port error inside a `Result<_, Problem>`
// handler maps to a generic 500 — the underlying error is logged by the
// caller, never exposed in the body (architecture section 6).
impl From<crate::ports::DbError> for Problem {
    fn from(error: crate::ports::DbError) -> Self {
        tracing::error!(error = %error, "database error mapped to internal problem");
        // wasm has no tracing dispatcher (it hangs the isolate), so also
        // forward the diagnostic to the runtime's sink — otherwise this 500 is
        // invisible on Workers (issue #107). DbError is sanitized for logs.
        crate::logging::forward_internal_error(&format!(
            "database error mapped to internal problem: {error}"
        ));
        Self::internal()
    }
}
