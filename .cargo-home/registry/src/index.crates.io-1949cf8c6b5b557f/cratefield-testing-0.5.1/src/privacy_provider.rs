//! [`FakePrivacyProvider`] (issue #653): an in-memory external subject-data
//! provider — the `HttpClient` a `Privacy` module calls on export and
//! erasure, with no network.
//!
//! It is the receiving end of the module's contract: it verifies
//! `Cratefield-Signature` with the core [`WebhookVerifier`] and
//! [`StripeStyle`], so a test proves the module signs what a real receiver
//! checks, and it holds per-subject sections an erasure can delete.

#![allow(clippy::disallowed_types)]
// Every accessor locks an unpoisoned fixture mutex; per-method `# Panics`
// sections would add noise without information (as `fakes.rs` records).
#![allow(clippy::missing_panics_doc)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{HttpClient, HttpError, StripeStyle, WebhookVerifier};
use http::{Request, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The header the module signs with; the fake verifies exactly this.
const SIGNATURE_HEADER: &str = "Cratefield-Signature";

/// One request a [`FakePrivacyProvider`] accepted, for assertions.
#[derive(Debug, Clone)]
pub struct ProviderCall {
    /// The request path: `/export`, `/erase/plan` or `/erase/apply`.
    pub path: String,
    /// The `request_id` the module sent, which a confirm and its retries share.
    pub request_id: String,
}

/// An in-memory external provider. Construct with its signing secret, hold
/// sections per subject ([`with_subject`](Self::with_subject)), and assert on
/// what it saw ([`calls`](Self::calls), [`applies`](Self::applies),
/// [`holds`](Self::holds)).
#[derive(Clone, Default)]
pub struct FakePrivacyProvider {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    secret: String,
    subjects: Mutex<BTreeMap<String, Value>>,
    retain: Mutex<BTreeMap<String, String>>,
    failure: Mutex<Option<(u16, String)>>,
    calls: Mutex<Vec<ProviderCall>>,
    applied: Mutex<BTreeMap<String, usize>>,
    signature_failures: AtomicUsize,
}

impl FakePrivacyProvider {
    /// A provider that signs with `secret`. A module configured with a
    /// different one has every call refused with 401.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Inner {
                secret: secret.into(),
                ..Inner::default()
            }),
        }
    }

    /// Holds `sections` (the `sections` array a real provider answers
    /// `/export` with) for `subject`.
    #[must_use]
    pub fn with_subject(&self, subject: &str, sections: Value) -> Self {
        self.inner
            .subjects
            .lock()
            .expect("provider lock")
            .insert(subject.to_owned(), sections);
        self.clone()
    }

    /// Plans `section` as `retain` rather than `delete`, with `reason`.
    #[must_use]
    pub fn retain_section(&self, section: &str, reason: &str) -> Self {
        self.inner
            .retain
            .lock()
            .expect("provider lock")
            .insert(section.to_owned(), reason.to_owned());
        self.clone()
    }

    /// Answers every call with `status` and `body`, after authentication.
    pub fn set_failure(&self, status: u16, body: &str) {
        *self.inner.failure.lock().expect("provider lock") = Some((status, body.to_owned()));
    }

    /// The whole provider is down: every call answers 503.
    pub fn set_down(&self, down: bool) {
        *self.inner.failure.lock().expect("provider lock") =
            down.then(|| (503, "provider down".to_owned()));
    }

    /// Every authenticated call, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<ProviderCall> {
        self.inner.calls.lock().expect("provider lock").clone()
    }

    /// How many times `request_id` effectively applied: 1 after the first
    /// apply, still 1 after a retry or a re-POST of the same confirm.
    #[must_use]
    pub fn applies(&self, request_id: &str) -> usize {
        self.inner
            .applied
            .lock()
            .expect("provider lock")
            .get(request_id)
            .copied()
            .unwrap_or(0)
    }

    /// Whether it still holds anything for `subject`.
    #[must_use]
    pub fn holds(&self, subject: &str) -> bool {
        self.inner
            .subjects
            .lock()
            .expect("provider lock")
            .contains_key(subject)
    }

    /// How many calls arrived with a signature this provider refused.
    #[must_use]
    pub fn signature_failures(&self) -> usize {
        self.inner.signature_failures.load(Ordering::SeqCst)
    }

    fn sections(&self, subject: &str) -> Value {
        self.inner
            .subjects
            .lock()
            .expect("provider lock")
            .get(subject)
            .cloned()
            .unwrap_or_else(|| json!([]))
    }

    fn plan(&self, subject: &str) -> Value {
        let sections = self.sections(subject);
        let retain = self.inner.retain.lock().expect("provider lock");
        let planned = sections
            .as_array()
            .into_iter()
            .flatten()
            .map(|section| {
                let name = section["name"].as_str().unwrap_or_default();
                match retain.get(name) {
                    Some(reason) => json!({ "name": name, "action": "retain", "reason": reason }),
                    None => json!({ "name": name, "action": "delete" }),
                }
            })
            .collect();
        Value::Array(planned)
    }

    /// Idempotent on `request_id`: a repeat of the same erase does nothing.
    fn apply(&self, subject: &str, request_id: &str) {
        let mut applied = self.inner.applied.lock().expect("provider lock");
        if applied.contains_key(request_id) {
            return;
        }
        self.inner
            .subjects
            .lock()
            .expect("provider lock")
            .remove(subject);
        applied.insert(request_id.to_owned(), 1);
    }
}

#[async_trait]
impl HttpClient for FakePrivacyProvider {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        if !WebhookVerifier::new(StripeStyle {
            header: SIGNATURE_HEADER,
        })
        .verify(&self.inner.secret, &parts.headers, &body, unix_now())
        {
            self.inner.signature_failures.fetch_add(1, Ordering::SeqCst);
            return response(401, "invalid signature");
        }
        if let Some((status, body)) = self.inner.failure.lock().expect("provider lock").clone() {
            return response(status, &body);
        }
        let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
            return response(400, "malformed body");
        };
        let subject = payload["subject"].as_str().unwrap_or_default().to_owned();
        let request_id = payload["request_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let path = parts.uri.path().to_owned();
        self.inner
            .calls
            .lock()
            .expect("provider lock")
            .push(ProviderCall {
                path: path.clone(),
                request_id: request_id.clone(),
            });

        if path.ends_with("/export") {
            return json_response(&json!({ "sections": self.sections(&subject) }));
        }
        if path.ends_with("/erase/plan") {
            return json_response(&json!({ "sections": self.plan(&subject) }));
        }
        if path.ends_with("/erase/apply") {
            self.apply(&subject, &request_id);
            return json_response(&json!({ "applied": true }));
        }
        response(404, "no such path")
    }
}

fn unix_now() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

fn response(status: u16, body: &str) -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(status)
        .body(Bytes::from(body.to_owned()))
        .map_err(|err| HttpError::Transport(err.to_string()))
}

fn json_response(value: &Value) -> Result<Response<Bytes>, HttpError> {
    response(200, &value.to_string())
}
