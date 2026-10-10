//! `Dispatcher` over Workers service bindings (ADR 0009).
//!
//! Bindings are resolved once, when the runtime builds its ports, so
//! `has()` is a map lookup rather than a binding probe on the hot path.
//! Cloudflare requires a bound Worker to be on the same account as its
//! caller, which is what makes a customer-deployed sidecar work in the
//! customer-account mode and is why the hosted mode is still open (#67).

use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{DispatchError, Dispatcher};
use worker::js_sys::Uint8Array;
use worker::send::IntoSendFuture;
use worker::{Fetcher, Headers, Method, Request as WorkerRequest, RequestInit};

pub(crate) struct ServiceDispatcher(BTreeMap<String, Fetcher>);

impl ServiceDispatcher {
    #[must_use]
    pub(crate) fn new(bindings: BTreeMap<String, Fetcher>) -> Self {
        Self(bindings)
    }
}

#[async_trait]
impl Dispatcher for ServiceDispatcher {
    fn has(&self, binding: &str) -> bool {
        self.0.contains_key(binding)
    }

    async fn dispatch(
        &self,
        binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        let fetcher = self
            .0
            .get(binding)
            .ok_or_else(|| DispatchError::NotBound(binding.to_owned()))?;
        let unavailable = |err: worker::Error| DispatchError::Unavailable {
            binding: binding.to_owned(),
            reason: err.to_string(),
        };

        let (parts, body) = request.into_parts();
        let mut init = RequestInit::new();
        init.method = Method::from(parts.method.as_str().to_string());
        let headers = Headers::new();
        for (name, value) in &parts.headers {
            let _ = headers.set(name.as_str(), value.to_str().unwrap_or_default());
        }
        init.headers = headers;
        // Binary-safe, unlike the JSON-only `HttpClient` adapter: a sidecar
        // module owns its own routes and may accept any body the 64 KiB
        // `/v1/*` limit allows.
        if !body.is_empty() {
            init.with_body(Some(Uint8Array::from(body.as_ref()).into()));
        }

        // workerd refuses a relative URL in `new Request` — and the unit
        // tests, which dispatch through fakes, cannot see that — so the
        // path-only requests the event forwarder builds (`/__events`) died
        // here with "invalid URL for Request" on every real runtime while
        // every test stayed green (issue #258). A service binding's fetch
        // ignores the authority entirely, so a stand-in origin costs
        // nothing and makes the request fetchable; an absolute URL the
        // caller supplied is forwarded as-is.
        let target = match parts.uri.path_and_query() {
            Some(path_and_query) if parts.uri.host().is_none() => {
                format!("https://sidecar{path_and_query}")
            }
            _ => parts.uri.to_string(),
        };

        let worker_request = WorkerRequest::new_with_init(&target, &init).map_err(unavailable)?;
        let mut response = fetcher
            .fetch_request(worker_request)
            .into_send()
            .await
            .map_err(unavailable)?;

        let mut builder = http::Response::builder().status(response.status_code());
        if let Some(headers) = builder.headers_mut() {
            for (name, value) in response.headers() {
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::try_from(name.as_str()),
                    http::HeaderValue::try_from(value.as_str()),
                ) {
                    headers.insert(name, value);
                }
            }
        }
        let bytes = response.bytes().into_send().await.map_err(unavailable)?;
        builder
            .body(Bytes::from(bytes))
            .map_err(|err| DispatchError::Unavailable {
                binding: binding.to_owned(),
                reason: err.to_string(),
            })
    }
}
