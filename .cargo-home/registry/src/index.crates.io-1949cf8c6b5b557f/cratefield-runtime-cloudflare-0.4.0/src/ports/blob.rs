//! [`Blob`] over a Cloudflare R2 bucket (issue #105). Small media on Workers:
//! a coach's voice clip, served to members.
//!
//! [`Blob::put`], [`get`](Blob::get) and [`delete`](Blob::delete) go through
//! the Worker binding; the two presign methods go through R2's S3-compatible
//! API instead (issue #622) — a different endpoint with its own credentials.
//! They work only when the venture called
//! [`Cloudflare::blob_presign`](crate::Cloudflare::blob_presign) **and** the
//! four named values are present and non-empty in the Worker `Env` at request
//! time; otherwise both answer [`BlobError::Unsupported`] and the bytes are
//! served through [`Blob::get`].
//!
//! Presigning is pure — no binding, no network. A presigned `PUT` cannot cap
//! the size (the signature covers headers, not the body) but can pin an exact
//! `Content-Length`. Never log a presigned URL: its query string is a bearer
//! credential until it expires.
//!
//! **Verification.** Like every Workers adapter this is build-checked here and
//! must be exercised in `wrangler dev` against a real bucket before it is
//! trusted (issue #105 acceptance) — cargo tests never touch R2.

use async_trait::async_trait;
use cratefield_core::sigv4::{self, Credentials, SignableRequest};
use cratefield_core::{Blob, BlobError, BlobObject, Clock, PresignedPut, check_blob_size};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use worker::send::IntoSendFuture;
use worker::{Bucket, HttpMetadata};

/// R2's S3-compatible API signs for the `auto` region and the `s3` service.
const R2_REGION: &str = "auto";
const R2_SERVICE: &str = "s3";

fn op_err(err: &worker::Error) -> BlobError {
    BlobError::Operation(err.to_string())
}

/// The refusal both presign methods answer when presigning is off:
/// `.blob_presign` was never called, or a value it named is missing or empty.
fn unsupported_presign() -> BlobError {
    BlobError::Unsupported(
        "R2 presigning needs the S3-compatible API and its access keys; configure \
         Cloudflare::blob_presign(account_id, access_key_id, secret_access_key, bucket), \
         or serve the bytes through the harness"
            .to_owned(),
    )
}

/// The presigning seam, or the shared refusal when it is absent. Free so the
/// `Unsupported` path is testable without a `worker::Bucket`.
fn presigner(presigner: Option<&R2Presigner>) -> Result<&R2Presigner, BlobError> {
    presigner.ok_or_else(unsupported_presign)
}

/// The signing seam (issue #622): everything a presigned URL needs except the
/// Worker binding, so it is unit-testable natively (`worker::Bucket` cannot be
/// built off-wasm). Its [`fmt::Debug`] prints the account, bucket and access
/// key id — never the secret.
pub(crate) struct R2Presigner {
    account_id: String,
    bucket: String,
    credentials: Credentials,
    clock: Arc<dyn Clock>,
}

impl R2Presigner {
    pub(crate) fn new(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
        credentials: Credentials,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            bucket: bucket.into(),
            credentials,
            clock,
        }
    }

    /// Presigns `method` on `key` for `ttl`, signing `headers` exactly as
    /// given: host `<account>.r2.cloudflarestorage.com`, path
    /// `/<bucket>/<encoded key>`. Pure; time comes from the [`Clock`] port.
    fn sign(&self, method: &str, key: &str, headers: &[(String, String)], ttl: Duration) -> String {
        let host = format!("{}.r2.cloudflarestorage.com", self.account_id);
        let path = format!("/{}{}", self.bucket, sigv4::s3_key_path(key));
        sigv4::presign(
            &self.credentials,
            R2_REGION,
            R2_SERVICE,
            &SignableRequest {
                method,
                host: &host,
                path: &path,
                query: &[],
                headers,
            },
            ttl.as_secs().max(1),
            self.clock.now(),
        )
    }

    /// A presigned `GET` for `key`.
    fn signed_url(&self, key: &str, ttl: Duration) -> String {
        self.sign("GET", key, &[], ttl)
    }

    /// A presigned `PUT` for `key`. Signs `content-type`, and `content-length`
    /// too when given, and returns both for the client to send back exactly.
    fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: Duration,
    ) -> PresignedPut {
        let mut headers = vec![("content-type".to_owned(), content_type.to_owned())];
        if let Some(length) = content_length {
            headers.push(("content-length".to_owned(), length.to_string()));
        }
        PresignedPut {
            url: self.sign("PUT", key, &headers, ttl),
            method: "PUT",
            headers,
        }
    }
}

impl fmt::Debug for R2Presigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Credentials`' own `Debug` prints the access key id and redacts the
        // secret, so this can safely include it.
        f.debug_struct("R2Presigner")
            .field("account_id", &self.account_id)
            .field("bucket", &self.bucket)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

/// A [`Blob`] store over an R2 bucket binding, plus the presigning seam when
/// the venture configured one: `None` leaves both presign methods
/// [`BlobError::Unsupported`] and touches no network.
pub(crate) struct R2Blob {
    bucket: Bucket,
    presigner: Option<R2Presigner>,
}

impl R2Blob {
    pub(crate) fn new(bucket: Bucket, presigner: Option<R2Presigner>) -> Self {
        Self { bucket, presigner }
    }
}

#[async_trait]
impl Blob for R2Blob {
    async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError> {
        check_blob_size(bytes)?;
        self.bucket
            .put(key, bytes.to_vec())
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.to_owned()),
                ..Default::default()
            })
            .execute()
            .into_send()
            .await
            .map(|_| ())
            .map_err(|err| op_err(&err))
    }

    async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError> {
        let Some(object) = self
            .bucket
            .get(key)
            .execute()
            .into_send()
            .await
            .map_err(|err| op_err(&err))?
        else {
            return Ok(None);
        };
        let content_type = object
            .http_metadata()
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        let bytes = match object.body() {
            Some(body) => body.bytes().into_send().await.map_err(|err| op_err(&err))?,
            None => Vec::new(),
        };
        Ok(Some(BlobObject {
            bytes,
            content_type,
        }))
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        self.bucket
            .delete(key)
            .into_send()
            .await
            .map_err(|err| op_err(&err))
    }

    async fn signed_url(&self, key: &str, ttl: Duration) -> Result<String, BlobError> {
        Ok(presigner(self.presigner.as_ref())?.signed_url(key, ttl))
    }

    async fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: Duration,
    ) -> Result<PresignedPut, BlobError> {
        Ok(presigner(self.presigner.as_ref())?.signed_put_url(
            key,
            content_type,
            content_length,
            ttl,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cratefield_core::sigv4::{SigV4Error, verify_presigned};
    use time::OffsetDateTime;

    const ACCESS_KEY: &str = "AKIAEXAMPLE";
    const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    /// A key whose space must be percent-encoded, so the test pins the path
    /// shape rather than a trivially-safe key.
    const KEY: &str = "renders/job 1/out.mp4";
    const PATH: &str = "/media/renders/job%201/out.mp4";

    /// A clock frozen at one instant, so a test can verify at a later one to
    /// prove expiry. (`cratefield-testing`'s `FixedClock` sits behind a feature
    /// this crate's dev-dependencies do not carry.)
    struct TestClock(OffsetDateTime);

    #[async_trait]
    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    /// A valid test timestamp, read as UTC.
    fn at(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> OffsetDateTime {
        let date =
            time::Date::from_calendar_date(year, time::Month::try_from(month).expect("month"), day)
                .expect("a valid test date");
        let time = time::Time::from_hms(hour, minute, second).expect("a valid test time");
        time::PrimitiveDateTime::new(date, time).assume_utc()
    }

    fn credentials() -> Credentials {
        Credentials::new(ACCESS_KEY, SECRET_KEY)
    }

    fn presigner_at(now: OffsetDateTime) -> R2Presigner {
        R2Presigner::new("acct123", "media", credentials(), Arc::new(TestClock(now)))
    }

    #[test]
    fn a_signed_get_url_has_the_r2_shape_and_verifies() {
        let now = at(2026, 1, 1, 0, 0, 0);
        let url = presigner_at(now).signed_url(KEY, Duration::from_secs(600));
        assert!(
            url.starts_with(&format!("https://acct123.r2.cloudflarestorage.com{PATH}?")),
            "{url}"
        );
        verify_presigned(&url, "GET", &[], &credentials(), R2_REGION, R2_SERVICE, now)
            .expect("the URL verifies against the same credentials");
    }

    #[test]
    fn a_signed_put_url_signs_content_type_and_length() {
        let now = at(2026, 1, 1, 0, 0, 0);
        let put = presigner_at(now).signed_put_url(
            KEY,
            "video/mp4",
            Some(1024),
            Duration::from_secs(600),
        );
        assert_eq!(put.method, "PUT");
        assert_eq!(
            put.headers,
            vec![
                ("content-type".to_owned(), "video/mp4".to_owned()),
                ("content-length".to_owned(), "1024".to_owned()),
            ]
        );
        verify_presigned(
            &put.url,
            "PUT",
            &put.headers,
            &credentials(),
            R2_REGION,
            R2_SERVICE,
            now,
        )
        .expect("the signed headers verify");
    }

    #[test]
    fn a_url_is_refused_after_it_expires() {
        let url = presigner_at(at(2026, 1, 1, 0, 0, 0)).signed_url(KEY, Duration::from_secs(600));
        let verify_at =
            |now| verify_presigned(&url, "GET", &[], &credentials(), R2_REGION, R2_SERVICE, now);
        // The deadline itself (signed_at + 600s) is still valid; a second later
        // is not.
        verify_at(at(2026, 1, 1, 0, 10, 0)).expect("the deadline itself still verifies");
        assert_eq!(
            verify_at(at(2026, 1, 1, 0, 10, 1)),
            Err(SigV4Error::Expired)
        );
    }

    #[test]
    fn presigning_is_unsupported_without_a_presigner() {
        // Both presign methods share this refusal: no seam means `Unsupported`.
        assert!(matches!(presigner(None), Err(BlobError::Unsupported(_))));
        assert!(presigner(Some(&presigner_at(at(2026, 1, 1, 0, 0, 0)))).is_ok());
    }
}
