//! The registry of every problem slug the harness can emit (architecture
//! section 6): stable `type` URIs, statuses and descriptions. Modules add
//! their own slugs as `const ProblemDef`s in the same shape, and every
//! slug — core's and modules' — must be unique workspace-wide:
//! `errors-doc` collects the definitions from source and fails CI on a
//! slug defined twice (issue #419).

use axum::http::StatusCode;

/// Definition of one problem slug.
#[derive(Debug, Clone, Copy)]
pub struct ProblemDef {
    /// Last path segment of the `type` URI.
    pub slug: &'static str,
    pub status: StatusCode,
    /// Short, stable human title (RFC 9457 `title`).
    pub title: &'static str,
    /// One-line description for reviewers; not part of the response.
    pub description: &'static str,
}

/// Every slug core emits. Keep sorted by status.
pub struct Slugs {
    /// 400: a request body/query did not deserialize or failed validation.
    pub validation_failed: ProblemDef,
    /// 400: a captcha token was missing or rejected.
    pub captcha_failed: ProblemDef,
    /// 400: a signed link/token is malformed, tampered or expired.
    pub invalid_token: ProblemDef,
    /// 400: the request named a resource outside the configured set
    /// (e.g. an unknown waitlist product).
    pub unknown_product: ProblemDef,
    /// 401: a credential was presented and did not verify, or none was
    /// presented where one is required. The one 401 for every
    /// unauthenticated caller — the auth-client bearer check, the tables
    /// API's access decision and the modules reusing them all answer
    /// with it.
    pub unauthenticated: ProblemDef,
    /// 401: admin endpoints are disabled (`ADMIN_TOKEN` unset) or the
    /// request carried no bearer token.
    pub admin_unauthorized: ProblemDef,
    /// 401: a developer API key was missing, malformed, unknown, revoked
    /// or failed its hash check — one uniform answer for all five, so a
    /// probe cannot tell which (issue #532).
    pub api_key_unauthorized: ProblemDef,
    /// 403: the presented API key is valid but lacks the scope the route
    /// requires (issue #532).
    pub api_key_forbidden: ProblemDef,
    /// 403: the presented admin token is wrong.
    pub admin_forbidden: ProblemDef,
    /// 401: a request reached a sidecar-guarded route (`/v1/*` or
    /// `/__surface` on a sidecar that requires it) without a valid gateway
    /// token from the trusted host (issue #131).
    pub sidecar_unauthorized: ProblemDef,
    /// 503: the deployment declares production but cannot satisfy the
    /// abuse controls its own routes declare, so the guarded routes are
    /// refused rather than served unprotected (issue #143).
    pub not_production_ready: ProblemDef,
    /// 413: the request body exceeded the 64 KiB `/v1/*` limit.
    pub request_too_large: ProblemDef,
    /// 429: the rate limit for this IP or address was exceeded.
    pub rate_limited: ProblemDef,
    /// 429: a metered allowance is spent for the current period (issue
    /// #588). A quota, not a throttle: the subject must wait for the
    /// period to roll over, which `Retry-After` names.
    pub allowance_exhausted: ProblemDef,
    /// 404: no route matched.
    pub not_found: ProblemDef,
    /// 500: unhandled error; body carries no internals.
    pub internal: ProblemDef,
    /// 503: the mailer is not configured (no API key / unverified sending
    /// domain); forms should degrade to a direct address.
    pub mail_not_configured: ProblemDef,
    /// 503: readiness probe failed (`/__ready`): database missing, slow or
    /// erroring.
    pub not_ready: ProblemDef,
    /// 404: the request's host resolves to no tenant in the registry. A
    /// 404 and not a 403: which hosts are tenants is not a secret worth
    /// a distinguishable answer, and "no such tenant" is the truth
    /// (RECONCILIATION.md §6, TENANT-ROUTING.md §3).
    pub unknown_tenant: ProblemDef,
    /// 503: a sidecar-mounted module could not be reached (ADR 0009). Only
    /// that prefix fails; every in-process module keeps serving.
    pub sidecar_unavailable: ProblemDef,
    /// 503: a sidecar answered with a different `HARNESS_API` than this
    /// harness speaks, so its responses cannot be trusted.
    pub sidecar_contract_mismatch: ProblemDef,
    /// 503: the request's tenant is in the registry but `degraded` — its
    /// schema is behind or its database is unreachable, so serving it
    /// would read a shape the code no longer expects
    /// (RECONCILIATION.md §6, TENANT-ROUTING.md §3).
    pub tenant_degraded: ProblemDef,
}

pub const SLUGS: Slugs = Slugs {
    validation_failed: ProblemDef {
        slug: "validation-failed",
        status: StatusCode::BAD_REQUEST,
        title: "Request validation failed",
        description: "The request body or query did not deserialize into a valid request.",
    },
    captcha_failed: ProblemDef {
        slug: "captcha-failed",
        status: StatusCode::BAD_REQUEST,
        title: "Captcha verification failed",
        description: "The captcha token was missing or rejected; retry the challenge.",
    },
    invalid_token: ProblemDef {
        slug: "invalid-token",
        status: StatusCode::BAD_REQUEST,
        title: "Invalid or expired token",
        description: "A signed link or token is malformed, tampered with, or expired.",
    },
    unknown_product: ProblemDef {
        slug: "unknown-product",
        status: StatusCode::BAD_REQUEST,
        title: "Unknown product",
        description: "The named product is not on this waitlist.",
    },
    unauthenticated: ProblemDef {
        slug: "unauthenticated",
        status: StatusCode::UNAUTHORIZED,
        title: "Not authenticated",
        description: "A credential was presented and did not verify, or none was presented where one is required.",
    },
    admin_unauthorized: ProblemDef {
        slug: "admin-unauthorized",
        status: StatusCode::UNAUTHORIZED,
        title: "Admin access unauthorized",
        description: "Admin endpoints are disabled or the request has no bearer token.",
    },
    api_key_unauthorized: ProblemDef {
        slug: "api-key-unauthorized",
        status: StatusCode::UNAUTHORIZED,
        title: "API key unauthorized",
        description: "The request's API key was missing, malformed, unknown, revoked or invalid; one uniform answer for all five.",
    },
    api_key_forbidden: ProblemDef {
        slug: "api-key-forbidden",
        status: StatusCode::FORBIDDEN,
        title: "API key lacks the required scope",
        description: "The presented API key is valid but does not carry the scope this route requires.",
    },
    admin_forbidden: ProblemDef {
        slug: "admin-forbidden",
        status: StatusCode::FORBIDDEN,
        title: "Admin token rejected",
        description: "The presented admin token is wrong.",
    },
    sidecar_unauthorized: ProblemDef {
        slug: "sidecar-unauthorized",
        status: StatusCode::UNAUTHORIZED,
        title: "Unauthorized sidecar caller",
        description: "A request to a sidecar-guarded route could not be established as coming from the trusted gateway.",
    },
    not_production_ready: ProblemDef {
        slug: "not-production-ready",
        status: StatusCode::SERVICE_UNAVAILABLE,
        title: "Not ready for production traffic",
        description: "This deployment declares production but cannot satisfy the abuse controls its routes declare.",
    },
    request_too_large: ProblemDef {
        slug: "request-too-large",
        status: StatusCode::PAYLOAD_TOO_LARGE,
        title: "Request body too large",
        description: "The request body exceeded the 64 KiB limit for /v1 endpoints.",
    },
    rate_limited: ProblemDef {
        slug: "rate-limited",
        status: StatusCode::TOO_MANY_REQUESTS,
        title: "Rate limit exceeded",
        description: "Too many requests from this IP or address; retry after the pause.",
    },
    allowance_exhausted: ProblemDef {
        slug: "usage/allowance-exhausted",
        status: StatusCode::TOO_MANY_REQUESTS,
        title: "Usage allowance exhausted",
        description: "The subject's metered allowance is spent for the current period; retry after the period resets.",
    },
    not_found: ProblemDef {
        slug: "not-found",
        status: StatusCode::NOT_FOUND,
        title: "Not found",
        description: "No route matched the request.",
    },
    unknown_tenant: ProblemDef {
        slug: "unknown-tenant",
        status: StatusCode::NOT_FOUND,
        title: "Unknown tenant",
        description: "The request's host resolves to no tenant in the registry.",
    },
    internal: ProblemDef {
        slug: "internal",
        status: StatusCode::INTERNAL_SERVER_ERROR,
        title: "Internal error",
        description: "Unhandled error; no internals are exposed in the body.",
    },
    mail_not_configured: ProblemDef {
        slug: "mail-not-configured",
        status: StatusCode::SERVICE_UNAVAILABLE,
        title: "Mail is not configured",
        description: "No sending domain is verified; use the direct address shown by the form.",
    },
    not_ready: ProblemDef {
        slug: "not-ready",
        status: StatusCode::SERVICE_UNAVAILABLE,
        title: "Service not ready",
        description: "Readiness probe failed: the database is missing, erroring or too slow.",
    },
    sidecar_unavailable: ProblemDef {
        slug: "sidecar-unavailable",
        status: StatusCode::SERVICE_UNAVAILABLE,
        title: "Sidecar module unavailable",
        description: "A sidecar-mounted module could not be reached; other modules are unaffected.",
    },
    sidecar_contract_mismatch: ProblemDef {
        slug: "sidecar-contract-mismatch",
        status: StatusCode::SERVICE_UNAVAILABLE,
        title: "Sidecar contract mismatch",
        description: "A sidecar answers a different HARNESS_API than this harness speaks.",
    },
    tenant_degraded: ProblemDef {
        slug: "tenant-degraded",
        status: StatusCode::SERVICE_UNAVAILABLE,
        title: "Tenant is degraded",
        description: "The tenant's schema is behind or its database is unreachable; its neighbours are unaffected.",
    },
};

/// Every core slug definition, for tests and docs.
pub fn registry() -> Vec<&'static ProblemDef> {
    vec![
        &SLUGS.validation_failed,
        &SLUGS.captcha_failed,
        &SLUGS.invalid_token,
        &SLUGS.unknown_product,
        &SLUGS.unauthenticated,
        &SLUGS.admin_unauthorized,
        &SLUGS.api_key_unauthorized,
        &SLUGS.api_key_forbidden,
        &SLUGS.admin_forbidden,
        &SLUGS.sidecar_unauthorized,
        &SLUGS.not_production_ready,
        &SLUGS.request_too_large,
        &SLUGS.rate_limited,
        &SLUGS.allowance_exhausted,
        &SLUGS.not_found,
        &SLUGS.unknown_tenant,
        &SLUGS.internal,
        &SLUGS.mail_not_configured,
        &SLUGS.not_ready,
        &SLUGS.sidecar_unavailable,
        &SLUGS.sidecar_contract_mismatch,
        &SLUGS.tenant_degraded,
    ]
}
