//! Tokker's Cratefield harness modules.
//!
//! [`offers`] serves the public price index at `/v1/offers` (issue #19);
//! [`freshness`] holds the freshness SLAs both the build and the Worker
//! compute staleness with. As the venture grows, the remaining pricing
//! routes, the calculator and the MCP tool surface live here too.

#![forbid(unsafe_code)]

pub mod freshness;
pub mod offers;
pub(crate) mod offers_query;

pub use offers::Offers;

use cratefield_core::{Config, ConfigError, Migrations, Module, ModuleContext, Port};

/// The Tokker API module — empty for now, mounted at `/v1/tokker`.
pub struct TokkerApi;

impl Default for TokkerApi {
    fn default() -> Self {
        Self
    }
}

impl Module for TokkerApi {
    fn name(&self) -> &'static str {
        "tokker"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}
