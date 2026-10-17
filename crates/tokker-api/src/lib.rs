//! Tokker's Cratefield harness modules.
//!
//! A [`Module`] stub plus [`freshness`], the freshness SLAs. As the venture
//! grows, the pricing routes, the calculator and the MCP tool surface live
//! here too.

#![forbid(unsafe_code)]

pub mod freshness;

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
