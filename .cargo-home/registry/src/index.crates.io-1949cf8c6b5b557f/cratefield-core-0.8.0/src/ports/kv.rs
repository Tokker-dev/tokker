//! The `KeyValue` port (architecture section 5): KV on Workers, Redis later.

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum KvError {
    #[error("key-value operation failed: {0}")]
    Operation(String),
}

#[async_trait]
pub trait KeyValue: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, KvError>;
    async fn put(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), KvError>;
    async fn delete(&self, key: &str) -> Result<(), KvError>;
}
