//! `KeyValue` over a Workers KV namespace.

use async_trait::async_trait;
use cratefield_core::{KeyValue, KvError};
use std::time::Duration;
use worker::KvStore;
use worker::send::IntoSendFuture;

pub struct KvStorePort(pub KvStore);

#[async_trait]
impl KeyValue for KvStorePort {
    async fn get(&self, key: &str) -> Result<Option<String>, KvError> {
        self.0
            .get(key)
            .text()
            .into_send()
            .await
            .map_err(|err| KvError::Operation(err.to_string()))
    }

    async fn put(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), KvError> {
        let mut builder = self
            .0
            .put(key, value)
            .map_err(|err| KvError::Operation(err.to_string()))?;
        if let Some(ttl) = ttl {
            let secs = ttl.as_secs().max(1);
            builder = builder.expiration_ttl(secs);
        }
        builder
            .execute()
            .into_send()
            .await
            .map_err(|err| KvError::Operation(err.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.0
            .delete(key)
            .into_send()
            .await
            .map_err(|err| KvError::Operation(err.to_string()))
    }
}
