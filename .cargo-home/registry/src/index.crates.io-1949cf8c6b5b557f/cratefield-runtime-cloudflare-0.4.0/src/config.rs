//! `Config` over the Workers `Env`: secrets first, then vars.

use cratefield_core::Config;
use worker::Env;

pub struct EnvConfig(pub Env);

impl Config for EnvConfig {
    fn get(&self, key: &str) -> Option<String> {
        // Secrets take precedence over vars of the same name.
        self.0
            .secret(key)
            .map(|secret| secret.to_string())
            .ok()
            .or_else(|| self.0.var(key).map(|var| var.to_string()).ok())
    }
}
