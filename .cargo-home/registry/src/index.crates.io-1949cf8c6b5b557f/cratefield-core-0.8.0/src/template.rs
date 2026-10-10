//! The template registry (issue #4): mail subjects and bodies with
//! venture-level overrides and locale fallback.
//!
//! `Template` is a trait so ventures can use askama, `format!`, or anything
//! else. Ids are `<module>/<template>` (`email-signup/confirm`); locale
//! variants register as `<id>@<locale>` and are tried first.
//!
//! **Where defaults come from.** The locked `Module` trait (architecture
//! section 4) has no `templates()` hook, so a module's default templates are
//! its own code: modules ship `pub fn default_templates() ->
//! Vec<(String, Box<dyn Template>)>` as a plain associated function, and the
//! venture's `src/lib.rs` registers them before its overrides — or the
//! module falls back to its built-in template when the registry misses.
//! This keeps the trait exactly as specified in the architecture doc.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// A rendered mail, ready for `Message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub subject: String,
    pub html: String,
    pub text: String,
}

#[derive(Debug, Clone, Error)]
pub enum TemplateError {
    #[error("template {id:?} is not registered (locale {locale:?})")]
    UnknownTemplate { id: String, locale: String },
    #[error("template {id:?} failed to render: {reason}")]
    RenderFailed { id: String, reason: String },
}

/// One template. `data` is the caller's JSON payload; `locale` is the
/// requested locale tag (`en`, `de`, ...) used by the implementation for
/// its own variants.
pub trait Template: Send + Sync {
    /// # Errors
    ///
    /// `Err` when the template cannot render `data` (missing fields, ...).
    fn render(&self, data: &Value, locale: &str) -> Result<Rendered, TemplateError>;
}

/// Immutable registry: venture overrides are inserted after module defaults
/// at `Harness::build`, so they win on id collision.
#[derive(Clone, Default)]
pub struct TemplateRegistry {
    templates: HashMap<String, Arc<dyn Template>>,
}

impl TemplateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts (or replaces) a template under `id` or `id@<locale>`.
    pub fn register(&mut self, id: impl Into<String>, template: Box<dyn Template>) {
        self.templates.insert(id.into(), Arc::from(template));
    }

    /// Registers every pair; later entries win on id collision, so call it
    /// with overrides last.
    pub fn register_all(
        &mut self,
        templates: impl IntoIterator<Item = (String, Box<dyn Template>)>,
    ) {
        for (id, template) in templates {
            self.register(id, template);
        }
    }

    /// Renders `<id>@<locale>` if present, else `<id>`.
    ///
    /// # Errors
    ///
    /// `UnknownTemplate` when neither id is registered; `RenderFailed`
    /// when the chosen template cannot render `data`.
    pub fn render(&self, id: &str, data: &Value, locale: &str) -> Result<Rendered, TemplateError> {
        let localized = format!("{id}@{locale}");
        if let Some(template) = self.templates.get(&localized) {
            return template.render(data, locale);
        }
        match self.templates.get(id) {
            Some(template) => template.render(data, locale),
            None => Err(TemplateError::UnknownTemplate {
                id: id.to_string(),
                locale: locale.to_string(),
            }),
        }
    }

    /// Whether `id` (or `id@<locale>`) is registered.
    pub fn contains(&self, id: &str, locale: &str) -> bool {
        self.templates.contains_key(&format!("{id}@{locale}")) || self.templates.contains_key(id)
    }
}

impl std::fmt::Debug for TemplateRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ids: Vec<&String> = self.templates.keys().collect();
        ids.sort();
        f.debug_struct("TemplateRegistry")
            .field("ids", &ids)
            .finish()
    }
}
