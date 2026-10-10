//! The `Embedder` port (issue #561, ADR 0024): text into embedding
//! vectors, asked for by shape, never by vendor. A module holds
//! `Arc<dyn Embedder>` and never learns which provider turned its text
//! into numbers; the vectors feed the [`VectorIndex`](crate::VectorIndex)
//! port, the sibling of this one — which is why [`Embeddings`] reports the
//! answering model: vectors from different models are not comparable. No
//! outcome enum, as on [`TextModel`](crate::TextModel): the unwired answer
//! is [`EmbedError::NotConfigured`], so a module that cannot degrade
//! without its embedder fails loudly.

use async_trait::async_trait;

/// One answered embedding request: one vector per input text, **in input
/// order**, plus the model that answered and the input tokens it billed.
#[derive(Debug, Clone, PartialEq)]
pub struct Embeddings {
    pub vectors: Vec<Vec<f32>>,
    /// A provider identifier for the log line and the bill, not a wire
    /// value a module switches on.
    pub model: String,
    pub input_tokens: u64,
}

impl Embeddings {
    /// An answer by `model`; vectors and usage follow with
    /// [`Embeddings::vector`] / [`Embeddings::usage`].
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            vectors: Vec::new(),
            model: model.into(),
            input_tokens: 0,
        }
    }

    /// Appends one vector, in input order.
    #[must_use]
    pub fn vector(mut self, vector: Vec<f32>) -> Self {
        self.vectors.push(vector);
        self
    }

    /// The token count the provider billed for the inputs.
    #[must_use]
    pub fn usage(mut self, input_tokens: u64) -> Self {
        self.input_tokens = input_tokens;
        self
    }
}

/// Embedding failures. [`EmbedError::Provider`] carries the provider's own
/// words, so it is scrubbed in `Display` (issue #235); `Debug` stays raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbedError {
    /// No embedder is wired — the venture did not provide one.
    NotConfigured,
    /// The request was malformed before any provider saw it.
    InvalidInput(String),
    /// The provider refused the request or the call failed.
    Provider(String),
}

impl std::fmt::Display for EmbedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::NotConfigured => f.write_str("no embedder is wired"),
            Self::InvalidInput(message) => {
                write!(f, "embed request rejected: {}", scrub(message))
            }
            Self::Provider(message) => write!(f, "embed failed: {}", scrub(message)),
        }
    }
}

impl std::error::Error for EmbedError {}

/// Embeds texts, over whichever provider the venture wired: exactly one
/// vector per input text, in input order, so a caller can zip them.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// Embeds every text in `texts`.
    ///
    /// # Errors
    /// [`EmbedError::NotConfigured`] when no embedder is wired;
    /// [`EmbedError::InvalidInput`] when the request is malformed;
    /// [`EmbedError::Provider`] when the provider refused or failed.
    async fn embed(&self, texts: &[String]) -> Result<Embeddings, EmbedError>;
}
