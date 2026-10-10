//! The `IdGen` port (architecture section 5): sortable ULID identifiers.

use ulid::Ulid;

pub trait IdGen: Send + Sync {
    fn ulid(&self) -> String;
}

/// Real ULID generator (monotonic per process).
#[derive(Debug, Clone, Copy, Default)]
pub struct UlidIdGen;

impl IdGen for UlidIdGen {
    fn ulid(&self) -> String {
        Ulid::generate().to_string()
    }
}
