//! A scratch directory that is removed **on drop**.
//!
//! The rule this exists to enforce: a test that removes its directory on
//! its last line removes it only when it passes. Every assertion that
//! fires before that line leaves the directory behind — and the tests that
//! most need a scratch directory are the ones writing key material, so
//! what a failing run leaks into `/tmp` is a `0600` private key that
//! nothing will ever clean up.
//!
//! `Drop` runs on the unwind, so the cleanup is not conditional on the
//! result. The repo hand-rolls this rather than depending on `tempfile`
//! (the same reasoning `crates/cli-acceptance/tests/card_data_guard.rs`
//! gives), and this is the copy the workspace shares.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A directory under the system temp directory, removed when this value
/// is dropped — including while a panic unwinds.
///
/// ```
/// # use cratefield_testing::TempDir;
/// let dir = TempDir::new("my-test");
/// std::fs::write(dir.join("key"), "secret").expect("writes");
/// let path = dir.path().to_path_buf();
/// drop(dir);
/// assert!(!path.exists());
/// ```
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    /// Creates a directory named after `tag`, unique to this call.
    ///
    /// # Panics
    ///
    /// If the directory cannot be created — a test cannot continue
    /// without it.
    #[must_use]
    pub fn new(tag: &str) -> Self {
        // A counter as well as the clock: `as_nanos` is not
        // nanosecond-*resolution* on macOS, and tests build these in
        // parallel, so two can land in the same tick and then share a
        // directory — which reads as a mystifying failure in the full
        // workspace run and passes when the file is run alone.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "cratefield-{tag}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock is after the epoch")
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Self(dir)
    }

    /// The directory itself.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// A path inside it. The file need not exist.
    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort: a test that has already failed must not fail
        // again, differently, in its own cleanup.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_goes_away_even_when_the_test_holding_it_panics() {
        // The whole point: cleanup on the last line of a test is cleanup
        // that never runs on the run that needed it.
        let dir = TempDir::new("panics");
        let path = dir.path().to_path_buf();
        std::fs::write(dir.join("vapid.key"), "a private key").expect("writes");
        assert!(path.exists(), "the directory was created");

        // The directory is *moved* into the closure, so the only thing
        // that can remove it is its `Drop` running on the unwind.
        let result = std::panic::catch_unwind(move || {
            let _held = dir;
            panic!("an assertion fires here");
        });

        assert!(result.is_err(), "the panic is the scenario");
        assert!(
            !path.exists(),
            "the unwind left {} behind, private key and all",
            path.display()
        );
    }

    #[test]
    fn two_directories_taken_in_the_same_tick_are_not_the_same_directory() {
        let first = TempDir::new("same-tick");
        let second = TempDir::new("same-tick");
        assert_ne!(first.path(), second.path());
    }
}
