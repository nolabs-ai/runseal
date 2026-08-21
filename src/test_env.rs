//! Env var mutation is process-global and not thread-safe across Rust's
//! parallel test runner, so any test that changes one must both serialize
//! against every other such test and restore the original value.
//! `EnvVarGuard` holds a process-wide lock for its lifetime and restores every
//! value it touched on drop.
//!
//! The lock is not reentrant, so a test must never hold two guards at once.
//! To stage several vars, chain them onto one guard:
//!
//! ```ignore
//! let _guard = EnvVarGuard::remove("RUNNER_TEMP").with_set("HOME", path);
//! ```

#![allow(clippy::disallowed_methods)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Serializes every env-var-mutating test in this binary against each other.
static ENV_LOCK: Mutex<()> = Mutex::new(());

pub struct EnvVarGuard {
    /// Original values in the order they were overwritten; restored in
    /// reverse so a var staged twice ends up back at its first-seen value.
    saved: Vec<(&'static str, Option<OsString>)>,
    // Declared last so it is released only after `Drop::drop` has restored
    // the environment.
    _lock: MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    /// Takes the process-wide lock without touching the environment yet.
    ///
    /// A poisoned lock still hands back a guard: the panicking test's own
    /// guard restored the environment as it unwound, so nothing is corrupt.
    fn acquire() -> Self {
        Self {
            saved: Vec::new(),
            _lock: ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }

    pub fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        Self::acquire().with_set(key, value)
    }

    pub fn remove(key: &'static str) -> Self {
        Self::acquire().with_remove(key)
    }

    #[must_use]
    pub fn with_set(mut self, key: &'static str, value: impl AsRef<OsStr>) -> Self {
        self.save(key);
        env::set_var(key, value);
        self
    }

    #[must_use]
    pub fn with_remove(mut self, key: &'static str) -> Self {
        self.save(key);
        env::remove_var(key);
        self
    }

    fn save(&mut self, key: &'static str) {
        self.saved.push((key, env::var_os(key)));
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, original) in self.saved.drain(..).rev() {
            match original {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
    }
}
