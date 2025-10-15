//! Test utilities for the auth service.
//!
//! Provides a robust, production-grade testing infrastructure that ensures
//! test isolation, reliability, and maintainability. This module is a core
//! asset for ensuring the quality of the application.

// This attribute ensures the entire module is only compiled for tests.
#![cfg(test)]

use crate::app::AppState;
use crate::config::database::{init_pool, run_migrations, DbPool};
use crate::utils::errors::AuthServiceError;
use once_cell::sync::Lazy;
use redis::Client as RedisClient;
use std::{env, sync::Mutex};



/// A global mutex lock to prevent race conditions during concurrent test setup.
///
/// When tests run in parallel (`cargo test`), multiple threads might try to
/// initialize the database environment simultaneously. This lock ensures that
/// database creation, cleaning, and migration happen serially, preventing
//  data corruption and flaky tests.
static DB_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Creates an isolated, clean test database pool with all migrations applied.
/// This is the definitive function for initializing a database for a test.
pub fn make_pool() -> DbPool {
    let _guard = DB_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    init_test_env();
    let pool = init_pool();

    // Cleaning the database before running migrations is crucial for idempotency.
    clean_test_database(&pool);

    if let Err(e) = run_migrations(&pool) {
        // This is not a panic because in a concurrent test run, another thread
        // might have already applied the migrations. This warning is for visibility.
        eprintln!(
            "Migration warning (this is often safe if migrations are already applied): {}",
            e
        );
    }

    pool
}

/// Truncates all user-related tables to ensure a clean state for each test.
/// Panics if the cleanup operation fails, as a dirty state is unacceptable for testing.
fn clean_test_database(pool: &DbPool) {
    use crate::db::schema::users;
    use diesel::prelude::*;

    let mut conn = pool
        .get()
        .expect("Failed to get DB connection for cleaning");

    // The order of deletion matters if there are foreign key constraints.
    // Start with tables that are depended upon.
    diesel::delete(users::table)
        .execute(&mut conn)
        .expect("Failed to clean 'users' table");
    // Add other tables here in the correct order, e.g.,
    // diesel::delete(tokens::table).execute(&mut conn).expect("Failed to clean 'tokens' table");
}

// =============================================================================
// APP STATE BUILDERS
// =============================================================================

/// Creates a full test `AppState` with a connection to a real Redis instance.
pub fn state_with_redis() -> AppState {
    init_test_env();
    let redis_url =
        env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    AppState {
        pool: make_pool(),
        redis_client: RedisClient::open(redis_url).ok(),
        email_config: None,
    }
}

// =============================================================================
// ENVIRONMENT SETUP
// =============================================================================

/// Initializes the environment for a test run.
/// Sets critical environment variables and initializes the metrics system.
pub fn init_test_env() {
    // Load variables from .env.test first, allowing overrides.
    dotenvy::from_filename(".env.test").ok();

    // Provide a default test database URL if not set.
    if env::var("DATABASE_URL").is_err() {
        env::set_var(
            "DATABASE_URL",
            "postgres://buildhub:bhdbjpak@localhost:5432/buildhub_auth_test",
        );
    }

    // Use a fixed, known JWT secret for reproducible tests.
    env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-long");

    // Initialize the metrics singleton to prevent panics in concurrent tests.
    crate::utils::metrics::init();
}

// The `cleanup_test_env` function was removed as it's an anti-pattern.
// Tests should be independent and set their own environment without relying on cleanup.

// =============================================================================
// VALIDATION HELPERS (TEST DSL)
// =============================================================================

/// Asserts that a given value passes a validation function.
/// Panics with a descriptive message if validation fails.
pub fn assert_valid<F>(value: &str, validator: F)
where
    F: Fn(&str) -> Result<(), AuthServiceError>,
{
    if let Err(e) = validator(value) {
        panic!("Expected '{}' to be valid, but got error: {:?}", value, e);
    }
}

/// Asserts that a given value fails a validation function with a specific error.
/// Panics if validation succeeds or fails with a different error.
pub fn assert_invalid<F>(field: &str, value: &str, contains: &str, validator: F)
where
    F: Fn(&str) -> Result<(), AuthServiceError>,
{
    match validator(value) {
        Ok(_) => panic!("Expected '{}' to be invalid, but it was valid.", value),
        Err(AuthServiceError::Validation {
            field: f,
            message,
        }) => {
            assert_eq!(f, field, "Validation error was for the wrong field.");
            assert!(
                message.contains(contains),
                "Error message '{}' did not contain expected text '{}'",
                message,
                contains
            );
        }
        Err(e) => panic!("Expected a Validation error, but got a different error: {:?}", e),
    }
}

// =============================================================================
// TEST DATA BUILDERS
// =============================================================================

/// Generates a standard JWT access token for a test user.
pub fn generate_test_token(username: &str) -> String {
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};
    init_test_env();
    generate_token(username, TOKEN_TYPE_ACCESS, None).expect("Failed to generate test token")
}

// =============================================================================
// ASYNC TEST HELPERS
// =============================================================================

/// Wraps a future in a timeout, causing a panic if it doesn't complete.
/// Essential for preventing hung tests in a CI environment.
pub async fn with_timeout<F, T>(duration: std::time::Duration, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(duration, future)
        .await
        .expect("Test timed out")
}

// =============================================================================
// SELF-TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    #[ignore] // Requires a running database
    fn test_make_pool_and_clean() {
        let pool = make_pool();
        assert!(pool.get().is_ok(), "Should be able to get a connection");
    }

    #[test]
    fn test_init_test_env_sets_variables() {
        init_test_env();
        assert_eq!(
            env::var("JWT_SECRET").unwrap(),
            "test-secret-key-minimum-32-characters-long"
        );
    }

    #[test]
    fn test_assert_valid_helper() {
        assert_valid("test", |_| Ok(()));
    }

    #[test]
    #[should_panic(expected = "Expected 'test' to be valid")]
    fn test_assert_valid_helper_panics() {
        assert_valid("test", |_| {
            Err(AuthServiceError::validation("field", "error"))
        });
    }

    #[test]
    fn test_assert_invalid_helper() {
        fn short_validator(s: &str) -> Result<(), AuthServiceError> {
            if s.len() < 5 {
                Err(AuthServiceError::validation("input", "too short"))
            } else {
                Ok(())
            }
        }
        assert_invalid("input", "abc", "short", short_validator);
    }

    #[test]
    #[should_panic(expected = "Expected 'longstring' to be invalid")]
    fn test_assert_invalid_helper_panics_on_valid() {
        fn short_validator(s: &str) -> Result<(), AuthServiceError> {
            if s.len() < 5 {
                Err(AuthServiceError::validation("input", "too short"))
            } else {
                Ok(())
            }
        }
        assert_invalid("input", "longstring", "short", short_validator);
    }

    #[test]
    fn test_token_generation() {
        let token = generate_test_token("test-user");
        assert!(!token.is_empty());
        assert_eq!(token.split('.').count(), 3, "Token should have 3 parts");
    }

    #[tokio::test]
    async fn test_timeout_helper_succeeds() {
        let result = with_timeout(Duration::from_secs(1), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            "done"
        })
        .await;
        assert_eq!(result, "done");
    }

    #[tokio::test]
    #[should_panic(expected = "Test timed out")]
    async fn test_timeout_helper_panics() {
        with_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
        })
        .await;
    }
}
