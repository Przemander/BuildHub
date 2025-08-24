//! Test utilities for the auth service.
//!
//! Provides essential testing infrastructure without over-engineering.

#![cfg(test)]

use crate::app::AppState;
use crate::config::database::{init_pool, run_migrations, DbPool};
use crate::utils::errors::AuthServiceError;
use once_cell::sync::Lazy;
use redis::Client as RedisClient;
use std::{
    env,
    sync::
        Mutex
    ,
};

// =============================================================================
// TEST DATABASE MANAGEMENT
// =============================================================================

/// Lock for database creation to prevent env var races
static DB_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
/// Creates an isolated test database pool with migrations.
pub fn make_pool() -> DbPool {
    // Acquire lock to prevent concurrent DB setup
    let _guard = DB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    
    // Set up test environment
    init_test_env();

    // Create the pool
    let pool = init_pool();
    
    // Clean the database before tests
    clean_test_database(&pool);
    
    // Run migrations with error handling
    if let Err(e) = run_migrations(&pool) {
        eprintln!("Migration warning (may be ok if already applied): {}", e);
    }
    
    pool
}

/// Cleans test database tables
fn clean_test_database(pool: &DbPool) {
    use diesel::prelude::*;
    
    if let Ok(mut conn) = pool.get() {
        // Use schema from your project
        use crate::db::schema::users::dsl::*;
        let _ = diesel::delete(users).execute(&mut conn);
        // Add other tables as needed
    }
}

// =============================================================================
// APP STATE BUILDERS
// =============================================================================

/// Creates test AppState with Redis.
pub fn state_with_redis() -> AppState {
    init_test_env();

    let redis_url = env::var("TEST_REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let redis_client = RedisClient::open(redis_url).ok();

    AppState {
        pool: make_pool(),
        redis_client,
        email_config: None,
    }
}

/// Creates test AppState without Redis.
pub fn state_no_redis() -> AppState {
    init_test_env();

    AppState {
        pool: make_pool(),
        redis_client: None,
        email_config: None,
    }
}

// =============================================================================
// ENVIRONMENT SETUP
// =============================================================================

/// Sets up test environment variables.
pub fn init_test_env() {
    // Load test environment from .env.test if available
    dotenvy::from_filename(".env.test").ok();
    
    // Set critical test variables with fallbacks
    if env::var("DATABASE_URL").is_err() {
        env::set_var("DATABASE_URL", "postgres://buildhub:bhdbjpak@localhost:5432/buildhub_auth_test");
    }
    
    env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters");
    env::set_var("TEST_MODE", "true");
    
    // Initialize metrics singleton
    crate::utils::metrics::init();
}

/// Cleans up test environment.
pub fn cleanup_test_env() {
    env::remove_var("DATABASE_URL");
    env::remove_var("JWT_SECRET");
    env::remove_var("TEST_MODE");
}

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

/// Asserts that validation passes.
pub fn assert_valid<F>(value: &str, validator: F)
where
    F: Fn(&str) -> Result<(), AuthServiceError>,
{
    if let Err(e) = validator(value) {
        panic!("Expected '{}' to be valid, but got: {:?}", value, e);
    }
}

/// Asserts that validation fails with expected error.
pub fn assert_invalid<F>(field: &str, value: &str, contains: &str, validator: F)
where
    F: Fn(&str) -> Result<(), AuthServiceError>,
{
    match validator(value) {
        Ok(_) => panic!("Expected '{}' to be invalid", value),
        Err(AuthServiceError::Validation { field: f, message }) => {
            assert_eq!(f, field, "Wrong field in error");
            assert!(
                message.contains(contains),
                "Error '{}' doesn't contain '{}'",
                message,
                contains
            );
        }
        Err(e) => panic!("Expected validation error, got: {:?}", e),
    }
}

// =============================================================================
// TEST DATA BUILDERS
// =============================================================================

/// Generates a test JWT token.
pub fn generate_test_token(username: &str) -> String {
    use crate::utils::jwt::{generate_token, TOKEN_TYPE_ACCESS};

    init_test_env();
    generate_token(username, TOKEN_TYPE_ACCESS, None)
        .expect("Failed to generate test token")
}

// =============================================================================
// ASYNC TEST HELPERS
// =============================================================================

/// Runs an async test with timeout.
pub async fn with_timeout<F, T>(duration: std::time::Duration, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(duration, future)
        .await
        .expect("Test timed out")
}

// =============================================================================
// HTTP TEST HELPERS
// =============================================================================

// Removed test_client() function - not used
// Removed parse_json_response() function - not used

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_pool() {
        let pool = make_pool();
        assert!(pool.get().is_ok());
    }

    #[test]
    fn test_init_test_env() {
        init_test_env();
        assert_eq!(
            env::var("JWT_SECRET").unwrap(),
            "test-secret-key-minimum-32-characters"
        );
        cleanup_test_env();
    }

    #[test]
    fn test_assert_valid() {
        fn always_valid(_: &str) -> Result<(), AuthServiceError> {
            Ok(())
        }
        assert_valid("test", always_valid);
    }

    #[test]
    #[should_panic(expected = "Expected 'test' to be valid")]
    fn test_assert_valid_fails() {
        fn always_invalid(_: &str) -> Result<(), AuthServiceError> {
            Err(AuthServiceError::validation("field", "error"))
        }
        assert_valid("test", always_invalid);
    }

    #[test]
    fn test_assert_invalid() {
        fn validate_length(s: &str) -> Result<(), AuthServiceError> {
            if s.len() < 5 {
                return Err(AuthServiceError::validation("input", "too short"));
            }
            Ok(())
        }
        assert_invalid("input", "abc", "short", validate_length);
    }

    #[test]
    #[should_panic(expected = "Expected 'longstring' to be invalid")]
    fn test_assert_invalid_fails() {
        fn validate_length(s: &str) -> Result<(), AuthServiceError> {
            if s.len() < 5 {
                return Err(AuthServiceError::validation("input", "too short"));
            }
            Ok(())
        }
        assert_invalid("input", "longstring", "short", validate_length);
    }

    #[test]
    fn test_generate_test_token() {
        let token = generate_test_token("testuser");
        assert!(!token.is_empty());
        assert!(token.contains('.'));
    }

    #[tokio::test]
    async fn test_with_timeout() {
        use std::time::Duration;

        let result = with_timeout(Duration::from_secs(1), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            42
        }).await;

        assert_eq!(result, 42);
    }

    #[tokio::test]
    #[should_panic(expected = "Test timed out")]
    async fn test_with_timeout_fails() {
        use std::time::Duration;

        with_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }).await;
    }
}
