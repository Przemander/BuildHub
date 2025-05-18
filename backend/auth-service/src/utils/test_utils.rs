//! Shared test helpers for auth-service tests.
//!
//! This module provides specialized testing utilities to streamline test development
//! and ensure consistency across the auth service test suite. It includes:
//!
//! - Database fixtures with isolated in-memory SQLite instances
//! - Mock AppState configurations with various dependencies enabled/disabled
//! - Validation assertion helpers for cleaner test cases
//! - Environment variable management for tests
//! - Thread-safe counters for parallel test execution
//!
//! All utilities are designed for test code only and should not be used in production.

// Since we're keeping the module for test purposes only
#![allow(dead_code)]

use crate::app::AppState;
use crate::config::database::{init_pool, run_migrations, DbPool};
use crate::utils::errors::ValidationError;
use once_cell::sync::Lazy;
use redis::Client as RedisClient;
use std::{
    env,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

/// Counter for generating unique database identifiers.
/// 
/// This ensures each test gets its own isolated database instance,
/// even when tests run in parallel.
static TEST_DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Mutex to synchronize database creation operations.
/// 
/// This prevents race conditions when multiple tests try to set
/// environment variables and run migrations simultaneously.
static MAKE_POOL_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Default secret key used for JWT testing.
const TEST_JWT_SECRET: &str = "test-secret-key-for-unit-tests-only";

/// Default Redis URL for testing.
const TEST_REDIS_URL: &str = "redis://127.0.0.1/";

/// Creates a unique in-memory SQLite database pool and runs migrations.
///
/// Each call generates a unique database name to ensure test isolation,
/// even when tests run in parallel. The database exists only in memory
/// and will be destroyed when the pool is dropped.
///
/// # Returns
///
/// A connection pool pointing to a fresh in-memory database with migrations applied
///
/// # Panics
///
/// - If migrations fail to apply
/// - If the database pool cannot be created
///
/// # Example
///
/// ```
/// #[cfg(test)]
/// mod tests {
///     use crate::utils::test_utils::make_pool;
///
///     #[test]
///     fn test_database_operations() {
///         let pool = make_pool();
///         // Use pool for test operations...
///     }
/// }
/// ```
pub fn make_pool() -> DbPool {
    // Acquire lock to prevent race conditions with environment variables
    let _guard = MAKE_POOL_LOCK.lock().unwrap();

    // Generate unique database name for this test
    let id = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let url = format!("file:auth_test_db_{}?mode=memory&cache=shared", id);
    
    // Set environment variable for database connection
    env::set_var("DATABASE_URL", &url);

    // Initialize pool and run migrations
    let pool = init_pool();
    run_migrations(&pool).expect("Failed to run database migrations for test");
    pool
}

/// Sets up a JWT secret for token-based tests.
///
/// Ensures the JWT_SECRET environment variable is set to a consistent value
/// for predictable test behavior. This should be called before any JWT
/// operations in tests.
///
/// # Example
///
/// ```
/// #[cfg(test)]
/// mod tests {
///     use crate::utils::test_utils::init_jwt_secret;
///
///     #[test]
///     fn test_token_generation() {
///         init_jwt_secret();
///         // Now token generation will work with the test secret
///     }
/// }
/// ```
pub fn init_jwt_secret() {
    env::set_var("JWT_SECRET", TEST_JWT_SECRET);
}

/// Creates an AppState with Redis enabled for integration tests.
///
/// This function initializes a complete AppState with both database and Redis
/// connections configured. Useful for testing handlers that require both services.
///
/// # Returns
///
/// A fully configured AppState with Redis enabled
///
/// # Panics
///
/// - If the database or Redis connections cannot be established
///
/// # Example
///
/// ```
/// #[cfg(test)]
/// mod tests {
///     use crate::utils::test_utils::state_with_redis;
///
///     #[tokio::test]
///     async fn test_handler_with_redis() {
///         let state = state_with_redis();
///         // Test a handler that uses Redis...
///     }
/// }
/// ```
pub fn state_with_redis() -> AppState {
    // Initialize JWT secret for token operations
    init_jwt_secret();
    
    // Create the AppState with Redis enabled
    AppState {
        pool: make_pool(),
        redis_client: Some(RedisClient::open(TEST_REDIS_URL).unwrap_or_else(|e| {
            panic!("Failed to create Redis client for tests: {}", e);
        })),
        email_config: None,
    }
}

/// Creates an AppState without Redis for testing failure cases.
///
/// This function is useful for testing how handlers behave when Redis
/// is unavailable. It provides a database connection but no Redis client.
///
/// # Returns
///
/// An AppState configured with a database pool but no Redis client
///
/// # Example
///
/// ```
/// #[cfg(test)]
/// mod tests {
///     use crate::utils::test_utils::state_no_redis;
///
///     #[tokio::test]
///     async fn test_handler_without_redis() {
///         let state = state_no_redis();
///         // Test how a handler behaves when Redis is unavailable...
///     }
/// }
/// ```
pub fn state_no_redis() -> AppState {
    // Initialize JWT secret for token operations
    init_jwt_secret();
    
    // Create the AppState without Redis
    AppState {
        pool: make_pool(),
        redis_client: None,
        email_config: None,
    }
}

/// Asserts that a validation function accepts a valid input.
///
/// This helper improves test readability by encapsulating the validation
/// logic check behind a descriptive assertion function.
///
/// # Arguments
///
/// * `value` - The input value to validate
/// * `validator` - The validation function to test
///
/// # Panics
///
/// - If the validator rejects the input
///
/// # Example
///
/// ```
/// #[cfg(test)]
/// mod tests {
///     use crate::utils::{test_utils::assert_valid, validators::validate_email};
///
///     #[test]
///     fn test_valid_emails() {
///         assert_valid("user@example.com", validate_email);
///     }
/// }
/// ```
pub fn assert_valid<F>(value: &str, validator: F)
where
    F: Fn(&str) -> Result<(), ValidationError>,
{
    match validator(value) {
        Ok(_) => {}, // Test passes
        Err(e) => panic!("Expected '{}' to be valid, but got error: {:?}", value, e),
    }
}

/// Asserts that a validation function rejects an invalid input.
///
/// This helper improves test readability by checking that:
/// 1. The validator rejects the input
/// 2. The error identifies the correct field
/// 3. The error message contains specific expected text
///
/// # Arguments
///
/// * `expected_field` - The field name that should appear in the error
/// * `value` - The invalid input value
/// * `error_contains` - Text that should appear in the error message
/// * `validator` - The validation function to test
///
/// # Panics
///
/// - If the validator accepts the input
/// - If the error field name doesn't match expectations
/// - If the error message doesn't contain the expected text
///
/// # Example
///
/// ```
/// #[cfg(test)]
/// mod tests {
///     use crate::utils::{test_utils::assert_invalid, validators::validate_email};
///
///     #[test]
///     fn test_invalid_emails() {
///         assert_invalid("email", "not-an-email", "valid email", validate_email);
///     }
/// }
/// ```
pub fn assert_invalid<F>(expected_field: &str, value: &str, error_contains: &str, validator: F)
where
    F: Fn(&str) -> Result<(), ValidationError>,
{
    match validator(value) {
        Ok(_) => panic!("Expected '{}' to be invalid, but validation passed", value),
        Err(ValidationError::InvalidValue(field, msg)) => {
            assert_eq!(
                field, expected_field,
                "Expected field '{}' but got '{}'",
                expected_field, field
            );
            assert!(
                msg.contains(error_contains),
                "Error message '{}' doesn't contain '{}'",
                msg, error_contains
            );
        }
    }
}

/// Resets all test environment variables to ensure a clean testing state.
///
/// This function clears any environment variables that might affect test
/// behavior, preventing test pollution between different test cases.
///
/// # Example
///
/// ```
/// #[cfg(test)]
/// mod tests {
///     use crate::utils::test_utils::reset_test_env;
///
///     #[test]
///     fn test_requiring_clean_environment() {
///         reset_test_env();
///         // Now no environment variables from other tests will interfere
///     }
/// }
/// ```
pub fn reset_test_env() {
    env::remove_var("DATABASE_URL");
    env::remove_var("JWT_SECRET");
    env::remove_var("REDIS_URL");
    // Add any other environment variables your tests might set
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::var;

    #[test]
    fn make_pool_creates_working_database() {
        let pool = make_pool();
        let conn_result = pool.get();
        assert!(conn_result.is_ok(), "Should be able to get a connection");
    }

    #[test]
    fn make_pool_creates_unique_databases() {
        // Clear environment before test
        env::remove_var("DATABASE_URL");
        
        // First pool
        let _pool1 = make_pool();
        let url1 = var("DATABASE_URL").unwrap();
        
        // Second pool
        let _pool2 = make_pool();
        let url2 = var("DATABASE_URL").unwrap();
        
        assert_ne!(url1, url2, "Database URLs should be unique");
    }

    #[test]
    fn init_jwt_secret_sets_environment_variable() {
        // Clear environment before test
        env::remove_var("JWT_SECRET");
        
        // Act
        init_jwt_secret();
        
        // Assert
        assert_eq!(var("JWT_SECRET").unwrap(), TEST_JWT_SECRET);
    }

    #[test]
    fn state_with_redis_creates_valid_app_state() {
        let state = state_with_redis();
        
        // Verify database connection
        assert!(state.pool.get().is_ok(), "Database pool should be working");
        
        // Verify Redis client exists
        assert!(state.redis_client.is_some(), "Redis client should be present");
    }

    #[test]
    fn state_no_redis_creates_app_state_without_redis() {
        let state = state_no_redis();
        
        // Verify database connection
        assert!(state.pool.get().is_ok(), "Database pool should be working");
        
        // Verify Redis client is None
        assert!(state.redis_client.is_none(), "Redis client should be None");
    }

    #[test]
    fn assert_valid_passes_for_valid_input() {
        // Define a simple validation function
        fn always_valid(_: &str) -> Result<(), ValidationError> {
            Ok(())
        }
        
        // This should not panic
        assert_valid("any input", always_valid);
    }

    #[test]
    #[should_panic(expected = "Expected 'test' to be valid")]
    fn assert_valid_panics_for_invalid_input() {
        // Define a validation function that always fails
        fn always_invalid(_: &str) -> Result<(), ValidationError> {
            Err(ValidationError::InvalidValue("field".into(), "error".into()))
        }
        
        // This should panic
        assert_valid("test", always_invalid);
    }

    #[test]
    fn assert_invalid_passes_for_invalid_input() {
        // Define a validation function that fails with the expected error
        fn fails_with_expected_error(_: &str) -> Result<(), ValidationError> {
            Err(ValidationError::InvalidValue(
                "test_field".into(),
                "contains expected text".into(),
            ))
        }
        
        // This should not panic
        assert_invalid("test_field", "bad input", "expected text", fails_with_expected_error);
    }

    #[test]
    #[should_panic(expected = "Expected 'test' to be invalid")]
    fn assert_invalid_panics_for_valid_input() {
        // Define a validation function that always succeeds
        fn always_valid(_: &str) -> Result<(), ValidationError> {
            Ok(())
        }
        
        // This should panic
        assert_invalid("field", "test", "error", always_valid);
    }

    #[test]
    #[should_panic(expected = "Expected field 'expected' but got 'actual'")]
    fn assert_invalid_checks_field_name() {
        // Define a validation function with wrong field name
        fn wrong_field(_: &str) -> Result<(), ValidationError> {
            Err(ValidationError::InvalidValue(
                "actual".into(),
                "error message".into(),
            ))
        }
        
        // This should panic due to field name mismatch
        assert_invalid("expected", "test", "error", wrong_field);
    }

    #[test]
    #[should_panic(expected = "Error message 'actual message' doesn't contain 'expected text'")]
    fn assert_invalid_checks_error_message() {
        // Define a validation function with message not containing expected text
        fn wrong_message(_: &str) -> Result<(), ValidationError> {
            Err(ValidationError::InvalidValue(
                "field".into(),
                "actual message".into(),
            ))
        }
        
        // This should panic due to message content mismatch
        assert_invalid("field", "test", "expected text", wrong_message);
    }
}