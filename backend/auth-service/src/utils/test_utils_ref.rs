//! Shared test helpers for auth-service tests.
//!
//! Provides reusable tools for database state, Redis setup, and validation assertions.

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

/// Ensures unique in-memory SQLite databases per test.
static TEST_DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Lock to serialize set_var + migration (avoids race and SQLite lock errors).
static MAKE_POOL_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Spins up a unique in-memory SQLite pool and runs all migrations.
pub fn make_pool() -> DbPool {
    let _guard = MAKE_POOL_LOCK.lock().unwrap();

    let id = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let url = format!("file:auth_test_db_{}?mode=memory&cache=shared", id);
    env::set_var("DATABASE_URL", &url);

    let pool = init_pool();
    run_migrations(&pool).expect("migrations failed");
    pool
}

/// Ensures a consistent JWT_SECRET for tests requiring token generation.
pub fn init_jwt_secret() {
    env::set_var("JWT_SECRET", "test-secret");
}

/// Constructs an `AppState` with Redis enabled.
pub fn state_with_redis() -> AppState {
    init_jwt_secret();
    AppState {
        pool: make_pool(),
        redis_client: Some(RedisClient::open("redis://127.0.0.1/").unwrap()),
        email_config: None,
    }
}

/// Constructs an `AppState` with no Redis available.
pub fn state_no_redis() -> AppState {
    init_jwt_secret();
    AppState {
        pool: make_pool(),
        redis_client: None,
        email_config: None,
    }
}

/// Asserts that a given input fails validation with the expected field and message.
pub fn assert_invalid<F>(field: &str, input: &str, expected_msg: &str, validator: F)
where
    F: Fn(&str) -> Result<(), ValidationError>,
{
    match validator(input).unwrap_err() {
        ValidationError::InvalidValue(fld, msg) => {
            assert_eq!(fld, field, "Validation failed for unexpected field");
            assert!(
                msg.contains(expected_msg),
                "Expected error message to contain '{expected_msg}', got '{msg}'"
            );
        }
        err => panic!("Expected InvalidValue error, got: {err:?}"),
    }
}

/// Asserts that a given input passes validation.
pub fn assert_valid<F>(input: &str, validator: F)
where
    F: Fn(&str) -> Result<(), ValidationError>,
{
    validator(input).unwrap_or_else(|e| panic!("Expected valid input, got error: {e:?}"));
}
