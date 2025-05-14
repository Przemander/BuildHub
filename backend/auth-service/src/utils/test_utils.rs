//! Shared test helpers for auth‐service tests.

use crate::app::AppState;
use crate::config::database::{init_pool, run_migrations, DbPool};
use redis::Client as RedisClient;
use once_cell::sync::Lazy;
use std::{
    env,
    sync::{atomic::{AtomicUsize, Ordering}, Mutex},
};

static TEST_DB_COUNTER: AtomicUsize = AtomicUsize::new(0);
// Serialize set_var + migrations to avoid env‐race & lock/table‐exists errors.
static MAKE_POOL_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Spins up a unique in‐memory SQLite pool and runs migrations.
pub fn make_pool() -> DbPool {
    let _guard = MAKE_POOL_LOCK.lock().unwrap();

    let id = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let url = format!("file:auth_test_db_{}?mode=memory&cache=shared", id);
    env::set_var("DATABASE_URL", &url);

    let pool = init_pool();
    run_migrations(&pool).expect("migrations failed");
    pool
}

/// Ensures a JWT_SECRET is present for token tests.
pub fn init_jwt_secret() {
    std::env::set_var("JWT_SECRET", "test-secret");
}

/// AppState with Redis enabled.
pub fn state_with_redis() -> AppState {
    init_jwt_secret();
    AppState {
        pool: make_pool(),
        redis_client: Some(RedisClient::open("redis://127.0.0.1/").unwrap()),
        email_config: None,
    }
}

/// AppState with no Redis.
pub fn state_no_redis() -> AppState {
    init_jwt_secret();
    AppState {
        pool: make_pool(),
        redis_client: None,
        email_config: None,
    }
}