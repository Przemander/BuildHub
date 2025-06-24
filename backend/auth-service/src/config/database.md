# File: `src/config/database.rs`

## 1. Overview

This module is responsible for all configuration and connection management for the SQLite database. It initializes, configures, and provides a connection pool that is safe for use in a multi-threaded environment, and it also manages database schema migrations. Its design emphasizes reliability, observability, and security.

## 2. Key Responsibilities

*   Initialize and configure a database connection pool using `r2d2`.
*   Run database schema migrations at application startup using `diesel_migrations`.
*   Provide a mechanism for acquiring a single connection from the pool.
*   Define type aliases for the pool (`DbPool`) and connection (`DbConnection`) for consistency across the application.
*   Ensure observability by logging errors and incrementing Prometheus metrics.
*   Provide robust, unit-tested logic for all public functions.

## 3. Core Components

### `fn init_pool()`

*   **Description:** Creates and returns a fully configured, ready-to-use database connection pool. This is the main function called at application startup to prepare the database connection.
*   **Parameters:** None. Configuration is sourced from environment variables.
*   **Error Handling:** If pool creation fails, the function logs a detailed error, increments an error metric, and deliberately **panics** to stop the application.

#### Code Snippet & Rationale
````rust
// ...
let pool = Pool::builder()
    .max_size(DEFAULT_MAX_POOL_SIZE)
    .min_idle(Some(DEFAULT_MIN_IDLE))
    .connection_timeout(Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECONDS))
    .build(manager)
    .unwrap_or_else(|e| {
        log_error!("Database", &format!("Failed to create connection pool: {}", e), "initialization_error");
        DB_POOL_OPERATIONS.with_label_values(&["failure"]).inc();
        panic!("Failed to create database connection pool: {}", e);
    });
// ...
````
*   **Rationale:**
    *   **Builder Pattern:** The `Pool::builder()` pattern is used for improved readability and maintainability. It allows for a clear, step-by-step configuration of the pool's parameters.
    *   **Robust Error Handling:** Instead of a simple `.unwrap()`, the code uses `.unwrap_or_else`. This allows for executing critical side-effects (logging, metrics) right before the application panics, providing maximum observability into startup failures.

### `fn run_migrations()`

*   **Description:** Runs all pending database migrations. This ensures the database schema is always up-to-date with each application start.
*   **Parameters:** Accepts an immutable reference to the connection pool (`&DbPool`).
*   **Error Handling:** Returns a `Result<(), _>`. Errors are wrapped in a custom `DatabaseError::Migration` type to provide context to the caller.

#### Code Snippet & Rationale
````rust
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
// ...
match conn.run_pending_migrations(MIGRATIONS) {
    Ok(applied) => {
        // ... log success
        Ok(())
    }
    Err(e) => {
        // ... log error and increment metric
        Err(DatabaseError::Migration {
            source: e,
            span: SpanTrace::capture(),
        })
    }
}
````
*   **Rationale:**
    *   **`embed_migrations!`:** This macro embeds SQL migration files directly into the application binary at compile time. This creates a self-contained executable, eliminating a whole class of deployment errors where the code version might not match the migration files on disk.
    *   **`match` Statement:** A `match` statement provides exhaustive handling for both success and failure scenarios. On failure, the original error (`e`) is not discarded but is wrapped in our custom `DatabaseError`, preserving the root cause for easier debugging.

### `fn get_connection()`

*   **Description:** A helper function to acquire a single, ready-to-use connection from the pool.
*   **Parameters:** Accepts an immutable reference to the pool (`&DbPool`).
*   **Error Handling:** Returns a `Result<DbConnection, _>`. Errors from the underlying pool library (e.g., a timeout) are mapped to a custom `DatabaseError` type.

#### Code Snippet & Rationale
````rust
pub fn get_connection(pool: &DbPool) -> Result<DbConnection, DatabaseError> {
    pool.get().map_err(|e| {
        // ...
        DatabaseError::Connection {
            source: e,
            span: SpanTrace::capture(),
        }
    })
}
````
*   **Rationale:**
    *   **`map_err`:** This is a key part of the module's abstraction. It translates a generic error from the `r2d2` library into our application-specific `DatabaseError`. This prevents "leaking" implementation details to the rest of the application and allows for consistent error handling everywhere.

## 4. Design Decisions & Rationale

*   **Decision: Use a connection pool (`r2d2`)**
    *   **Rationale:** Creating a new database connection for every request is an expensive operation. A connection pool maintains a set of ready connections, drastically reducing latency and improving application performance under load.

*   **Decision: Panic on failed pool initialization (Fail-Fast)**
    *   **Rationale:** The database connection is a critical resource. If it cannot be established at startup, the application cannot function correctly. A **"fail-fast"** strategy is employed—it is better to stop the application immediately than to let it run in an unstable state. This also facilitates automatic restarts by orchestration systems (e.g., Kubernetes).

*   **Decision: Configuration via environment variables (`DATABASE_URL`)**
    *   **Rationale:** Following the principles of a 12-Factor App, configuration is separated from code. This allows the same application binary to be deployed across different environments (development, testing, production) without any code changes.

## 5. Interactions & Dependencies

*   **Internal Modules:**
    *   `main.rs`: Calls `init_pool()` and `run_migrations()` during application startup.
    *   `app.rs`: Stores the `DbPool` instance in the application state (`AppState`).
    *   Modules in handlers and db: Use `get_connection()` to access the database.
*   **External Systems:**
    *   **SQLite:** Connects to the database file specified in `DATABASE_URL`.
    *   **Prometheus:** Sends metrics (`DB_POOL_OPERATIONS`, etc.) to monitor health.
*   **Crates (Libraries):**
    *   `diesel` & `diesel_migrations`: The primary ORM and migration tool.
    *   `r2d2` & `r2d2_diesel`: The connection pooling implementation and its adapter.
    *   `log`: A logging facade.

## 6. Testing Strategy

This module features a comprehensive test suite to ensure its reliability and correctness. The strategy covers several key areas:

*   **Happy Path (`init_pool_and_get_connection_success`):** Verifies that the pool can be initialized and a connection can be successfully retrieved under ideal conditions.
*   **Configuration Errors (`init_pool_no_env_panics`):** Ensures the application panics with a clear error message if the required `DATABASE_URL` environment variable is not set.
*   **I/O Errors (`invalid_db_url_causes_init_pool_to_panic`):** Simulates a real-world filesystem error (e.g., an invalid path) and verifies that the application panics as expected.
*   **Idempotency (`run_migrations_is_idempotent`):** A critical test confirming that running the migration process multiple times on an up-to-date database is safe and does not cause errors.
*   **Error Mapping (`get_connection_maps_pool_errors`):** An advanced test that forces a connection timeout to verify that library-specific errors are correctly translated into application-level errors, thus preserving the module's abstraction boundary.
*   **Utility Functions (`mask_db_url_hides_sensitive_info`):** Unit tests for helper functions to ensure they correctly handle various inputs, including safe, sensitive, and malformed data.
