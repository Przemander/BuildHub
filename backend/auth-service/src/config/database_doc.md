# Database Module Documentation

## Overview

This module provides **database configuration, connection pooling, migrations, health checks, and Prometheus metrics instrumentation** for the authentication service.

It uses:

* [Diesel](https://diesel.rs) ORM for database access
* [r2d2](https://docs.rs/r2d2) for connection pooling
* [diesel\_migrations](https://docs.rs/diesel_migrations) for embedded migrations
* [tracing](https://docs.rs/tracing) for structured logging
* [Prometheus](https://docs.rs/prometheus) via a local `utils::metrics` module for monitoring

The design ensures:

* **Reliable connectivity** with PostgreSQL
* **Fail-fast startup** if the database is misconfigured or unavailable
* **Automatic schema migrations** at startup
* **Observability** through logs and metrics
* **Async-safe health checks**

---

## Type Definitions

```rust
pub type DbPool = Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;
```

* `DbPool` is a thread-safe pool of PostgreSQL connections.
* `DbConnection` represents a checked-out pooled connection.

Connections are created and managed by `ConnectionManager<PgConnection>` and `r2d2`.

---

## Configuration Constants

```rust
const DATABASE_URL_ENV: &str = "DATABASE_URL";
const DEFAULT_CONNECTION_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_POOL_SIZE: u32 = 25;
const DEFAULT_MIN_IDLE: u32 = 2;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;  // 10 minutes
const DEFAULT_MAX_LIFETIME_SECS: u64 = 1800; // 30 minutes
```

* `DATABASE_URL_ENV` — name of the environment variable containing the PostgreSQL connection URL.
* `DEFAULT_MAX_POOL_SIZE` — maximum number of connections in the pool.
* `DEFAULT_MIN_IDLE` — minimum number of idle connections always maintained.
* `DEFAULT_CONNECTION_TIMEOUT_SECS` — timeout for acquiring a connection.
* `DEFAULT_IDLE_TIMEOUT_SECS` — how long idle connections live before being closed.
* `DEFAULT_MAX_LIFETIME_SECS` — maximum lifetime of a connection before recycling.

---

## Pool Initialization

```rust
pub fn init_pool() -> DbPool
```

### Purpose

Creates and configures the PostgreSQL connection pool with production-ready defaults.

### Behavior

1. Reads the `DATABASE_URL` environment variable. Panics if not set.
2. Creates a `ConnectionManager<PgConnection>`.
3. Builds a `r2d2::Pool` with:

   * Max size = 25
   * Min idle = 2
   * Connection timeout = 10s
   * Idle timeout = 10 minutes
   * Max lifetime = 30 minutes
   * Test connections on checkout
4. Logs pool configuration.
5. Emits metrics: `db_pool_size{state="max"}`.

### Error Handling

* Logs an error and **panics** if pool creation fails.

---

## Connection Management

```rust
pub fn get_connection(pool: &DbPool) -> Result<DbConnection, AuthServiceError>
```

### Purpose

Acquires a connection from the pool.

### Behavior

* On success:

  * Records `metrics::db::connection_acquired()`
  * Returns a live `DbConnection`
* On failure:

  * Logs the error
  * Records `metrics::db::connection_failed()`
  * Returns `AuthServiceError::database`

### Metrics

* `db_operations_total{operation="connection_acquire",result="success"}`
* `db_operations_total{operation="connection_acquire",result="failure"}`

---

## Database Migrations

```rust
pub fn run_migrations(pool: &DbPool) -> Result<(), AuthServiceError>
```

### Purpose

Runs embedded Diesel migrations at startup to ensure the schema is up-to-date.

### Behavior

* Embeds migrations with `embed_migrations!("migrations")`.
* Executes pending migrations using `run_pending_migrations`.
* Logs applied migrations or “schema is up to date”.

### Error Handling

* Logs error and returns `AuthServiceError::database` if migrations fail.

---

## Health Checks

```rust
pub async fn check_database_health(pool: &DbPool) -> Result<(), AuthServiceError>
```

### Purpose

Verifies database connectivity and responsiveness.

### Behavior

1. Runs in a `tokio::spawn_blocking` task (Diesel is synchronous).
2. Acquires a pooled connection.
3. Executes a trivial query `SELECT 1`.
4. Returns `Ok(())` if successful.

### Error Handling

* Logs WARN if query fails.
* Logs ERROR if the task cannot spawn or join.
* Returns `AuthServiceError::database` on failure.

---

## Metrics Integration

The `utils::metrics` module provides Prometheus counters, histograms, and gauges.

**Database-specific metrics used here:**

* **Connection Acquisition**

  * `db_operations_total{operation="connection_acquire",result="success"}`
  * `db_operations_total{operation="connection_acquire",result="failure"}`

* **Pool Size**

  * `db_pool_size{state="max"}` — gauge set when the pool is initialized.

**Other available namespaces (not directly used in this module):**

* `http_requests_total`, `http_request_duration_seconds`
* `auth_operations_total`
* `external_calls_total`
* `security_events_total`
* `errors_total`

---

## Logging

All key operations emit structured logs via [`tracing`](https://docs.rs/tracing):

* INFO — pool initialization, migrations, up-to-date schema
* ERROR — connection acquisition failures, migration errors, health check task failures
* WARN — health check query failures

---

## Tests

Tests are included under `#[cfg(test)]`.

* **Unit tests** (do not require DB):

  * Panic if `DATABASE_URL` missing
  * Constant validation
  * Mock-based error handling

* **Integration tests** (require PostgreSQL, marked `#[ignore]`):

  * Pool initialization
  * Connection acquisition
  * Health checks
  * Migrations (idempotency and fresh DB)
  * Concurrent health checks

---

## Example Usage

```rust
use crate::db::{init_pool, get_connection, run_migrations, check_database_health};

#[tokio::main]
async fn main() {
    // Initialize pool (panics if DATABASE_URL is not set)
    let pool = init_pool();

    // Run migrations
    run_migrations(&pool).expect("Migration failed");

    // Acquire connection
    let mut conn = get_connection(&pool).expect("Failed to acquire DB connection");

    // Health check (use in readiness probes)
    check_database_health(&pool)
        .await
        .expect("Database is unhealthy");
}
```

---

## References

* Diesel: [https://diesel.rs](https://diesel.rs)
* Diesel `PgConnection`: [docs](https://docs.diesel.rs/diesel/pg/struct.PgConnection.html)
* r2d2: [docs.rs/r2d2](https://docs.rs/r2d2/latest/r2d2/)
* diesel\_migrations: [docs.rs/diesel\_migrations](https://docs.rs/diesel_migrations/latest/diesel_migrations/)
* tracing: [docs.rs/tracing](https://docs.rs/tracing/latest/tracing/)
* prometheus crate: [docs.rs/prometheus](https://docs.rs/prometheus/latest/prometheus/)
