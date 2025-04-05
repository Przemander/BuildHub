//! Database configuration and connection pool management.
//!
//! This module provides functionality for setting up and managing
//! the SQLite database connection pool using Diesel and r2d2.

use diesel::r2d2::{ConnectionManager, Pool };
use diesel::SqliteConnection;
use std::env;
use log::{info, debug};

/// Type alias for the database connection pool.
pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

/// Initialize the database connection pool using the DATABASE_URL environment variable.
///
/// Creates a pool of connections to the SQLite database based on the configured URL.
/// The pool automatically handles connection management, reusing connections when possible
/// and creating new ones as needed up to the configured limit.
///
/// # Returns
/// A configured connection pool ready for use by request handlers
///
/// # Panics
/// Panics if the DATABASE_URL environment variable is not set or if the pool creation fails
pub fn init_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env or environment variables");
    
    info!("Initializing database connection pool to {}", database_url);
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    
    // Configure pool with reasonable defaults for SQLite
    let pool = Pool::builder()
        .max_size(15) // SQLite has limits on concurrent writers
        .min_idle(Some(1)) // Keep at least one connection ready
        .build(manager)
        .expect("Failed to create database connection pool.");
    
    debug!("Database connection pool initialized successfully");
    pool
}