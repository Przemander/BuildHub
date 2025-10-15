//! # Hashing Utilities
//!
//! Provides both cryptographic password hashing (Argon2id) and non-cryptographic
//! hashing utilities for creating privacy-preserving identifiers.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use once_cell::sync::Lazy;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use tracing::info;

use crate::utils::errors::AuthServiceError;

// ===========================================================================
// PASSWORD HASHING CONFIGURATION
// ===========================================================================

// Argon2id parameters, balanced for both security and performance.
// These parameters can be adjusted via environment variables in production.
const ARGON2_MEMORY_COST: u32 = 32768; // 32 MB
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 2;
const ARGON2_VERSION: Version = Version::V0x13;

/// A global, thread-safe, lazily-initialized instance of the Argon2 hasher.
static ARGON2_HASHER: Lazy<Argon2<'static>> = Lazy::new(|| {
    // Try to load custom parameters from environment variables, if defined.
    let memory = std::env::var("ARGON2_MEMORY_COST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(ARGON2_MEMORY_COST);
        
    let time = std::env::var("ARGON2_TIME_COST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(ARGON2_TIME_COST);
        
    let parallelism = std::env::var("ARGON2_PARALLELISM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(ARGON2_PARALLELISM);
        
    info!(
        "Initializing Argon2 hasher with memory={}, time={}, parallelism={}",
        memory, time, parallelism
    );
        
    Argon2::new(
        argon2::Algorithm::Argon2id,
        ARGON2_VERSION,
        Params::new(memory, time, parallelism, None)
            .expect("Invalid Argon2 params"),
    )
});

// ===========================================================================
// PASSWORD HASHING FUNCTIONS
// ===========================================================================

/// Hashes a password using the configured Argon2id parameters.
/// This is a CPU-intensive operation by design.
#[tracing::instrument(skip(password), name = "hash_password")]
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    
    ARGON2_HASHER
        .hash_password(password.as_bytes(), &salt)
        .expect("Password hashing failed - this is a critical configuration error")
        .to_string()
}

/// Verifies a password against a stored hash.
/// Returns true if the password matches, false otherwise.
/// This is a CPU-intensive operation by design.
#[tracing::instrument(skip(password, hash), name = "verify_password")]
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthServiceError> {
    let start_time = std::time::Instant::now();
    
    // Poprawka: obsługa błędów
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Invalid password hash format: {}", e);
            return Err(AuthServiceError::internal("Invalid password hash format in database."));
        }
    };

    let result = ARGON2_HASHER
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    tracing::info!(
        "Password verification took {:?}",
        start_time.elapsed()
    );

    Ok(result)
}

// ===========================================================================
// NON-CRYPTOGRAPHIC HASHING FUNCTIONS
// ===========================================================================

/// Creates a privacy-preserving hash of a string, typically for a rate limiting key.
///
/// This uses a non-cryptographic hasher to create a stable identifier for a string
/// (like an email or username) without storing the original value in keys.
/// The hashing is case-insensitive.
#[inline]
pub fn create_rate_limit_key(identifier: &str) -> String {
    let mut hasher = DefaultHasher::new();
    identifier.to_lowercase().hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

// ===========================================================================
// TESTS
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "Test123!";
        let hash = hash_password(password);
        
        // Verify the hash is in correct PHC format
        assert!(hash.starts_with("$argon2id$"));
        
        // Verify correct password works
        assert!(verify_password(password, &hash).unwrap());
        
        // Verify wrong password fails
        assert!(!verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_rate_limit_key_generation() {
        // Same input produces same output
        let key1 = create_rate_limit_key("test@example.com");
        let key2 = create_rate_limit_key("test@example.com");
        assert_eq!(key1, key2);
        
        // Case insensitive
        let key3 = create_rate_limit_key("TEST@example.com");
        assert_eq!(key1, key3);
        
        // Different inputs produce different outputs
        let key4 = create_rate_limit_key("other@example.com");
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_verify_password_invalid_hash_returns_error() {
        let err = verify_password("whatever", "not-a-valid-hash").unwrap_err();
        assert!(err.to_string().contains("Invalid password hash"));
    }
}