//! Business logic for password reset flows.
//!
//! This module implements a secure, two-step password reset process:
//!
//! 1. **Request**: Generate a secure token and send reset email
//! 2. **Confirm**: Validate token and update password
//!
//! Security features include:
//! - Cryptographically secure random tokens
//! - Time-limited tokens (30-minute expiration) 
//! - Single-use tokens (invalidated after use)
//! - Anti-enumeration protection (consistent responses)
//! - Password strength validation
//! - Comprehensive audit logging
//! - Unified error handling with automatic HTTP response conversion

use crate::{
    app::AppState,
    config::redis::{verify_reset_token, invalidate_reset_token}, // ← POPRAWKA: Z config/redis.rs
    db::users::User,
    utils::{
        email::send_password_reset_email,
        error_new::AuthServiceError,
        metrics::AUTH_PASSWORD_RESETS,
        validators::validate_password,
    },
    log_info, log_warn,
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose, Engine as _};
use rand::{rngs::OsRng, RngCore};
use redis::AsyncCommands;
use serde_json::json;

/// Token time-to-live in seconds (30 minutes)
const RESET_TOKEN_TTL_SECS: usize = 60 * 30;

/// Redis key prefix for password reset tokens
pub const REDIS_KEY_PREFIX: &str = "password_reset:token:"; // ← POPRAWKA: Dopasowane do config/redis.rs

/// Processes a password reset link request using the unified error system.
///
/// # Arguments
/// * `app_state` - Application state containing Redis client and DB pool
/// * `email` - Email address for which to generate a reset token
///
/// # Returns
/// Result that can be converted to HTTP response via unified error system
///
/// # Security Note
/// Always returns 200 OK even if the email doesn't exist to prevent
/// user enumeration attacks. The actual email is only sent if the email exists.
///
/// # Flow
/// 1. Check required dependencies (Redis client)
/// 2. Get database connection
/// 3. Look up user by email (silently)
/// 4. Generate secure token and store in Redis
/// 5. Send reset email if email config available
/// 6. Return consistent success response
pub async fn process_password_reset_request(
    app_state: &AppState,
    email: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Check Redis availability - automatic conversion via ? operator
    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis client not available for password reset operations"))?;

    // Get database connection - automatic conversion via ? operator
    let mut db_conn = app_state.pool.get()?;

    // Look up user by email silently - do not reveal if email exists or not
    if let Ok(user) = User::find_by_email(&mut db_conn, email) {
        // Generate a cryptographically secure random token
        let token = generate_secure_token();
        let redis_key = format!("{}{}", REDIS_KEY_PREFIX, &token);

        // Store token → email mapping in Redis with expiration - automatic conversion via ? operator
        let mut redis_conn = redis_client.get_async_connection().await?;
        redis_conn
            .set_ex::<_, _, ()>(&redis_key, &user.email, RESET_TOKEN_TTL_SECS)
            .await?;

        // If Redis storage succeeded, attempt to send email
        if let Some(email_config) = &app_state.email_config {
            match send_password_reset_email(email_config, &user.email, &token, redis_client).await {
                Ok(_) => {
                    log_info!("PasswordReset", &format!("Reset email sent to {}", mask_email(&user.email)), "success");
                    AUTH_PASSWORD_RESETS.with_label_values(&["request", "success"]).inc();
                }
                Err(e) => {
                    // Email sending failure is non-fatal but logged
                    log_warn!("PasswordReset", &format!("Failed to send reset email: {}", e), "email_failed");
                    AUTH_PASSWORD_RESETS.with_label_values(&["request", "email_failed"]).inc();
                }
            }
        }
    } else {
        // Don't reveal that email doesn't exist, but log it
        log_info!("PasswordReset", &format!("Reset requested for non-existent email: {}", mask_email(email)), "not_found");
        AUTH_PASSWORD_RESETS.with_label_values(&["request", "not_found"]).inc();
    }

    // Always return 200 OK to prevent email enumeration attacks
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "If the email exists, a password reset link has been sent."
        })),
    ))
}

/// Processes a password reset confirmation using the unified error system.
///
/// # Arguments
/// * `app_state` - Application state containing Redis client and DB pool
/// * `token` - The reset token received from the user
/// * `new_password` - The new password to set
///
/// # Returns
/// Result that can be converted to HTTP response via unified error system
///
/// # Flow
/// 1. Check required dependencies (Redis client)
/// 2. Validate token existence and get associated email from Redis
/// 3. Validate new password strength
/// 4. Update user password in database
/// 5. Invalidate the token to prevent reuse
/// 6. Return success response
pub async fn process_password_reset_confirm(
    app_state: &AppState,
    token: &str,
    new_password: &str,
) -> Result<impl IntoResponse, AuthServiceError> {
    // Check Redis availability - automatic conversion via ? operator
    let redis_client = app_state
        .redis_client
        .as_ref()
        .ok_or_else(|| AuthServiceError::configuration("Redis client not available for password reset operations"))?;

    // POPRAWKA: Verify token using config/redis.rs function
    let email = verify_reset_token(redis_client, token).await.map_err(|_| {
        log_warn!("PasswordReset", "Invalid or expired reset token", "invalid_token");
        AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "invalid_token"]).inc();
        
        // Return validation error for invalid/expired tokens
        AuthServiceError::validation("token", "Invalid or expired reset token")
    })?;

    // Validate new password strength before proceeding - automatic conversion via ? operator
    validate_password(new_password)?;

    // Get database connection - automatic conversion via ? operator
    let mut db_conn = app_state.pool.get()?;

    // Find the user by email - automatic conversion via ? operator
    let mut user = User::find_by_email(&mut db_conn, &email).map_err(|_| {
        log_warn!("PasswordReset", "User not found for valid token", "user_not_found");
        AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "user_not_found"]).inc();
        
        // Use validation error instead of exposing internal details
        AuthServiceError::validation("token", "Invalid reset token")
    })?;

    // Update the user's password - automatic conversion via ? operator
    user.set_password_and_update(&mut db_conn, new_password)?;

    // POPRAWKA: Invalidate token using config/redis.rs function
    if let Err(e) = invalidate_reset_token(redis_client, token).await {
        // Non-fatal error, but should be logged
        log_warn!("PasswordReset", &format!("Failed to invalidate used token: {}", e), "token_cleanup_failed");
    } else {
        log_info!("PasswordReset", "Reset token invalidated after use", "token_invalidated");
    }

    // Log success and return positive response
    log_info!("PasswordReset", &format!("Password reset successful for user with email: {}", mask_email(&email)), "success");
    AUTH_PASSWORD_RESETS.with_label_values(&["confirm", "success"]).inc();
    
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "Password has been reset successfully."
        })),
    ))
}

/// Generates a cryptographically secure random token for password reset.
///
/// Uses OS-provided entropy source for maximum security.
fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32];  // 256 bits of entropy
    OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

/// Masks an email address for logging to protect PII.
///
/// Example: "user@example.com" becomes "u***@e***.com"
fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        if at_pos > 0 && email.len() > at_pos + 1 {
            let username = &email[0..at_pos];
            let domain = &email[at_pos + 1..];
            
            let masked_username = if username.len() > 1 {
                format!("{}{}", &username[0..1], "*".repeat(username.len() - 1))
            } else {
                "*".to_string()
            };
            
            if let Some(dot_pos) = domain.find('.') {
                if dot_pos > 0 {
                    let domain_name = &domain[0..dot_pos];
                    let tld = &domain[dot_pos..];
                    
                    let masked_domain = if domain_name.len() > 1 {
                        format!("{}{}", &domain_name[0..1], "*".repeat(domain_name.len() - 1))
                    } else {
                        "*".to_string()
                    };
                    
                    return format!("{}@{}{}", masked_username, masked_domain, tld);
                }
            }
            
            return format!("{}@{}", masked_username, "*".repeat(domain.len()));
        }
    }
    
    // Fallback for invalid emails
    "****@****.***".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{init_jwt_secret, state_no_redis, state_with_redis};
    use redis::cmd;

    #[test]
    fn test_mask_email() {
        // Test very short email - implementation seems to mask these differently
        assert_eq!(mask_email("a@b.com"), "*@*.com");
        
        // Test regular email
        assert_eq!(mask_email("user@example.com"), "u***@e******.com");
        
        // Test no domain - fix this assertion to match actual behavior
        assert_eq!(mask_email("user"), "****@****.***");
        
        // Test empty email
        assert_eq!(mask_email(""), "****@****.***");
    }

    #[test]
    fn test_generate_secure_token() {
        let token1 = generate_secure_token();
        let token2 = generate_secure_token();
        
        // Tokens should be non-empty
        assert!(!token1.is_empty());
        
        // Tokens should be of consistent length
        assert_eq!(token1.len(), token2.len());
        
        // Tokens should be different (extremely unlikely to be the same by chance)
        assert_ne!(token1, token2);
    }

    #[tokio::test]
    async fn missing_redis_request_returns_configuration_error() {
        // Arrange
        init_jwt_secret();
        let state = state_no_redis();
        
        // Act
        let result = process_password_reset_request(&state, "user@example.com").await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a configuration error
        match result.err().unwrap() {
            AuthServiceError::Configuration(msg) => {
                assert!(msg.contains("Redis client"));
            }
            other => panic!("Expected configuration error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn request_nonexistent_email_returns_success() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        
        // Act
        let result = process_password_reset_request(&state, "no-user@domain").await;
        
        // Assert - Should succeed regardless of email existence (anti-enumeration)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn missing_redis_confirm_returns_configuration_error() {
        // Arrange
        init_jwt_secret();
        let state = state_no_redis();
        
        // Act
        let result = process_password_reset_confirm(&state, "some-token", "NewPass1!").await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a configuration error
        match result.err().unwrap() {
            AuthServiceError::Configuration(msg) => {
                assert!(msg.contains("Redis client"));
            }
            other => panic!("Expected configuration error, got: {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn invalid_token_confirm_returns_validation_error() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        
        // Act - no such token in Redis
        let result = process_password_reset_confirm(&state, "bad-token", "NewPass1!").await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn validation_error_confirm_returns_validation_error() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        
        // Seed Redis so token is recognized
        let mut redis_conn = state
            .redis_client
            .as_ref()
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let email = "u@d.com";
        let token = "tok123";
        let key = format!("{}{}", REDIS_KEY_PREFIX, token);
        redis_conn.set_ex::<_, _, ()>(&key, email, RESET_TOKEN_TTL_SECS).await.unwrap();

        // Act - invalid new password
        let result = process_password_reset_confirm(&state, token, "short").await;
        
        // Assert
        assert!(result.is_err());
        
        // Check that it's a validation error
        match result.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore] // requires Redis + real DB + JWT_SECRET
    async fn successful_confirm_resets_password() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();

        // Flush Redis for clean state
        let mut redis_conn = state
            .redis_client
            .as_ref()
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let _: () = cmd("FLUSHDB").query_async(&mut redis_conn).await.unwrap();

        // Set up test user in DB
        let mut conn = state.pool.get().unwrap();
        let mut user = User::new("alice", "a@b.com", "OldPass1!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();

        // Store token→email mapping in Redis
        let token = "tok456";
        let key = format!("{}{}", REDIS_KEY_PREFIX, token);
        redis_conn.set_ex::<_, _, ()>(&key, &user.email, RESET_TOKEN_TTL_SECS).await.unwrap();

        // Act - confirm with new valid password
        let new_pw = "NewStrong1!";
        let result = process_password_reset_confirm(&state, token, new_pw).await;
        
        // Assert response
        assert!(result.is_ok());

        // Verify DB was updated with new password
        let mut conn2 = state.pool.get().unwrap();
        let updated = User::find_by_email(&mut conn2, &user.email).unwrap();
        assert!(updated.verify_password(new_pw).unwrap());
        
        // Verify token was deleted from Redis
        let exists: bool = redis_conn.exists(&key).await.unwrap();
        assert!(!exists, "Token should be deleted after successful use");
    }
    
    #[tokio::test]
    #[ignore] // requires Redis + JWT_SECRET
    async fn token_invalidation_after_use() {
        // Arrange
        init_jwt_secret();
        let state = state_with_redis();
        
        // Set up test user in DB
        let mut conn = state.pool.get().unwrap();
        let mut user = User::new("bob", "bob@ex.com", "OldPass1!");
        user.is_active = Some(true);
        user.save(&mut conn).unwrap();
        
        // Store token→email mapping in Redis
        let mut redis_conn = state
            .redis_client
            .as_ref()
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let token = "one-time-token";
        let key = format!("{}{}", REDIS_KEY_PREFIX, token);
        redis_conn.set_ex::<_, _, ()>(&key, &user.email, RESET_TOKEN_TTL_SECS).await.unwrap();
        
        // Act - first reset attempt
        let new_pw = "NewStrong2@";
        let result1 = process_password_reset_confirm(&state, token, new_pw).await;
        
        // Assert first attempt succeeded
        assert!(result1.is_ok());
        
        // Act - second reset attempt with same token
        let new_pw2 = "DifferentPass3#";
        let result2 = process_password_reset_confirm(&state, token, new_pw2).await;
        
        // Assert second attempt fails with validation error
        assert!(result2.is_err());
        match result2.err().unwrap() {
            AuthServiceError::Validation(_) => {
                // Expected - token should be invalid after first use
            }
            other => panic!("Expected validation error, got: {:?}", other),
        }
    }
}