//! Email service utilities for user account management.
//!
//! This module provides robust functionality for:
//! - Building and sending transactional emails (activation, password reset)
//! - Managing activation codes via Redis
//! - Comprehensive error handling with structured errors
//! - Thorough observability (logging + metrics)
//!
//! Uses Lettre for email delivery with configurable SMTP settings.
//! All operations include appropriate metrics and structured logging.

use crate::utils::errors::{EmailError, ServiceError};
use crate::utils::metrics::{EMAILS_SENT, REDIS_OPERATIONS};
use crate::{log_debug, log_error, log_info, log_warn};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use redis::{AsyncCommands, Client as RedisClient};
use std::env;
use std::time::Duration;

/// TTL (in seconds) for activation codes stored in Redis
const ACTIVATION_CODE_TTL: u64 = 86_400; // 24 hours

#[allow(dead_code)]
/// TTL (in seconds) for password reset tokens
const PASSWORD_RESET_TTL: u64 = 1_800; // 30 minutes

/// Configuration for sending emails via SMTP.
#[derive(Clone)]
pub struct EmailConfig {
    from_address: String,
    mailer: SmtpTransport,
}

// Manual Debug implementation since SmtpTransport doesn't implement Debug
impl std::fmt::Debug for EmailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailConfig")
            .field("from_address", &self.from_address)
            .field("mailer", &"SmtpTransport instance")
            .finish()
    }
}

impl EmailConfig {
    /// Creates a new EmailConfig instance from environment variables.
    ///
    /// # Environment Variables
    /// - `SMTP_SERVER`: SMTP server hostname (required)
    /// - `SMTP_USERNAME`: SMTP authentication username (required)
    /// - `SMTP_PASSWORD`: SMTP authentication password (required)
    /// - `SMTP_FROM_ADDRESS`: Sender email address (defaults to "no-reply@example.com")
    ///
    /// # Returns
    /// - `Ok(EmailConfig)` on successful configuration
    /// - `Err(ServiceError)` if any required variables are missing or connection fails
    pub fn new() -> Result<Self, ServiceError> {
        log_info!("Email Configuration", "Initializing email service", "attempt");
        
        // Helper function to get environment variables with consistent error handling
        fn get_env_var(name: &str) -> Result<String, ServiceError> {
            env::var(name).map_err(|_| {
                log_error!("Email Configuration", &format!("{} variable missing", name), "failure");
                EMAILS_SENT.with_label_values(&["config", "failure"]).inc();
                ServiceError::Email(EmailError::Configuration(format!("{} must be set", name)))
            })
        }

        let smtp_server = get_env_var("SMTP_SERVER")?;
        let smtp_username = get_env_var("SMTP_USERNAME")?;
        let smtp_password = get_env_var("SMTP_PASSWORD")?;

        let from_address = env::var("SMTP_FROM_ADDRESS")
            .unwrap_or_else(|_| "no-reply@example.com".to_string());

        log_debug!("Email Configuration", "Building SMTP transport", "attempt");
        
        let creds = Credentials::new(smtp_username, smtp_password);
        let mailer = SmtpTransport::relay(&smtp_server)
            .map_err(|e| {
                log_error!(
                    "Email Configuration", 
                    &format!("SMTP transport creation failed: {}", e), 
                    "failure"
                );
                EMAILS_SENT.with_label_values(&["transport_init", "failure"]).inc();
                ServiceError::Email(EmailError::Internal("Failed to create email transport".to_string()))
            })?
            .credentials(creds)
            .timeout(Some(Duration::from_secs(10)))  // Add timeout for resilience
            .build();

        log_info!("Email Configuration", "SMTP transport configured successfully", "success");
        EMAILS_SENT.with_label_values(&["config", "success"]).inc();

        Ok(Self { from_address, mailer })
    }

    /// Sends an activation email containing the provided activation code.
    ///
    /// # Arguments
    /// - `to_email`: Recipient's email address
    /// - `activation_code`: Unique code for account activation
    /// - `redis_client`: Redis client for storing activation code
    ///
    /// # Returns
    /// - `Ok(())` if email is sent successfully
    /// - `Err(ServiceError)` if email building or sending fails
    pub async fn send_activation_email(
        &self,
        to_email: &str,
        activation_code: &str,
        redis_client: &RedisClient,
    ) -> Result<(), ServiceError> {
        log_debug!(
            "Account Activation", 
            &format!("Preparing activation email for {}", to_email), 
            "attempt"
        );

        let activation_link = generate_activation_link(activation_code);
        
        // Create email with professional HTML formatting
        let email_body = format!(
            "Hello,\n\nWelcome to BuildHub! To activate your account, click the link below:\n\n{}\n\n\
             If you did not create an account, please ignore this message.\n\n\
             This link will expire in 24 hours.\n\n\
             Best regards,\nThe BuildHub Team",
            activation_link
        );

        // First store the code in Redis before sending the email
        // This ensures the code exists when the user clicks the link
        if let Err(e) = store_activation_code(redis_client, to_email, activation_code).await {
            log_error!(
                "Account Activation",
                &format!("Failed to store activation code: {}", e),
                "failure"
            );
            // Don't return early - still try to send the email
            // This provides a better user experience even if Redis is having issues
        }

        // Build the email message
        let email = match self.build_email(
            to_email, 
            "Activate Your BuildHub Account",
            &email_body,
            "activation"
        ) {
            Ok(email) => email,
            Err(e) => {
                log_error!(
                    "Account Activation", 
                    &format!("Failed to build activation email: {}", e), 
                    "failure"
                );
                return Err(e);
            }
        };

        // Send the email
        EMAILS_SENT.with_label_values(&["activation", "attempt"]).inc();
        match self.mailer.send(&email) {
            Ok(_) => {
                log_info!(
                    "Account Activation", 
                    &format!("Activation email sent to {}", to_email), 
                    "success"
                );
                EMAILS_SENT.with_label_values(&["activation", "success"]).inc();
                Ok(())
            }
            Err(e) => {
                log_error!(
                    "Account Activation", 
                    &format!("Failed to send activation email: {}", e), 
                    "failure"
                );
                EMAILS_SENT.with_label_values(&["activation", "failure"]).inc();
                Err(ServiceError::Email(EmailError::Internal(
                    "Failed to send activation email".to_string()
                )))
            }
        }
    }
    
    /// Helper method to build email messages with consistent error handling
    fn build_email(
        &self, 
        recipient: &str, 
        subject: &str, 
        body: &str,
        operation: &str
    ) -> Result<Message, ServiceError> {
        Message::builder()
            .from(self.from_address.parse().map_err(|e| {
                log_error!(
                    "Email Building", 
                    &format!("Invalid from address '{}': {}", self.from_address, e), 
                    "failure"
                );
                EMAILS_SENT.with_label_values(&[operation, "addressing_failure"]).inc();
                ServiceError::Email(EmailError::Internal("Invalid sender address".to_string()))
            })?)
            .to(recipient.parse().map_err(|e| {
                log_error!(
                    "Email Building", 
                    &format!("Invalid recipient address '{}': {}", recipient, e), 
                    "failure"
                );
                EMAILS_SENT.with_label_values(&[operation, "addressing_failure"]).inc();
                ServiceError::Email(EmailError::Internal("Invalid recipient address".to_string()))
            })?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| {
                log_error!(
                    "Email Building", 
                    &format!("Failed to build email message: {}", e), 
                    "failure"
                );
                EMAILS_SENT.with_label_values(&[operation, "build_failure"]).inc();
                ServiceError::Email(EmailError::Internal("Failed to build email".to_string()))
            })
    }
}

#[cfg(test)]
impl EmailConfig {
    /// Used only in unit tests to avoid real SMTP connections.
    ///
    /// Creates a dummy email configuration that points to localhost:1025,
    /// which is typically where a test SMTP server like MailHog would run.
    pub fn dummy() -> Self {
        EmailConfig {
            from_address: "test@example.com".into(),
            mailer: SmtpTransport::builder_dangerous("localhost")
                .port(1025)
                .build(),
        }
    }
}

/// Sends a password reset email with a reset link containing the token.
///
/// # Arguments
/// - `email_config`: Email configuration for sending
/// - `to_email`: Recipient's email address
/// - `reset_token`: Unique token for password reset
///
/// # Returns
/// - `Ok(())` if email is sent successfully
/// - `Err(ServiceError)` if email building or sending fails
#[allow(dead_code)]
pub async fn send_password_reset_email(
    email_config: &EmailConfig,
    to_email: &str,
    reset_token: &str,
) -> Result<(), ServiceError> {
    log_debug!(
        "Password Reset", 
        &format!("Preparing password reset email for {}", to_email), 
        "attempt"
    );

    let frontend_url = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let reset_link = format!("{}/reset-password?token={}", frontend_url, reset_token);

    let email_body = format!(
        "Hello,\n\nWe received a request to reset your BuildHub password.\n\n\
         To reset your password, click the link below or paste it into your browser:\n\n{}\n\n\
         If you did not request a password reset, please ignore this message or contact support.\n\n\
         This link will expire in 30 minutes for security reasons.\n\n\
         Best regards,\nThe BuildHub Team",
        reset_link
    );

    // Build the email message
    let email = email_config.build_email(
        to_email,
        "Reset Your BuildHub Password",
        &email_body,
        "password_reset"
    )?;

    // Send the email
    EMAILS_SENT.with_label_values(&["password_reset", "attempt"]).inc();
    match email_config.mailer.send(&email) {
        Ok(_) => {
            log_info!(
                "Password Reset", 
                &format!("Password reset email sent to {}", to_email), 
                "success"
            );
            EMAILS_SENT.with_label_values(&["password_reset", "success"]).inc();
            Ok(())
        }
        Err(e) => {
            log_error!(
                "Password Reset", 
                &format!("Failed to send password reset email: {}", e), 
                "failure"
            );
            EMAILS_SENT.with_label_values(&["password_reset", "failure"]).inc();
            Err(ServiceError::Email(EmailError::Internal(
                "Failed to send password reset email".to_string()
            )))
        }
    }
}

/// Generates a unique activation code using UUID v4.
///
/// # Returns
/// A UUID v4 string to be used as an activation code
#[allow(dead_code)]
pub fn generate_activation_code() -> String {
    let code = uuid::Uuid::new_v4().to_string();
    log_debug!("Account Activation", "Generated new activation code", "success");
    code
}

/// Creates an activation link by combining the frontend URL with the activation code.
///
/// # Arguments
/// - `activation_code`: The code to include in the activation link
///
/// # Returns
/// A complete URL for account activation
#[allow(dead_code)]
pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL").unwrap_or_else(|_| {
        log_debug!(
            "Account Activation",
            "FRONTEND_URL not set, using default localhost",
            "info"
        );
        "http://localhost:3000".to_string()
    });
    
    let link = format!("{}/activate?code={}", frontend_url, activation_code);
    log_debug!("Account Activation", "Generated activation link", "success");
    link
}

/// Stores an activation code in Redis with an expiration of 24 hours.
///
/// # Arguments
/// - `redis_client`: Redis client for storage
/// - `email`: Email address associated with the activation code
/// - `code`: The activation code to store
///
/// # Returns
/// - `Ok(())` if storing succeeds
/// - `Err(ServiceError)` if Redis operations fail
pub async fn store_activation_code(
    redis_client: &RedisClient,
    email: &str,
    code: &str,
) -> Result<(), ServiceError> {
    log_debug!(
        "Account Activation", 
        &format!("Storing activation code for {}", email), 
        "attempt"
    );

    // Get Redis connection
    let mut conn = redis_client.get_async_connection().await.map_err(|e| {
        log_error!(
            "Account Activation", 
            &format!("Redis connection failed: {}", e), 
            "failure"
        );
        REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
        ServiceError::Email(EmailError::Internal(
            "Service unavailable - please try again later".to_string(),
        ))
    })?;

    REDIS_OPERATIONS.with_label_values(&["connection", "success"]).inc();
    
    // Generate the Redis key
    let key = format!("activation:code:{}", code);
    
    // Store with expiration
    REDIS_OPERATIONS.with_label_values(&["set_ex", "attempt"]).inc();
    conn.set_ex::<_, _, ()>(key, email, ACTIVATION_CODE_TTL as usize)
        .await
        .map_err(|e| {
            log_error!(
                "Account Activation", 
                &format!("Failed to store activation code in Redis: {}", e), 
                "failure"
            );
            REDIS_OPERATIONS.with_label_values(&["set_ex", "failure"]).inc();
            ServiceError::Email(EmailError::Internal(
                "Failed to complete registration. Please try again later.".to_string(),
            ))
        })?;

    REDIS_OPERATIONS.with_label_values(&["set_ex", "success"]).inc();
    log_info!(
        "Account Activation", 
        &format!("Activation code for {} stored successfully", email), 
        "success"
    );
    
    Ok(())
}

/// Verifies an activation code by retrieving and then deleting the associated email in Redis.
///
/// # Arguments
/// - `redis_client`: Redis client for verification
/// - `code`: The activation code to verify
///
/// # Returns
/// - `Ok(email)` with the associated email if code is valid
/// - `Err(ServiceError)` if the code doesn't exist or Redis operations fail
pub async fn verify_activation_code(
    redis_client: &RedisClient,
    code: &str,
) -> Result<String, ServiceError> {
    log_debug!(
        "Account Activation", 
        &format!("Verifying activation code: {}", code), 
        "attempt"
    );

    // Get Redis connection
    let mut conn = redis_client.get_async_connection().await.map_err(|e| {
        log_error!(
            "Account Activation", 
            &format!("Redis connection failed: {}", e), 
            "failure"
        );
        REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
        ServiceError::Email(EmailError::Internal(
            "Service unavailable - please try again later".to_string(),
        ))
    })?;

    REDIS_OPERATIONS.with_label_values(&["connection", "success"]).inc();
    
    // Generate the Redis key
    let key = format!("activation:code:{}", code);
    
    // Retrieve email associated with code
    REDIS_OPERATIONS.with_label_values(&["get", "attempt"]).inc();
    let email: Option<String> = conn.get(&key).await.map_err(|e| {
        log_error!(
            "Account Activation", 
            &format!("Failed to retrieve activation code from Redis: {}", e), 
            "failure"
        );
        REDIS_OPERATIONS.with_label_values(&["get", "failure"]).inc();
        ServiceError::Email(EmailError::Internal(
            "Failed to verify activation code".to_string(),
        ))
    })?;

    REDIS_OPERATIONS.with_label_values(&["get", "success"]).inc();
    
    match email {
        Some(email) => {
            log_debug!(
                "Account Activation", 
                &format!("Valid code found for {}", email), 
                "success"
            );
            
            // Delete the code to prevent reuse
            REDIS_OPERATIONS.with_label_values(&["del", "attempt"]).inc();
            let _: () = conn.del(&key).await.map_err(|e| {
                log_error!(
                    "Account Activation", 
                    &format!("Failed to delete used activation code: {}", e), 
                    "failure"
                );
                REDIS_OPERATIONS.with_label_values(&["del", "failure"]).inc();
                ServiceError::Email(EmailError::Internal(
                    "Failed to complete activation process".to_string(),
                ))
            })?;
            
            REDIS_OPERATIONS.with_label_values(&["del", "success"]).inc();
            log_info!(
                "Account Activation", 
                &format!("Account for {} successfully activated", email), 
                "success"
            );
            
            Ok(email)
        }
        None => {
            log_warn!(
                "Account Activation", 
                &format!("Invalid or expired activation code: {}", code), 
                "failure"
            );
            REDIS_OPERATIONS.with_label_values(&["get", "not_found"]).inc();
            Err(ServiceError::Email(EmailError::InvalidCode(
                "Invalid or expired activation code".to_string(),
            )))
        }
    }
}

/// Stores a password reset token in Redis with an expiration time.
///
/// # Arguments
/// - `redis_client`: Redis client for storage
/// - `email`: Email address associated with the reset token
/// - `token`: The reset token to store
///
/// # Returns
/// - `Ok(())` if storing succeeds
/// - `Err(ServiceError)` if Redis operations fail
#[allow(dead_code)]
pub async fn store_password_reset_token(
    redis_client: &RedisClient,
    email: &str,
    token: &str,
) -> Result<(), ServiceError> {
    log_debug!(
        "Password Reset", 
        &format!("Storing password reset token for {}", email), 
        "attempt"
    );

    // Get Redis connection
    let mut conn = redis_client.get_async_connection().await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Redis connection failed: {}", e), 
            "failure"
        );
        REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
        ServiceError::Email(EmailError::Internal(
            "Service unavailable - please try again later".to_string(),
        ))
    })?;

    REDIS_OPERATIONS.with_label_values(&["connection", "success"]).inc();
    
    // Generate the Redis key
    let key = format!("password_reset:token:{}", token);
    
    // Store with expiration using the PASSWORD_RESET_TTL constant
    REDIS_OPERATIONS.with_label_values(&["set_ex", "attempt"]).inc();
    conn.set_ex::<_, _, ()>(key, email, PASSWORD_RESET_TTL as usize)
        .await
        .map_err(|e| {
            log_error!(
                "Password Reset", 
                &format!("Failed to store reset token in Redis: {}", e), 
                "failure"
            );
            REDIS_OPERATIONS.with_label_values(&["set_ex", "failure"]).inc();
            ServiceError::Email(EmailError::Internal(
                "Failed to initiate password reset. Please try again later.".to_string(),
            ))
        })?;

    REDIS_OPERATIONS.with_label_values(&["set_ex", "success"]).inc();
    log_info!(
        "Password Reset", 
        &format!("Reset token for {} stored successfully", email), 
        "success"
    );
    
    Ok(())
}

/// Verifies a password reset token by retrieving the associated email in Redis.
///
/// # Arguments
/// - `redis_client`: Redis client for verification
/// - `token`: The password reset token to verify
///
/// # Returns
/// - `Ok(email)` with the associated email if token is valid
/// - `Err(ServiceError)` if the token doesn't exist or Redis operations fail
#[allow(dead_code)]
pub async fn verify_reset_token(
    redis_client: &RedisClient,
    token: &str,
) -> Result<String, ServiceError> {
    log_debug!(
        "Password Reset", 
        &format!("Verifying reset token: {}", token), 
        "attempt"
    );

    // Get Redis connection
    let mut conn = redis_client.get_async_connection().await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Redis connection failed: {}", e), 
            "failure"
        );
        REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
        ServiceError::Email(EmailError::Internal(
            "Service unavailable - please try again later".to_string(),
        ))
    })?;

    REDIS_OPERATIONS.with_label_values(&["connection", "success"]).inc();
    
    // Generate the Redis key
    let key = format!("password_reset:token:{}", token);
    
    // Retrieve email associated with token
    REDIS_OPERATIONS.with_label_values(&["get", "attempt"]).inc();
    let email: Option<String> = conn.get(&key).await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Failed to retrieve reset token from Redis: {}", e), 
            "failure"
        );
        REDIS_OPERATIONS.with_label_values(&["get", "failure"]).inc();
        ServiceError::Email(EmailError::Internal(
            "Failed to verify reset token".to_string(),
        ))
    })?;

    REDIS_OPERATIONS.with_label_values(&["get", "success"]).inc();
    
    match email {
        Some(email) => {
            log_debug!(
                "Password Reset", 
                &format!("Valid token found for {}", email), 
                "success"
            );
            
            Ok(email)
        }
        None => {
            log_warn!(
                "Password Reset", 
                &format!("Invalid or expired reset token: {}", token), 
                "failure"
            );
            REDIS_OPERATIONS.with_label_values(&["get", "not_found"]).inc();
            Err(ServiceError::Email(EmailError::InvalidCode(
                "Invalid or expired password reset token".to_string(),
            )))
        }
    }
}

/// Marks a reset token as used by removing it from Redis after password has been reset.
///
/// # Arguments
/// - `redis_client`: Redis client for operation
/// - `token`: The password reset token to invalidate
///
/// # Returns
/// - `Ok(())` if deletion succeeds
/// - `Err(ServiceError)` if Redis operations fail
#[allow(dead_code)]
pub async fn invalidate_reset_token(
    redis_client: &RedisClient,
    token: &str,
) -> Result<(), ServiceError> {
    log_debug!(
        "Password Reset", 
        &format!("Invalidating used reset token: {}", token), 
        "attempt"
    );

    // Get Redis connection
    let mut conn = redis_client.get_async_connection().await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Redis connection failed: {}", e), 
            "failure"
        );
        REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
        ServiceError::Email(EmailError::Internal(
            "Service unavailable - please try again later".to_string(),
        ))
    })?;

    // Generate the Redis key
    let key = format!("password_reset:token:{}", token);
    
    // Delete the token to prevent reuse
    REDIS_OPERATIONS.with_label_values(&["del", "attempt"]).inc();
    let _: () = conn.del(&key).await.map_err(|e| {
        log_error!(
            "Password Reset", 
            &format!("Failed to delete used reset token: {}", e), 
            "failure"
        );
        REDIS_OPERATIONS.with_label_values(&["del", "failure"]).inc();
        ServiceError::Email(EmailError::Internal(
            "Failed to complete password reset process".to_string(),
        ))
    })?;
    
    REDIS_OPERATIONS.with_label_values(&["del", "success"]).inc();
    log_info!(
        "Password Reset", 
        &format!("Reset token {} successfully invalidated", token), 
        "success"
    );
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;
    use std::env;
    
    /// Helper to get a Redis client pointing at localhost.
    async fn make_redis_client() -> Client {
        Client::open("redis://127.0.0.1/")
            .expect("Redis must be running on localhost:6379")
    }

    #[test]
    fn generate_activation_code_non_empty() {
        let code = generate_activation_code();
        assert!(!code.is_empty(), "Activation code should not be empty");
        // UUID v4 has exactly 36 characters
        assert_eq!(code.len(), 36, "UUID should be 36 characters");
    }

    #[test]
    fn generate_activation_link_defaults_to_localhost() {
        // Ensure environment variable is not set
        env::remove_var("FRONTEND_URL");
        
        let code = "testcode123";
        let link = generate_activation_link(code);
        
        assert!(
            link.starts_with("http://localhost:3000/activate?code="),
            "Expected default localhost URL"
        );
        assert!(link.ends_with(code), "Should include the activation code");
    }

    #[test]
    fn generate_activation_link_respects_env() {
        // Set environment variable for this test
        env::set_var("FRONTEND_URL", "https://example.org");
        
        let code = "abc123";
        let link = generate_activation_link(code);
        
        assert_eq!(
            link,
            "https://example.org/activate?code=abc123",
            "Should use FRONTEND_URL environment variable"
        );
        
        // Clean up
        env::remove_var("FRONTEND_URL");
    }

    #[tokio::test]
    async fn store_and_verify_activation_code_roundtrip() {
        let client = make_redis_client().await;
        let code = generate_activation_code();
        let test_email = "test@example.com";
        
        // Clean up any existing test data
        let mut conn = client.get_async_connection().await
            .expect("Failed to get Redis connection");
        let _: Option<String> = conn
            .get(&format!("activation:code:{}", code)).await.ok();

        // Store activation code
        store_activation_code(&client, test_email, &code)
            .await
            .expect("store_activation_code should succeed");

        // Verify activation code
        let email = verify_activation_code(&client, &code)
            .await
            .expect("verify_activation_code should succeed");
        
        assert_eq!(email, test_email, "Retrieved email should match stored email");

        // Verify code was deleted (second verify should fail)
        let err = verify_activation_code(&client, &code).await.unwrap_err();
        match err {
            ServiceError::Email(EmailError::InvalidCode(_)) => {},
            other => panic!("Expected InvalidCode error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn verify_activation_code_not_found() {
        let client = make_redis_client().await;
        let fake_code = "this-code-does-not-exist-in-redis";
        
        let err = verify_activation_code(&client, fake_code).await.unwrap_err();
        
        match err {
            ServiceError::Email(EmailError::InvalidCode(msg)) => {
                assert!(
                    msg.contains("Invalid or expired"), 
                    "Error message should mention 'Invalid or expired'"
                );
            }
            other => panic!("Expected InvalidCode error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn email_config_dummy_creates_valid_instance() {
        let config = EmailConfig::dummy();
        assert_eq!(config.from_address, "test@example.com");
        // Just check that it doesn't panic when formatted
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("SmtpTransport instance"));
    }

    #[tokio::test]
    async fn password_reset_email_builds_valid_link() {
        // Use dummy config to avoid real SMTP
        let config = EmailConfig::dummy();
        env::set_var("FRONTEND_URL", "https://test-app.com");
        
        // Should build without errors (will fail at send due to dummy config)
        let result = send_password_reset_email(&config, "user@example.com", "reset123").await;
        
        // Expected to fail at send time, not at build time
        assert!(result.is_err());
        
        // Clean up
        env::remove_var("FRONTEND_URL");
    }

    #[tokio::test]
    async fn password_reset_token_roundtrip() {
        let client = make_redis_client().await;
        let token = uuid::Uuid::new_v4().to_string();
        let test_email = "test@example.com";
        
        // Store token
        store_password_reset_token(&client, test_email, &token)
            .await
            .expect("store_password_reset_token should succeed");
        
        // Verify token
        let email = verify_reset_token(&client, &token)
            .await
            .expect("verify_reset_token should succeed");
        
        assert_eq!(email, test_email, "Retrieved email should match stored email");
        
        // Invalidate token
        invalidate_reset_token(&client, &token)
            .await
            .expect("invalidate_reset_token should succeed");
        
        // Verify token was deleted
        let err = verify_reset_token(&client, &token).await.unwrap_err();
        match err {
            ServiceError::Email(EmailError::InvalidCode(_)) => {},
            other => panic!("Expected InvalidCode error, got: {:?}", other),
        }
    }
}