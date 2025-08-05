//! # Email Service Module
//!
//! This module provides production-ready email functionality for user account management
//! in the BuildHub authentication service. It offers robust, observable, and testable
//! email operations with comprehensive error handling.
//!
//! ## Features
//!
//! - **Transactional Emails**: Account activation and password reset emails
//! - **Production-Ready**: SMTP transport with timeouts and credential management
//! - **Test-Friendly**: Built-in test mode for development and CI/CD
//! - **Observable**: Comprehensive logging and metrics integration
//! - **Resilient**: Structured error handling with context preservation
//! - **Secure**: Redis integration for token management and verification
//!
//! ## Architecture
//!
//! The module follows a clean separation of concerns:
//! - Email building and sending logic
//! - Redis operations delegated to the `redis` module
//! - Error handling via the unified `AuthServiceError` system
//! - Metrics tracking via the dedicated `email_metrics` system
//!
//! ## Usage Example
//!
//! ```rust
//! use crate::utils::email::{EmailConfig, send_password_reset_email};
//!
//! async fn send_activation() -> Result<(), AuthServiceError> {
//!     let email_config = EmailConfig::new()?;
//!     let redis_client = redis::init_redis()?;
//!     
//!     email_config.send_activation_email(
//!         "user@example.com",
//!         "activation-code-123",
//!         &redis_client
//!     ).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Environment Variables
//!
//! | Variable | Required | Default | Description |
//! |----------|----------|---------|-------------|
//! | `SMTP_SERVER` | Yes | - | SMTP server hostname |
//! | `SMTP_USERNAME` | Yes | - | SMTP authentication username |
//! | `SMTP_PASSWORD` | Yes | - | SMTP authentication password |
//! | `SMTP_FROM_ADDRESS` | No | `no-reply@example.com` | Sender email address |
//! | `FRONTEND_URL` | No | `http://localhost:3000` | Frontend base URL for links |
//! | `TEST_MODE` | No | `false` | Enable test mode (logs instead of sending) |

// Add these imports for OpenTelemetry integration
use crate::utils::telemetry::{business_operation_span, SpanExt};
use tracing::Instrument;

use crate::config::redis::store_password_reset_token;
use crate::{
    config::redis::store_activation_code,
    utils::error_new::AuthServiceError,
    utils::log_new::Log,
    metricss::email_metrics::{
        // Core API functions
        record_email_failure, time_email_processing, email_types, failure_types,
        // Business helper functions
        record_activation_success, record_activation_failure, record_activation_failure_detailed,
        record_password_reset_success, record_password_reset_failure, record_password_reset_failure_detailed,
    },
};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use redis::Client as RedisClient;
use std::env;
use std::time::Duration;

// =============================================================================
// CORE TYPES AND CONFIGURATION
// =============================================================================

/// Email configuration with SMTP transport and sender settings
#[derive(Clone)]
pub struct EmailConfig {
    from_address: String,
    mailer: SmtpTransport,
}

impl std::fmt::Debug for EmailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailConfig")
            .field("from_address", &self.from_address)
            .field("mailer", &"SmtpTransport{configured}")
            .finish()
    }
}

// =============================================================================
// EMAIL CONFIGURATION AND INITIALIZATION
// =============================================================================

impl EmailConfig {
    /// Creates a new email configuration from environment variables
    ///
    /// This function initializes the email service with either:
    /// - A test configuration (if TEST_MODE=true)
    /// - A production SMTP configuration with credentials and timeouts
    ///
    /// # Returns
    ///
    /// A fully configured EmailConfig or an error if configuration fails
    pub fn new() -> Result<Self, AuthServiceError> {
        // Create span for email service initialization
        let span = business_operation_span("init_email_service");
        
        // Use the span to wrap the initialization logic
        span.in_scope(|| {
            Log::event(
                "INFO",
                "Email Configuration",
                "Initializing email service",
                "attempt",
                "EmailConfig::new"
            );
            
            // Test mode: Use mock SMTP configuration for development and testing
            if Self::is_test_mode() {
                Log::event(
                    "INFO",
                    "Email Configuration",
                    "Running in TEST_MODE - emails will be logged but not sent",
                    "info",
                    "EmailConfig::new"
                );
                
                span.record("test_mode", &true);
                span.record("result", &"success");
                
                return Ok(Self {
                    from_address: "test@example.com".into(),
                    mailer: SmtpTransport::builder_dangerous("localhost")
                        .port(1025) // Standard MailHog/test SMTP port
                        .build(),
                });
            }
            
            span.record("test_mode", &false);
            
            // Production mode: Configure real SMTP transport
            let smtp_server = match Self::get_required_env_var("SMTP_SERVER") {
                Ok(server) => server,
                Err(e) => {
                    span.record("result", &"failure");
                    span.record("failure_reason", &"missing_server_config");
                    return Err(e);
                }
            };
            
            let smtp_username = match Self::get_required_env_var("SMTP_USERNAME") {
                Ok(username) => username,
                Err(e) => {
                    span.record("result", &"failure");
                    span.record("failure_reason", &"missing_username_config");
                    return Err(e);
                }
            };
            
            let smtp_password = match Self::get_required_env_var("SMTP_PASSWORD") {
                Ok(password) => password,
                Err(e) => {
                    span.record("result", &"failure");
                    span.record("failure_reason", &"missing_password_config");
                    return Err(e);
                }
            };

            let from_address = env::var("SMTP_FROM_ADDRESS")
                .unwrap_or_else(|_| "no-reply@example.com".to_string());
            
            span.record("smtp_server", &smtp_server);
            span.record("from_address", &from_address);
            
            let credentials = Credentials::new(smtp_username, smtp_password);
            let mailer = SmtpTransport::relay(&smtp_server)
                .map_err(|e| {
                    Log::event(
                        "ERROR",
                        "Email Configuration",
                        &format!("SMTP transport creation failed: {}", e),
                        "failure",
                        "EmailConfig::new"
                    );
                    record_email_failure(failure_types::CONFIGURATION, email_types::ACTIVATION);
                    span.record("result", &"failure");
                    span.record("failure_reason", &"smtp_relay_creation_failed");
                    span.record_error(&e);
                    AuthServiceError::configuration("Failed to create email transport")
                })?
                .credentials(credentials)
                .timeout(Some(Duration::from_secs(10)))
                .build();

            Log::event(
                "INFO",
                "Email Configuration",
                "SMTP transport configured successfully",
                "success",
                "EmailConfig::new"
            );
            
            span.record("result", &"success");
            span.record("timeout_seconds", &10);

            Ok(Self { from_address, mailer })
        })
    }

    /// Retrieves a required environment variable with proper error handling
    fn get_required_env_var(name: &str) -> Result<String, AuthServiceError> {
        env::var(name).map_err(|_| {
            Log::event(
                "ERROR",
                "Email Configuration",
                &format!("{} variable missing", name),
                "failure",
                "get_required_env_var"
            );
            record_email_failure(failure_types::CONFIGURATION, email_types::ACTIVATION);
            AuthServiceError::configuration(&format!("{} must be set", name))
        })
    }

    /// Checks if the service is running in test mode
    fn is_test_mode() -> bool {
        env::var("TEST_MODE").is_ok_and(|v| v == "true")
    }
}

// =============================================================================
// EMAIL SENDING OPERATIONS
// =============================================================================

impl EmailConfig {
    /// Sends an account activation email with an activation link
    ///
    /// This function:
    /// 1. Stores the activation code in Redis
    /// 2. Creates an email with an activation link
    /// 3. Sends the email or logs it in test mode
    ///
    /// # Parameters
    ///
    /// * `to_email` - Recipient's email address
    /// * `activation_code` - Unique activation code for the user
    /// * `redis_client` - Redis client for storing the activation code
    ///
    /// # Returns
    ///
    /// Result indicating success or detailed error information
    pub async fn send_activation_email(
        &self,
        to_email: &str,
        activation_code: &str,
        redis_client: &RedisClient,
    ) -> Result<(), AuthServiceError> {
        // Create span for activation email
        let span = business_operation_span("send_activation_email");
        span.record("email_domain", &to_email.split('@').nth(1).unwrap_or("invalid"));
        span.record("code_length", &activation_code.len());
        
        // Clone span before moving it into async operation
        let span_clone = span.clone();
        
        // Use timer API to measure operation time
        let _timer = time_email_processing(email_types::ACTIVATION);
        
        // Wrap the email operation in the span
        async move {
            let activation_link = generate_activation_link(activation_code);
            
            let email_body = format!(
                "Hello,\n\n\
                 Welcome to BuildHub! To activate your account, click the link below:\n\n\
                 {}\n\n\
                 If you did not create an account, please ignore this message.\n\n\
                 This link will expire in 24 hours for security reasons.\n\n\
                 Best regards,\n\
                 The BuildHub Team",
                activation_link
            );

            // Store activation code in Redis before sending email
            if let Err(e) = store_activation_code(redis_client, to_email, activation_code).await {
                Log::event(
                    "ERROR",
                    "Account Activation",
                    &format!("Failed to store activation code: {}", e),
                    "failure",
                    "send_activation_email"
                );
                record_activation_failure_detailed(failure_types::TOKEN_STORAGE);
                span.record("result", &"failure");
                span.record("failure_reason", &"redis_store_failed");
                span.record_error(&e);
                return Err(AuthServiceError::from(e));
            }

            // Test mode: Log instead of sending
            if Self::is_test_mode() {
                Log::event(
                    "INFO",
                    "Account Activation",
                    &format!("TEST MODE: Would send activation email to {}", to_email),
                    "success",
                    "send_activation_email"
                );
                record_activation_success();
                span.record("result", &"success");
                span.record("test_mode", &true);
                return Ok(());
            }

            // Production mode: Build and send email
            let result = self.send_email_message(
                to_email,
                "Activate Your BuildHub Account",
                &email_body,
                email_types::ACTIVATION
            ).await;

            match result {
                Ok(()) => {
                    record_activation_success();
                    span.record("result", &"success");
                    Ok(())
                }
                Err(e) => {
                    record_activation_failure();
                    span.record("result", &"failure");
                    span.record("failure_reason", &"send_failed");
                    span.record_error(&e);
                    Err(e)
                }
            }
        }
        .instrument(span_clone)
        .await
    }
    
    /// Internal helper to send an email message via SMTP
    ///
    /// This function handles the core email sending with comprehensive error handling
    /// and classification of SMTP failures for better observability.
    async fn send_email_message(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
        email_type: &str,
    ) -> Result<(), AuthServiceError> {
        // Create span for email sending
        let span = business_operation_span("send_email");
        span.record("email_domain", &recipient.split('@').nth(1).unwrap_or("invalid"));
        span.record("email_type", &email_type);
        span.record("subject_length", &subject.len());
        span.record("body_length", &body.len());
        
        // Clone span before moving it into async operation
        let span_clone = span.clone();
        
        // Wrap the email sending in the span
        async move {
            // Create child span for message building
            let build_span = business_operation_span("build_email_message");
            build_span.record("email_type", &email_type);
            
            // Build email message within its own span
            let email = build_span.in_scope(|| {
                self.build_email_message(recipient, subject, body, email_type)
            })?;

            // Send via SMTP
            match self.mailer.send(&email) {
                Ok(_) => {
                    Log::event(
                        "INFO",
                        "Email Service",
                        &format!("{} email sent to {}", email_type, recipient),
                        "success",
                        "send_email_message"
                    );
                    span.record("result", &"success");
                    Ok(())
                }
                Err(e) => {
                    Log::event(
                        "ERROR",
                        "Email Service",
                        &format!("Failed to send {} email: {}", email_type, e),
                        "failure",
                        "send_email_message"
                    );
                    
                    // Enhanced SMTP error classification
                    let error_string = e.to_string().to_lowercase();
                    let failure_type = if error_string.contains("connection") || error_string.contains("connect") {
                        "smtp_connection"
                    } else if error_string.contains("auth") || error_string.contains("credential") {
                        "smtp_auth"
                    } else if error_string.contains("timeout") || error_string.contains("time") {
                        "smtp_timeout"
                    } else {
                        "smtp_unknown"
                    };
                    
                    record_email_failure(failure_type, email_type);
                    span.record("result", &"failure");
                    span.record("failure_reason", &failure_type);
                    span.record_error(&e);
                    
                    Err(AuthServiceError::configuration(&format!("Failed to send {} email", email_type)))
                }
            }
        }
        .instrument(span_clone)
        .await
    }
    
    /// Builds an email message with proper error handling
    ///
    /// This function constructs a valid email message with sender, recipient,
    /// subject, and body, with appropriate error handling for each step.
    fn build_email_message(
        &self, 
        recipient: &str, 
        subject: &str, 
        body: &str,
        email_type: &str
    ) -> Result<Message, AuthServiceError> {
        Message::builder()
            .from(self.from_address.parse().map_err(|e| {
                Log::event(
                    "ERROR",
                    "Email Building",
                    &format!("Invalid sender address '{}': {}", self.from_address, e),
                    "failure",
                    "build_email_message"
                );
                record_email_failure(failure_types::CONFIGURATION, email_type);
                AuthServiceError::configuration("Invalid sender email address configuration")
            })?)
            .to(recipient.parse().map_err(|e| {
                Log::event(
                    "ERROR",
                    "Email Building",
                    &format!("Invalid recipient address '{}': {}", recipient, e),
                    "failure",
                    "build_email_message"
                );
                record_email_failure(failure_types::INVALID_ADDRESS, email_type);
                AuthServiceError::configuration("Invalid recipient email address")
            })?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| {
                Log::event(
                    "ERROR",
                    "Email Building",
                    &format!("Failed to build email message: {}", e),
                    "failure",
                    "build_email_message"
                );
                record_email_failure(failure_types::CONFIGURATION, email_type);
                AuthServiceError::configuration("Failed to build email message")
            })
    }
}

// =============================================================================
// TEST UTILITIES
// =============================================================================

#[cfg(test)]
impl EmailConfig {
    /// Creates a dummy EmailConfig for testing
    pub fn dummy() -> Self {
        EmailConfig {
            from_address: "test@example.com".into(),
            mailer: SmtpTransport::builder_dangerous("localhost")
                .port(1025)
                .build(),
        }
    }
}

// =============================================================================
// STANDALONE EMAIL OPERATIONS
// =============================================================================

/// Sends a password reset email with a time-limited reset link
///
/// This function:
/// 1. Stores the reset token in Redis with expiration
/// 2. Creates an email with a password reset link
/// 3. Sends the email or logs it in test mode
///
/// # Parameters
///
/// * `email_config` - Email service configuration
/// * `to_email` - Recipient's email address
/// * `reset_token` - Unique password reset token
/// * `redis_client` - Redis client for storing the reset token
///
/// # Returns
///
/// Result indicating success or detailed error information
pub async fn send_password_reset_email(
    email_config: &EmailConfig,
    to_email: &str,
    reset_token: &str,
    redis_client: &RedisClient,
) -> Result<(), AuthServiceError> {
    // Create span for password reset email
    let span = business_operation_span("send_password_reset_email");
    span.record("email_domain", &to_email.split('@').nth(1).unwrap_or("invalid"));
    span.record("token_length", &reset_token.len());
    
    // Clone span before moving it into async operation
    let span_clone = span.clone();
    
    // Use timer API to measure operation time
    let _timer = time_email_processing(email_types::PASSWORD_RESET);
    
    // Wrap the email operation in the span
    async move {
        // Store reset token in Redis before sending email
        if let Err(e) = store_password_reset_token(redis_client, to_email, reset_token).await {
            Log::event(
                "ERROR",
                "Password Reset",
                &format!("Failed to store password reset token: {}", e),
                "failure",
                "send_password_reset_email"
            );
            record_password_reset_failure_detailed(failure_types::TOKEN_STORAGE);
            span.record("result", &"failure");
            span.record("failure_reason", &"redis_store_failed");
            span.record_error(&e);
            return Err(AuthServiceError::from(e));
        }

        let frontend_url = env::var("FRONTEND_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());
        let reset_link = format!("{}/reset-password?token={}", frontend_url, reset_token);
        
        span.record("frontend_url", &frontend_url);

        let email_body = format!(
            "Hello,\n\n\
             We received a request to reset your BuildHub password.\n\n\
             To reset your password, click the link below or paste it into your browser:\n\n\
             {}\n\n\
             If you did not request a password reset, please ignore this message or contact support.\n\n\
             This link will expire in 30 minutes for security reasons.\n\n\
             Best regards,\n\
             The BuildHub Team",
            reset_link
        );

        // Test mode: Log instead of sending
        if EmailConfig::is_test_mode() {
            Log::event(
                "INFO",
                "Password Reset",
                &format!("TEST MODE: Would send password reset email to {}", to_email),
                "success",
                "send_password_reset_email"
            );
            record_password_reset_success();
            span.record("result", &"success");
            span.record("test_mode", &true);
            return Ok(());
        }

        // Production mode: Send actual email
        let result = email_config.send_email_message(
            to_email,
            "Reset Your BuildHub Password",
            &email_body,
            email_types::PASSWORD_RESET
        ).await;

        match result {
            Ok(()) => {
                record_password_reset_success();
                span.record("result", &"success");
                Ok(())
            }
            Err(e) => {
                record_password_reset_failure();
                span.record("result", &"failure");
                span.record("failure_reason", &"send_failed");
                span.record_error(&e);
                Err(e)
            }
        }
    }
    .instrument(span_clone)
    .await
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/// Generates a secure, random activation code
pub fn generate_activation_code() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Creates a frontend activation link from an activation code
pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL").unwrap_or_else(|_| {
        Log::event(
            "WARN",
            "Account Activation",
            "No FRONTEND_URL env variable, using localhost",
            "warning",
            "generate_activation_link"
        );
        "http://localhost:3000".to_string()
    });
    
    format!("{}/auth/activate?code={}", frontend_url, activation_code)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_activation_link() {
        let code = "test-activation-code-123";
        std::env::set_var("FRONTEND_URL", "https://example.com");
        
        let link = generate_activation_link(code);
        assert_eq!(link, "https://example.com/auth/activate?code=test-activation-code-123");
    }
    
    #[test]
    fn test_generate_activation_code() {
        let code1 = generate_activation_code();
        let code2 = generate_activation_code();
        
        // Verify UUIDs are valid and unique
        assert_ne!(code1, code2, "Activation codes should be unique");
        assert_eq!(code1.len(), 36, "Should be a valid UUID string");
        
        // Verify it's a valid UUID
        assert!(uuid::Uuid::parse_str(&code1).is_ok());
    }
    
    #[test]
    fn test_is_test_mode() {
        // Test when TEST_MODE is not set
        std::env::remove_var("TEST_MODE");
        assert!(!EmailConfig::is_test_mode());
        
        // Test when TEST_MODE=true
        std::env::set_var("TEST_MODE", "true");
        assert!(EmailConfig::is_test_mode());
        
        // Test when TEST_MODE has other value
        std::env::set_var("TEST_MODE", "1");
        assert!(!EmailConfig::is_test_mode());
    }
}