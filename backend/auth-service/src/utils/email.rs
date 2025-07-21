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

use crate::config::redis::store_password_reset_token;
use crate::{
    config::redis::store_activation_code,
    utils::error_new::AuthServiceError,
    // ✅ PERFECT: Clean imports using 10/10 standardized email metrics
    metricss::email_metrics::{
        // Core API functions (standardized)
        record_email_failure, time_email_processing, email_types, failure_types,
        // Business helper functions (semantic and clean)
        record_activation_success, record_activation_failure, record_activation_failure_detailed,
        record_password_reset_success, record_password_reset_failure, record_password_reset_failure_detailed,
    },
    log_debug, log_error, log_info,
};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use redis::Client as RedisClient;
use std::env;
use std::time::Duration;

// =============================================================================
// CORE TYPES AND CONFIGURATION
// =============================================================================

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
    pub fn new() -> Result<Self, AuthServiceError> {
        log_info!("Email Configuration", "Initializing email service", "attempt");
        
        // Test mode: Use mock SMTP configuration for development and testing
        if Self::is_test_mode() {
            log_info!("Email Configuration", "Running in TEST_MODE - emails will be logged but not sent", "info");
            
            return Ok(Self {
                from_address: "test@example.com".into(),
                mailer: SmtpTransport::builder_dangerous("localhost")
                    .port(1025) // Standard MailHog/test SMTP port
                    .build(),
            });
        }
        
        // Production mode: Configure real SMTP transport
        let smtp_server = Self::get_required_env_var("SMTP_SERVER")?;
        let smtp_username = Self::get_required_env_var("SMTP_USERNAME")?;
        let smtp_password = Self::get_required_env_var("SMTP_PASSWORD")?;

        let from_address = env::var("SMTP_FROM_ADDRESS")
            .unwrap_or_else(|_| "no-reply@example.com".to_string());

        log_debug!("Email Configuration", "Building production SMTP transport", "attempt");
        
        let credentials = Credentials::new(smtp_username, smtp_password);
        let mailer = SmtpTransport::relay(&smtp_server)
            .map_err(|e| {
                log_error!(
                    "Email Configuration", 
                    &format!("SMTP transport creation failed: {}", e), 
                    "failure"
                );
                // ✅ PERFECT: Clean failure tracking using standardized metrics
                record_email_failure(failure_types::CONFIGURATION, email_types::ACTIVATION);
                AuthServiceError::configuration("Failed to create email transport")
            })?
            .credentials(credentials)
            .timeout(Some(Duration::from_secs(10)))
            .build();

        log_info!("Email Configuration", "SMTP transport configured successfully", "success");

        Ok(Self { from_address, mailer })
    }

    fn get_required_env_var(name: &str) -> Result<String, AuthServiceError> {
        env::var(name).map_err(|_| {
            log_error!("Email Configuration", &format!("{} variable missing", name), "failure");
            // ✅ PERFECT: Clean failure tracking
            record_email_failure(failure_types::CONFIGURATION, email_types::ACTIVATION);
            AuthServiceError::configuration(&format!("{} must be set", name))
        })
    }

    fn is_test_mode() -> bool {
        env::var("TEST_MODE").is_ok_and(|v| v == "true")
    }
}

// =============================================================================
// EMAIL SENDING OPERATIONS
// =============================================================================

impl EmailConfig {
    pub async fn send_activation_email(
        &self,
        to_email: &str,
        activation_code: &str,
        redis_client: &RedisClient,
    ) -> Result<(), AuthServiceError> {
        // ✅ PERFECT: Clean timer using standardized approach - no Option<>, no custom error handling
        let _timer = time_email_processing(email_types::ACTIVATION);
        
        log_debug!(
            "Account Activation", 
            &format!("Preparing activation email for {}", to_email), 
            "attempt"
        );

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
        match store_activation_code(redis_client, to_email, activation_code).await {
            Ok(()) => {
                log_debug!("Account Activation", "Activation code stored in Redis successfully", "success");
            }
            Err(e) => {
                log_error!(
                    "Account Activation",
                    &format!("Failed to store activation code: {}", e),
                    "failure"
                );
                // ✅ PERFECT: Clean detailed failure tracking using business helper
                record_activation_failure_detailed(failure_types::TOKEN_STORAGE);
                
                return Err(AuthServiceError::from(e));
            }
        }

        // Test mode: Log instead of sending
        if Self::is_test_mode() {
            log_info!(
                "Account Activation", 
                &format!("TEST MODE: Would send activation email to {} with link {}", to_email, activation_link), 
                "success"
            );
            // ✅ PERFECT: Clean success tracking using business helper
            record_activation_success();
            
            return Ok(());
        }

        // Production mode: Build and send email
        let result = self.send_email_message(
            to_email,
            "Activate Your BuildHub Account",
            &email_body,
            email_types::ACTIVATION
        ).await;

        // ✅ PERFECT: Clean result tracking using business helpers
        match result {
            Ok(()) => {
                record_activation_success();
                Ok(())
            }
            Err(e) => {
                record_activation_failure();
                Err(e)
            }
        }
    }
    
    async fn send_email_message(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
        email_type: &str,
    ) -> Result<(), AuthServiceError> {
        // Build email message
        let email = self.build_email_message(recipient, subject, body, email_type)?;

        // Send via SMTP
        match self.mailer.send(&email) {
            Ok(_) => {
                log_info!(
                    "Email Service", 
                    &format!("{} email sent to {}", email_type, recipient), 
                    "success"
                );
                Ok(())
            }
            Err(e) => {
                log_error!(
                    "Email Service", 
                    &format!("Failed to send {} email: {}", email_type, e), 
                    "failure"
                );
                
                // ✅ PERFECT: Enhanced SMTP error classification using standardized metrics
                let error_string = e.to_string().to_lowercase();
                let failure_type = if error_string.contains("connection") || error_string.contains("connect") {
                    failure_types::SMTP_CONNECTION
                } else if error_string.contains("auth") || error_string.contains("credential") {
                    failure_types::SMTP_AUTH
                } else if error_string.contains("timeout") || error_string.contains("time") {
                    failure_types::SMTP_TIMEOUT
                } else {
                    failure_types::SMTP_CONNECTION // Default to connection issue
                };
                
                // ✅ PERFECT: Clean failure tracking
                record_email_failure(failure_type, email_type);
                
                Err(AuthServiceError::configuration(&format!("Failed to send {} email", email_type)))
            }
        }
    }
    
    fn build_email_message(
        &self, 
        recipient: &str, 
        subject: &str, 
        body: &str,
        email_type: &str
    ) -> Result<Message, AuthServiceError> {
        Message::builder()
            .from(self.from_address.parse().map_err(|e| {
                log_error!(
                    "Email Building", 
                    &format!("Invalid sender address '{}': {}", self.from_address, e), 
                    "failure"
                );
                // ✅ PERFECT: Clean failure tracking
                record_email_failure(failure_types::CONFIGURATION, email_type);
                AuthServiceError::configuration("Invalid sender email address configuration")
            })?)
            .to(recipient.parse().map_err(|e| {
                log_error!(
                    "Email Building", 
                    &format!("Invalid recipient address '{}': {}", recipient, e), 
                    "failure"
                );
                // ✅ PERFECT: Clean invalid address tracking
                record_email_failure(failure_types::INVALID_ADDRESS, email_type);
                AuthServiceError::configuration("Invalid recipient email address")
            })?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| {
                log_error!(
                    "Email Building", 
                    &format!("Failed to build email message: {}", e), 
                    "failure"
                );
                // ✅ PERFECT: Clean failure tracking
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

pub async fn send_password_reset_email(
    email_config: &EmailConfig,
    to_email: &str,
    reset_token: &str,
    redis_client: &RedisClient,
) -> Result<(), AuthServiceError> {
    // ✅ PERFECT: Clean timer using standardized approach
    let _timer = time_email_processing(email_types::PASSWORD_RESET);
    
    log_debug!(
        "Password Reset", 
        &format!("Preparing password reset email for {}", to_email), 
        "attempt"
    );

    // Store reset token in Redis before sending email
    match store_password_reset_token(redis_client, to_email, reset_token).await {
        Ok(()) => {
            log_debug!("Password Reset", "Reset token stored in Redis successfully", "success");
        }
        Err(e) => {
            log_error!(
                "Password Reset",
                &format!("Failed to store password reset token: {}", e),
                "failure"
            );
            // ✅ PERFECT: Clean detailed failure tracking using business helper
            record_password_reset_failure_detailed(failure_types::TOKEN_STORAGE);
            
            return Err(AuthServiceError::from(e));
        }
    }

    let frontend_url = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let reset_link = format!("{}/reset-password?token={}", frontend_url, reset_token);

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
        log_info!(
            "Password Reset", 
            &format!("TEST MODE: Would send password reset email to {} with link {}", to_email, reset_link), 
            "success"
        );
        // ✅ PERFECT: Clean success tracking using business helper
        record_password_reset_success();
        
        return Ok(());
    }

    // Production mode: Send actual email
    let result = email_config.send_email_message(
        to_email,
        "Reset Your BuildHub Password",
        &email_body,
        email_types::PASSWORD_RESET
    ).await;

    // ✅ PERFECT: Clean result tracking using business helpers
    match result {
        Ok(()) => {
            record_password_reset_success();
            Ok(())
        }
        Err(e) => {
            record_password_reset_failure();
            Err(e)
        }
    }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

pub fn generate_activation_code() -> String {
    let code = uuid::Uuid::new_v4().to_string();
    log_debug!("Account Activation", "Generated new activation code", "success");
    code
}

pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL").unwrap_or_else(|_| {
        log_debug!("Account Activation", "No FRONTEND_URL env variable, using localhost", "warning");
        "http://localhost:3000".to_string()
    });
    
    let link = format!("{}/auth/activate?code={}", frontend_url, activation_code);
    log_debug!("Account Activation", "Generated activation link", "success");
    link
}

// =============================================================================
// TESTS (Updated for Perfect 10/10 Email Metrics)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;
    use std::env;
    
    async fn make_test_redis_client() -> Client {
        Client::open("redis://127.0.0.1/")
            .expect("Redis must be running on localhost:6379 for integration tests")
    }

    #[test]
    fn test_generate_activation_code_format() {
        let code = generate_activation_code();
        assert!(!code.is_empty());
        assert_eq!(code.len(), 36);
        assert_eq!(code.matches('-').count(), 4);
    }

    #[test]
    fn test_generate_activation_code_uniqueness() {
        let code1 = generate_activation_code();
        let code2 = generate_activation_code();
        assert_ne!(code1, code2);
    }

    #[test]
    fn test_generate_activation_link_with_default_url() {
        env::remove_var("FRONTEND_URL");
        
        let code = "test-activation-code-123";
        let link = generate_activation_link(code);
        
        assert!(link.starts_with("http://localhost:3000/auth/activate?code="));
        assert!(link.ends_with(code));
    }

    #[test]
    fn test_generate_activation_link_with_custom_url() {
        env::set_var("FRONTEND_URL", "https://buildhub.example.com");
        
        let code = "custom-test-code";
        let link = generate_activation_link(code);
        
        assert_eq!(
            link,
            "https://buildhub.example.com/auth/activate?code=custom-test-code"
        );
        
        env::remove_var("FRONTEND_URL");
    }

    #[test]
    fn test_email_config_debug_implementation() {
        let config = EmailConfig::dummy();
        let debug_output = format!("{:?}", config);
        
        assert!(debug_output.contains("EmailConfig"));
        assert!(debug_output.contains("from_address"));
        assert!(debug_output.contains("test@example.com"));
        assert!(debug_output.contains("SmtpTransport{configured}"));
    }

    #[tokio::test]
    async fn test_email_config_dummy_creates_valid_instance() {
        let config = EmailConfig::dummy();
        
        assert_eq!(config.from_address, "test@example.com");
        assert!(format!("{:?}", config).contains("SmtpTransport{configured}"));
    }

    #[tokio::test]
    async fn test_send_password_reset_email_in_test_mode() {
        let config = EmailConfig::dummy();
        let client = make_test_redis_client().await;
        env::set_var("FRONTEND_URL", "https://test-buildhub.com");
        env::set_var("TEST_MODE", "true");
        
        let result = send_password_reset_email(
            &config, 
            "user@example.com", 
            "test-reset-token-123", 
            &client
        ).await;
        
        assert!(result.is_ok());
        
        env::remove_var("FRONTEND_URL");
        env::remove_var("TEST_MODE");
    }

    #[tokio::test]
    async fn test_send_activation_email_in_test_mode() {
        let config = EmailConfig::dummy();
        let client = make_test_redis_client().await;
        env::set_var("TEST_MODE", "true");
        
        let result = config.send_activation_email(
            "newuser@example.com", 
            "test-activation-code-456", 
            &client
        ).await;
        
        assert!(result.is_ok());
        
        env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_is_test_mode_detection() {
        env::set_var("TEST_MODE", "true");
        assert!(EmailConfig::is_test_mode());
        
        env::set_var("TEST_MODE", "false");
        assert!(!EmailConfig::is_test_mode());
        
        env::remove_var("TEST_MODE");
        assert!(!EmailConfig::is_test_mode());
    }

    #[test]
    fn test_email_config_new_in_test_mode() {
        env::set_var("TEST_MODE", "true");
        
        let result = EmailConfig::new();
        assert!(result.is_ok());
        
        let config = result.unwrap();
        assert_eq!(config.from_address, "test@example.com");
        
        env::remove_var("TEST_MODE");
    }

    // ✅ PERFECT: Updated tests for 10/10 standardized email metrics
    #[tokio::test]
    async fn test_email_metrics_integration_activation() {
        use crate::metricss::email_metrics::{init_email_metrics, EMAIL_OPERATIONS, EMAIL_DURATION};
        
        init_email_metrics();
        let config = EmailConfig::dummy();
        let client = make_test_redis_client().await;
        env::set_var("TEST_MODE", "true");
        
        // Record initial metrics state
        let initial_count = EMAIL_OPERATIONS
            .with_label_values(&[email_types::ACTIVATION, "success"])
            .get();
        let initial_duration_count = EMAIL_DURATION
            .with_label_values(&[email_types::ACTIVATION])
            .get_sample_count();
        
        // Send activation email
        let result = config.send_activation_email(
            "metrics-test@example.com",
            "test-activation-metrics",
            &client
        ).await;
        
        assert!(result.is_ok());
        
        // ✅ PERFECT: Clean assertions - timer always works with standardized approach
        let final_count = EMAIL_OPERATIONS
            .with_label_values(&[email_types::ACTIVATION, "success"])
            .get();
        let final_duration_count = EMAIL_DURATION
            .with_label_values(&[email_types::ACTIVATION])
            .get_sample_count();
        
        assert_eq!(final_count, initial_count + 1.0);
        assert_eq!(final_duration_count, initial_duration_count + 1);
        
        env::remove_var("TEST_MODE");
    }

    #[tokio::test]
    async fn test_email_metrics_integration_password_reset() {
        use crate::metricss::email_metrics::{init_email_metrics, EMAIL_OPERATIONS, EMAIL_DURATION};
        
        init_email_metrics();
        let config = EmailConfig::dummy();
        let client = make_test_redis_client().await;
        env::set_var("TEST_MODE", "true");
        
        // Record initial metrics state
        let initial_count = EMAIL_OPERATIONS
            .with_label_values(&[email_types::PASSWORD_RESET, "success"])
            .get();
        let initial_duration_count = EMAIL_DURATION
            .with_label_values(&[email_types::PASSWORD_RESET])
            .get_sample_count();
        
        // Send password reset email
        let result = send_password_reset_email(
            &config,
            "password-reset-test@example.com",
            "test-reset-metrics-token",
            &client
        ).await;
        
        assert!(result.is_ok());
        
        // ✅ PERFECT: Clean assertions - timer always works with standardized approach
        let final_count = EMAIL_OPERATIONS
            .with_label_values(&[email_types::PASSWORD_RESET, "success"])
            .get();
        let final_duration_count = EMAIL_DURATION
            .with_label_values(&[email_types::PASSWORD_RESET])
            .get_sample_count();
        
        assert_eq!(final_count, initial_count + 1.0);
        assert_eq!(final_duration_count, initial_duration_count + 1);
        
        env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_standardized_email_failure_classification() {
        use crate::metricss::email_metrics::{init_email_metrics, EMAIL_FAILURES};
        
        init_email_metrics();
        
        // Test that we can record different failure types using standardized approach
        let initial_smtp_failures = EMAIL_FAILURES
            .with_label_values(&[failure_types::SMTP_CONNECTION, email_types::ACTIVATION])
            .get();
        let initial_config_failures = EMAIL_FAILURES
            .with_label_values(&[failure_types::CONFIGURATION, email_types::ACTIVATION])
            .get();
        
        // ✅ PERFECT: Clean failure recording using standardized metrics
        record_email_failure(failure_types::SMTP_CONNECTION, email_types::ACTIVATION);
        record_email_failure(failure_types::CONFIGURATION, email_types::ACTIVATION);
        
        let final_smtp_failures = EMAIL_FAILURES
            .with_label_values(&[failure_types::SMTP_CONNECTION, email_types::ACTIVATION])
            .get();
        let final_config_failures = EMAIL_FAILURES
            .with_label_values(&[failure_types::CONFIGURATION, email_types::ACTIVATION])
            .get();
        
        assert_eq!(final_smtp_failures, initial_smtp_failures + 1.0);
        assert_eq!(final_config_failures, initial_config_failures + 1.0);
    }

    #[test]
    fn test_standardized_business_helpers() {
        use crate::metricss::email_metrics::{init_email_metrics, EMAIL_OPERATIONS, EMAIL_FAILURES};
        
        init_email_metrics();
        
        // ✅ PERFECT: Test business helpers using standardized metrics
        let initial_success = EMAIL_OPERATIONS
            .with_label_values(&[email_types::ACTIVATION, "success"])
            .get();
        let initial_failure = EMAIL_OPERATIONS
            .with_label_values(&[email_types::ACTIVATION, "failure"])
            .get();
        let initial_detailed_failure = EMAIL_FAILURES
            .with_label_values(&[failure_types::TOKEN_STORAGE, email_types::ACTIVATION])
            .get();
        
        // Use business helpers
        record_activation_success();
        record_activation_failure_detailed(failure_types::TOKEN_STORAGE);
        
        let final_success = EMAIL_OPERATIONS
            .with_label_values(&[email_types::ACTIVATION, "success"])
            .get();
        let final_failure = EMAIL_OPERATIONS
            .with_label_values(&[email_types::ACTIVATION, "failure"])
            .get();
        let final_detailed_failure = EMAIL_FAILURES
            .with_label_values(&[failure_types::TOKEN_STORAGE, email_types::ACTIVATION])
            .get();
        
        assert_eq!(final_success, initial_success + 1.0);
        assert_eq!(final_failure, initial_failure + 1.0); // detailed failure also records general failure
        assert_eq!(final_detailed_failure, initial_detailed_failure + 1.0);
    }
}