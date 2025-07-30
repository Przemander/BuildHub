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
    utils::log_new::Log,
    // ✅ PERFECT: Clean imports using standardized email metrics
    metricss::email_metrics::{
        // Core API functions (standardized)
        record_email_failure, time_email_processing, email_types, failure_types,
        // Business helper functions (semantic and clean)
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

        Log::event(
            "DEBUG",
            "Email Configuration",
            "Building production SMTP transport",
            "attempt",
            "EmailConfig::new"
        );
        
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
                // Clean failure tracking using standardized metrics
                record_email_failure(failure_types::CONFIGURATION, email_types::ACTIVATION);
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

        Ok(Self { from_address, mailer })
    }

    fn get_required_env_var(name: &str) -> Result<String, AuthServiceError> {
        env::var(name).map_err(|_| {
            Log::event(
                "ERROR",
                "Email Configuration",
                &format!("{} variable missing", name),
                "failure",
                "get_required_env_var"
            );
            // Clean failure tracking
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
        // Clean timer using standardized approach - no Option<>, no custom error handling
        let _timer = time_email_processing(email_types::ACTIVATION);
        
        Log::event(
            "DEBUG",
            "Account Activation",
            &format!("Preparing activation email for {}", to_email),
            "attempt",
            "send_activation_email"
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
                Log::event(
                    "DEBUG",
                    "Account Activation",
                    "Activation code stored in Redis successfully",
                    "success",
                    "send_activation_email"
                );
            }
            Err(e) => {
                Log::event(
                    "ERROR",
                    "Account Activation",
                    &format!("Failed to store activation code: {}", e),
                    "failure",
                    "send_activation_email"
                );
                // Clean detailed failure tracking using business helper
                record_activation_failure_detailed(failure_types::TOKEN_STORAGE);
                
                return Err(AuthServiceError::from(e));
            }
        }

        // Test mode: Log instead of sending
        if Self::is_test_mode() {
            Log::event(
                "INFO",
                "Account Activation",
                &format!("TEST MODE: Would send activation email to {} with link {}", to_email, activation_link),
                "success",
                "send_activation_email"
            );
            // Clean success tracking using business helper
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

        // Clean result tracking using business helpers
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
                Log::event(
                    "INFO",
                    "Email Service",
                    &format!("{} email sent to {}", email_type, recipient),
                    "success",
                    "send_email_message"
                );
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
                
                // Enhanced SMTP error classification using standardized metrics
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
                
                // Clean failure tracking
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
                Log::event(
                    "ERROR",
                    "Email Building",
                    &format!("Invalid sender address '{}': {}", self.from_address, e),
                    "failure",
                    "build_email_message"
                );
                // Clean failure tracking
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
                // Clean invalid address tracking
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
                // Clean failure tracking
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
    // Clean timer using standardized approach
    let _timer = time_email_processing(email_types::PASSWORD_RESET);
    
    Log::event(
        "DEBUG",
        "Password Reset",
        &format!("Preparing password reset email for {}", to_email),
        "attempt",
        "send_password_reset_email"
    );

    // Store reset token in Redis before sending email
    match store_password_reset_token(redis_client, to_email, reset_token).await {
        Ok(()) => {
            Log::event(
                "DEBUG",
                "Password Reset",
                "Reset token stored in Redis successfully",
                "success",
                "send_password_reset_email"
            );
        }
        Err(e) => {
            Log::event(
                "ERROR",
                "Password Reset",
                &format!("Failed to store password reset token: {}", e),
                "failure",
                "send_password_reset_email"
            );
            // Clean detailed failure tracking using business helper
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
        Log::event(
            "INFO",
            "Password Reset",
            &format!("TEST MODE: Would send password reset email to {} with link {}", to_email, reset_link),
            "success",
            "send_password_reset_email"
        );
        // Clean success tracking using business helper
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

    // Clean result tracking using business helpers
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
    Log::event(
        "DEBUG",
        "Account Activation",
        "Generated new activation code",
        "success",
        "generate_activation_code"
    );
    code
}

pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL").unwrap_or_else(|_| {
        Log::event(
            "DEBUG",
            "Account Activation",
            "No FRONTEND_URL env variable, using localhost",
            "warning",
            "generate_activation_link"
        );
        "http://localhost:3000".to_string()
    });
    
    let link = format!("{}/auth/activate?code={}", frontend_url, activation_code);
    Log::event(
        "DEBUG",
        "Account Activation",
        "Generated activation link",
        "success",
        "generate_activation_link"
    );
    link
}

// Tests section remains unchanged