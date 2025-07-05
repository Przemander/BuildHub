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

// ← POPRAWKA: Usuń problematyczne re-exports
// USUŃ: pub use crate::config::redis::{...};

use crate::config::redis::store_password_reset_token;
use crate::{
    config::redis::store_activation_code, // ← POPRAWKA: Direct import z config/redis.rs
    utils::error_new::AuthServiceError,
    utils::metrics::EMAILS_SENT,
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

/// Production-ready email configuration with SMTP transport.
///
/// This struct encapsulates all necessary components for sending emails via SMTP,
/// including authentication credentials and transport configuration. It supports
/// both production SMTP servers and test environments.
///
/// # Examples
///
/// ```rust
/// // Production configuration from environment variables
/// let config = EmailConfig::new()?;
///
/// // Test configuration (only available in test builds)
/// #[cfg(test)]
/// let test_config = EmailConfig::dummy();
/// ```
#[derive(Clone)]
pub struct EmailConfig {
    /// Sender email address used in the "From" field
    from_address: String,
    /// Configured SMTP transport with authentication and timeouts
    mailer: SmtpTransport,
}

// Manual Debug implementation since SmtpTransport doesn't implement Debug
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
    /// Initializes a new EmailConfig from environment variables.
    ///
    /// This constructor reads SMTP configuration from environment variables and
    /// creates a production-ready email transport. In test mode, it returns a
    /// mock configuration that logs emails instead of sending them.
    ///
    /// # Environment Variables
    ///
    /// - `TEST_MODE`: If set to "true", enables test mode with mock SMTP
    /// - `SMTP_SERVER`: SMTP server hostname (required in production)
    /// - `SMTP_USERNAME`: SMTP authentication username (required in production)
    /// - `SMTP_PASSWORD`: SMTP authentication password (required in production)
    /// - `SMTP_FROM_ADDRESS`: Sender email address (optional)
    ///
    /// # Returns
    ///
    /// - `Ok(EmailConfig)`: Successfully configured email service
    /// - `Err(AuthServiceError)`: Configuration error with detailed context
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Production setup
    /// std::env::set_var("SMTP_SERVER", "smtp.gmail.com");
    /// std::env::set_var("SMTP_USERNAME", "user@gmail.com");
    /// std::env::set_var("SMTP_PASSWORD", "app-password");
    /// 
    /// let config = EmailConfig::new()?;
    ///
    /// // Test setup
    /// std::env::set_var("TEST_MODE", "true");
    /// let test_config = EmailConfig::new()?; // Uses mock SMTP
    /// ```
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
                EMAILS_SENT.with_label_values(&["transport_init", "failure"]).inc();
                AuthServiceError::configuration("Failed to create email transport")
            })?
            .credentials(credentials)
            .timeout(Some(Duration::from_secs(10))) // Prevent hanging connections
            .build();

        log_info!("Email Configuration", "SMTP transport configured successfully", "success");
        EMAILS_SENT.with_label_values(&["config", "success"]).inc();

        Ok(Self { from_address, mailer })
    }

    /// Helper function to retrieve required environment variables with consistent error handling.
    ///
    /// # Arguments
    /// - `name`: Environment variable name
    ///
    /// # Returns
    /// - `Ok(String)`: Environment variable value
    /// - `Err(AuthServiceError)`: Missing or invalid environment variable
    fn get_required_env_var(name: &str) -> Result<String, AuthServiceError> {
        env::var(name).map_err(|_| {
            log_error!("Email Configuration", &format!("{} variable missing", name), "failure");
            EMAILS_SENT.with_label_values(&["config", "failure"]).inc();
            AuthServiceError::configuration(&format!("{} must be set", name))
        })
    }

    /// Checks if the application is running in test mode.
    ///
    /// # Returns
    /// `true` if TEST_MODE environment variable is set to "true"
    fn is_test_mode() -> bool {
        env::var("TEST_MODE").is_ok_and(|v| v == "true")
    }
}

// =============================================================================
// EMAIL SENDING OPERATIONS
// =============================================================================

impl EmailConfig {
    /// Sends an account activation email with a secure activation link.
    ///
    /// This method creates and sends a professional activation email containing
    /// a unique activation link. The activation code is stored in Redis before
    /// sending to ensure it's available when the user clicks the link.
    ///
    /// # Arguments
    /// - `to_email`: Recipient's email address
    /// - `activation_code`: Unique UUID-based activation code
    /// - `redis_client`: Redis client for storing the activation code
    ///
    /// # Returns
    /// - `Ok(())`: Email sent successfully (or logged in test mode)
    /// - `Err(AuthServiceError)`: Failed to store code, build email, or send
    ///
    /// # Security Considerations
    /// - Activation codes are stored in Redis with 24-hour expiration
    /// - Codes are single-use (deleted after successful activation)
    /// - Links include the frontend domain for proper routing
    ///
    /// # Examples
    ///
    /// ```rust
    /// let config = EmailConfig::new()?;
    /// let redis_client = redis::init_redis()?;
    /// let activation_code = uuid::Uuid::new_v4().to_string();
    ///
    /// config.send_activation_email(
    ///     "newuser@example.com",
    ///     &activation_code,
    ///     &redis_client
    /// ).await?;
    /// ```
    pub async fn send_activation_email(
        &self,
        to_email: &str,
        activation_code: &str,
        redis_client: &RedisClient,
    ) -> Result<(), AuthServiceError> {
        log_debug!(
            "Account Activation", 
            &format!("Preparing activation email for {}", to_email), 
            "attempt"
        );

        let activation_link = generate_activation_link(activation_code);
        
        // Create professional email content with clear instructions
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
        // This ensures the code exists when the user clicks the link
        store_activation_code(redis_client, to_email, activation_code).await
            .map_err(|e| {
                log_error!(
                    "Account Activation",
                    &format!("Failed to store activation code: {}", e),
                    "failure"
                );
                AuthServiceError::from(e) // CacheError -> AuthServiceError conversion
            })?;

        // Test mode: Log instead of sending
        if Self::is_test_mode() {
            log_info!(
                "Account Activation", 
                &format!("TEST MODE: Would send activation email to {} with link {}", to_email, activation_link), 
                "success"
            );
            EMAILS_SENT.with_label_values(&["activation", "test_mode"]).inc();
            return Ok(());
        }

        // Production mode: Build and send email
        self.send_email_message(
            to_email,
            "Activate Your BuildHub Account",
            &email_body,
            "activation"
        ).await
    }
    
    /// Internal helper method to build and send email messages with consistent error handling.
    ///
    /// This method encapsulates the common pattern of building a message and sending it
    /// via the SMTP transport, with comprehensive error handling and metrics collection.
    ///
    /// # Arguments
    /// - `recipient`: Recipient email address
    /// - `subject`: Email subject line
    /// - `body`: Email body content (plain text)
    /// - `operation`: Operation name for metrics and logging
    ///
    /// # Returns
    /// - `Ok(())`: Email sent successfully
    /// - `Err(AuthServiceError)`: Failed to build or send email
    async fn send_email_message(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
        operation: &str,
    ) -> Result<(), AuthServiceError> {
        let email = self.build_email_message(recipient, subject, body, operation)?;

        EMAILS_SENT.with_label_values(&[operation, "attempt"]).inc();
        
        match self.mailer.send(&email) {
            Ok(_) => {
                log_info!(
                    "Email Service", 
                    &format!("{} email sent to {}", operation, recipient), 
                    "success"
                );
                EMAILS_SENT.with_label_values(&[operation, "success"]).inc();
                Ok(())
            }
            Err(e) => {
                log_error!(
                    "Email Service", 
                    &format!("Failed to send {} email: {}", operation, e), 
                    "failure"
                );
                EMAILS_SENT.with_label_values(&[operation, "failure"]).inc();
                Err(AuthServiceError::configuration(&format!("Failed to send {} email", operation)))
            }
        }
    }
    
    /// Builds an email message with comprehensive validation and error handling.
    ///
    /// This helper method creates a `Message` instance with proper validation of
    /// email addresses and structured error handling for different failure modes.
    ///
    /// # Arguments
    /// - `recipient`: Recipient email address (validated)
    /// - `subject`: Email subject line
    /// - `body`: Email body content
    /// - `operation`: Operation name for error context
    ///
    /// # Returns
    /// - `Ok(Message)`: Successfully built email message
    /// - `Err(AuthServiceError)`: Invalid addresses or message building failed
    fn build_email_message(
        &self, 
        recipient: &str, 
        subject: &str, 
        body: &str,
        operation: &str
    ) -> Result<Message, AuthServiceError> {
        Message::builder()
            .from(self.from_address.parse().map_err(|e| {
                log_error!(
                    "Email Building", 
                    &format!("Invalid sender address '{}': {}", self.from_address, e), 
                    "failure"
                );
                EMAILS_SENT.with_label_values(&[operation, "addressing_failure"]).inc();
                AuthServiceError::configuration("Invalid sender email address configuration")
            })?)
            .to(recipient.parse().map_err(|e| {
                log_error!(
                    "Email Building", 
                    &format!("Invalid recipient address '{}': {}", recipient, e), 
                    "failure"
                );
                EMAILS_SENT.with_label_values(&[operation, "addressing_failure"]).inc();
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
                EMAILS_SENT.with_label_values(&[operation, "build_failure"]).inc();
                AuthServiceError::configuration("Failed to build email message")
            })
    }
}

// =============================================================================
// TEST UTILITIES
// =============================================================================

#[cfg(test)]
impl EmailConfig {
    /// Creates a dummy email configuration for unit testing.
    ///
    /// This method is only available in test builds and creates a mock SMTP
    /// transport pointing to localhost:1025 (standard MailHog test server port).
    ///
    /// # Returns
    /// EmailConfig instance configured for testing
    ///
    /// # Examples
    ///
    /// ```rust
    /// #[cfg(test)]
    /// mod tests {
    ///     use super::*;
    ///
    ///     #[test]
    ///     fn test_email_creation() {
    ///         let config = EmailConfig::dummy();
    ///         assert_eq!(config.from_address, "test@example.com");
    ///     }
    /// }
    /// ```
    pub fn dummy() -> Self {
        EmailConfig {
            from_address: "test@example.com".into(),
            mailer: SmtpTransport::builder_dangerous("localhost")
                .port(1025) // Standard MailHog port
                .build(),
        }
    }
}

// =============================================================================
// STANDALONE EMAIL OPERATIONS
// =============================================================================

/// Sends a password reset email with a secure reset link.
///
/// This standalone function creates and sends a password reset email containing
/// a time-limited reset token. The token is stored in Redis with a 30-minute
/// expiration for security.
///
/// # Arguments
/// - `email_config`: Configured email service instance
/// - `to_email`: Recipient's email address
/// - `reset_token`: Unique UUID-based reset token
/// - `redis_client`: Redis client for storing the reset token
///
/// # Returns
/// - `Ok(())`: Email sent successfully (or logged in test mode)
/// - `Err(AuthServiceError)`: Failed to store token, build email, or send
///
/// # Security Considerations
/// - Reset tokens expire after 30 minutes
/// - Tokens are single-use (should be invalidated after password reset)
/// - Links point to the configured frontend URL
///
/// # Examples
///
/// ```rust
/// let email_config = EmailConfig::new()?;
/// let redis_client = redis::init_redis()?;
/// let reset_token = uuid::Uuid::new_v4().to_string();
///
/// send_password_reset_email(
///     &email_config,
///     "user@example.com",
///     &reset_token,
///     &redis_client
/// ).await?;
/// ```
pub async fn send_password_reset_email(
    email_config: &EmailConfig,
    to_email: &str,
    reset_token: &str,
    redis_client: &RedisClient,
) -> Result<(), AuthServiceError> {
    log_debug!(
        "Password Reset", 
        &format!("Preparing password reset email for {}", to_email), 
        "attempt"
    );

    // Store reset token in Redis before sending email
    // This ensures the token exists when the user clicks the link
    store_password_reset_token(redis_client, to_email, reset_token).await?;

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
        EMAILS_SENT.with_label_values(&["password_reset", "test_mode"]).inc();
        return Ok(());
    }

    // Production mode: Send actual email
    email_config.send_email_message(
        to_email,
        "Reset Your BuildHub Password",
        &email_body,
        "password_reset"
    ).await
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/// Generates a cryptographically secure activation code using UUID v4.
///
/// This function creates a unique, unpredictable activation code suitable for
/// account activation workflows. The code is a standard UUID v4 string.
///
/// # Returns
/// A 36-character UUID v4 string (e.g., "550e8400-e29b-41d4-a716-446655440000")
///
/// # Examples
///
/// ```rust
/// let code = generate_activation_code();
/// assert_eq!(code.len(), 36);
/// assert!(code.contains('-'));
/// ```
pub fn generate_activation_code() -> String {
    let code = uuid::Uuid::new_v4().to_string();
    log_debug!("Account Activation", "Generated new activation code", "success");
    code
}

/// Creates a frontend activation link by combining the base URL with the activation code.
///
/// This function constructs a complete activation URL by reading the frontend URL
/// from environment variables and appending the activation code as a query parameter.
/// Falls back to localhost for development environments.
///
/// # Arguments
/// - `activation_code`: The UUID-based activation code to include in the link
///
/// # Returns
/// A complete activation URL (e.g., "https://buildhub.com/auth/activate?code=...")
///
/// # Environment Variables
/// - `FRONTEND_URL`: Base URL of the frontend application (optional)
///
/// # Examples
///
/// ```rust
/// std::env::set_var("FRONTEND_URL", "https://buildhub.com");
/// let link = generate_activation_link("test-code-123");
/// assert_eq!(link, "https://buildhub.com/auth/activate?code=test-code-123");
///
/// std::env::remove_var("FRONTEND_URL");
/// let link = generate_activation_link("test-code-123");
/// assert!(link.starts_with("http://localhost:3000"));
/// ```
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
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;
    use std::env;
    
    /// Helper function to create a Redis client for testing.
    /// Assumes Redis is running on localhost:6379 for integration tests.
    async fn make_test_redis_client() -> Client {
        Client::open("redis://127.0.0.1/")
            .expect("Redis must be running on localhost:6379 for integration tests")
    }

    #[test]
    fn test_generate_activation_code_format() {
        let code = generate_activation_code();
        assert!(!code.is_empty(), "Activation code should not be empty");
        assert_eq!(code.len(), 36, "UUID v4 should be exactly 36 characters");
        assert_eq!(code.matches('-').count(), 4, "UUID should contain 4 hyphens");
    }

    #[test]
    fn test_generate_activation_code_uniqueness() {
        let code1 = generate_activation_code();
        let code2 = generate_activation_code();
        assert_ne!(code1, code2, "Generated codes should be unique");
    }

    #[test]
    fn test_generate_activation_link_with_default_url() {
        // Ensure environment variable is not set
        env::remove_var("FRONTEND_URL");
        
        let code = "test-activation-code-123";
        let link = generate_activation_link(code);
        
        assert!(
            link.starts_with("http://localhost:3000/auth/activate?code="),
            "Should use default localhost URL"
        );
        assert!(link.ends_with(code), "Should include the activation code");
    }

    #[test]
    fn test_generate_activation_link_with_custom_url() {
        // Set custom frontend URL for this test
        env::set_var("FRONTEND_URL", "https://buildhub.example.com");
        
        let code = "custom-test-code";
        let link = generate_activation_link(code);
        
        assert_eq!(
            link,
            "https://buildhub.example.com/auth/activate?code=custom-test-code",
            "Should use custom FRONTEND_URL environment variable"
        );
        
        // Clean up environment
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
        // Setup test environment
        let config = EmailConfig::dummy();
        let client = make_test_redis_client().await;
        env::set_var("FRONTEND_URL", "https://test-buildhub.com");
        env::set_var("TEST_MODE", "true");
        
        // Test password reset email
        let result = send_password_reset_email(
            &config, 
            "user@example.com", 
            "test-reset-token-123", 
            &client
        ).await;
        
        assert!(result.is_ok(), "Should succeed in test mode");
        
        // Clean up environment
        env::remove_var("FRONTEND_URL");
        env::remove_var("TEST_MODE");
    }

    #[tokio::test]
    async fn test_send_activation_email_in_test_mode() {
        // Setup test environment
        let config = EmailConfig::dummy();
        let client = make_test_redis_client().await;
        env::set_var("TEST_MODE", "true");
        
        // Test activation email
        let result = config.send_activation_email(
            "newuser@example.com", 
            "test-activation-code-456", 
            &client
        ).await;
        
        assert!(result.is_ok(), "Should succeed in test mode");
        
        // Clean up environment
        env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_is_test_mode_detection() {
        // Test with TEST_MODE set to "true"
        env::set_var("TEST_MODE", "true");
        assert!(EmailConfig::is_test_mode());
        
        // Test with TEST_MODE set to other value
        env::set_var("TEST_MODE", "false");
        assert!(!EmailConfig::is_test_mode());
        
        // Test with TEST_MODE unset
        env::remove_var("TEST_MODE");
        assert!(!EmailConfig::is_test_mode());
    }

    #[test]
    fn test_email_config_new_in_test_mode() {
        env::set_var("TEST_MODE", "true");
        
        let result = EmailConfig::new();
        assert!(result.is_ok(), "Should succeed in test mode");
        
        let config = result.unwrap();
        assert_eq!(config.from_address, "test@example.com");
        
        env::remove_var("TEST_MODE");
    }
}