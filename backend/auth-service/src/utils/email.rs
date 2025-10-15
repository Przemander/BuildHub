//! # Email Service and Token/Link Generation Utilities
//!
//! This module provides a robust and configurable service for sending emails via SMTP.
//! It also contains helper functions for generating frontend links and security tokens
//! required for the email flows (account activation, password reset).
//!
//! ## Features
//! - **Email Service**: Configuration from environment variables for production, with a
//!   safe, mocked "test mode" for local development that logs emails to the console.
//! - **Link Generation**: Creates full frontend URLs for activation and password reset.
//! - **Token/Code Generation**: Securely generates random codes and tokens.
//! - **Observability**: Detailed error handling and metrics for all SMTP operations.
//! - **Clean Design**: A single, cohesive module for all email-related utilities.

use crate::utils::{errors::AuthServiceError, metrics};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use std::env;
use std::time::Duration;
use tracing::{error, info, warn};

// =============================================================================
// EMAIL CONFIGURATION
// =============================================================================

/// Email service configuration, holding the sender address and the SMTP transport.
#[derive(Clone)]
pub struct EmailConfig {
    from_address: String,
    mailer: SmtpTransport,
}

impl EmailConfig {
    /// Creates a new `EmailConfig` from environment variables.
    ///
    /// In production, it configures a real SMTP transport. If `TEST_MODE=true`,
    /// it configures a mock transport that logs emails instead of sending them.
    pub fn new() -> Result<Self, AuthServiceError> {
        if Self::is_test_mode() {
            info!("Running in TEST_MODE: emails will be logged to console, not sent.");
            return Ok(Self {
                from_address: "test@example.com".into(),
                mailer: SmtpTransport::builder_dangerous("localhost")
                    .port(1025) // Default port for MailHog/MailCatcher
                    .build(),
            });
        }

        // Production mode: configure real SMTP transport
        let smtp_server = env::var("SMTP_SERVER")
            .map_err(|_| AuthServiceError::configuration("SMTP_SERVER must be set"))?;
        let smtp_username = env::var("SMTP_USERNAME")
            .map_err(|_| AuthServiceError::configuration("SMTP_USERNAME must be set"))?;
        let smtp_password = env::var("SMTP_PASSWORD")
            .map_err(|_| AuthServiceError::configuration("SMTP_PASSWORD must be set"))?;
        let from_address = env::var("SMTP_FROM_ADDRESS")
            .unwrap_or_else(|_| "no-reply@example.com".to_string());

        let credentials = Credentials::new(smtp_username, smtp_password);
        let mailer = SmtpTransport::relay(&smtp_server)
            .map_err(|e| {
                error!("Failed to create SMTP transport: {}", e);
                metrics::external::email_failure("configuration");
                AuthServiceError::configuration("Failed to create email transport")
            })?
            .credentials(credentials)
            .timeout(Some(Duration::from_secs(10)))
            .build();

        info!("SMTP transport configured for {}", smtp_server);
        Ok(Self { from_address, mailer })
    }

    /// Checks if the application is running in test mode via `TEST_MODE=true`.
    fn is_test_mode() -> bool {
        env::var("TEST_MODE").is_ok_and(|v| v == "true")
    }

    /// Sends an account activation email.
    pub async fn send_activation_email(
        &self,
        to_email: &str,
        activation_code: &str,
    ) -> Result<(), AuthServiceError> {
        let activation_link = generate_activation_link(activation_code);
        let email_body = format!(
            "Hello,\n\nWelcome to BuildHub! To activate your account, click the link below:\n\n{}\n\nThis link will expire in 24 hours.\n\nBest regards,\nThe BuildHub Team",
            activation_link
        );

        if Self::is_test_mode() {
            info!("TEST MODE: Would send activation email to {}", to_email);
            metrics::external::email_success("account_activation");
            return Ok(());
        }

        self.send_email(
            to_email,
            "Welcome to BuildHub! Activate Your Account",
            &email_body,
            "account_activation",
        )?;

        metrics::external::email_success("account_activation");
        info!("Activation email sent to {}", to_email);
        Ok(())
    }

    /// Sends a password reset email.
    pub async fn send_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), AuthServiceError> {
        let reset_link = generate_reset_link(reset_token);
        let email_body = format!(
            "Hello,\n\nYou requested a password reset. Click the link below:\n\n{}\n\nThis link will expire in 30 minutes.\n\nIf you did not request this, please ignore this email.\n\nBest regards,\nThe BuildHub Team",
            reset_link
        );

        if Self::is_test_mode() {
            info!("TEST MODE: Would send password reset email to {}", to_email);
            metrics::external::email_success("password_reset");
            return Ok(());
        }

        self.send_email(
            to_email,
            "Your Password Reset Request",
            &email_body,
            "password_reset",
        )?;

        metrics::external::email_success("password_reset");
        info!("Password reset email sent to {}", to_email);
        Ok(())
    }

    /// A generic, internal method to construct and send an email via SMTP.
    fn send_email(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
        email_type: &str,
    ) -> Result<(), AuthServiceError> {
        let email = Message::builder()
            .from(self.from_address.parse().map_err(|e| {
                error!("Invalid sender address configuration: {}", e);
                AuthServiceError::configuration("Invalid sender email address")
            })?)
            .to(recipient.parse().map_err(|e| {
                warn!("Invalid recipient address '{}': {}", recipient, e);
                AuthServiceError::validation("email", "Invalid recipient email address")
            })?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| {
                error!("Failed to build email message: {}", e);
                AuthServiceError::internal("Failed to build email message")
            })?;

        self.mailer.send(&email).map_err(|e| {
            let error_str = e.to_string().to_lowercase();
            let failure_type = if error_str.contains("connection") {
                "smtp_connection"
            } else if error_str.contains("auth") {
                "smtp_auth"
            } else {
                "smtp_error"
            };

            error!("Failed to send {} email via SMTP: {}", email_type, e);
            metrics::external::email_failure(failure_type);
            AuthServiceError::external(format!("Failed to send {} email", email_type))
        })?;

        Ok(())
    }
}

// Add this block for the test helper function
#[cfg(test)]
impl EmailConfig {
    /// Creates a dummy config for testing that does not require env vars or test mode.
    pub fn dummy() -> Self {
        Self {
            from_address: "test@example.com".into(),
            mailer: SmtpTransport::builder_dangerous("localhost")
                .port(1025) // Default port for MailHog/MailCatcher
                .build(),
        }
    }
}

// =============================================================================
// PUBLIC HELPER FUNCTIONS
// =============================================================================

/// Generates a random, 36-character UUID v4 string for account activation.
pub fn generate_activation_code() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generates a 256-bit cryptographically secure, URL-safe token for password resets.
pub fn generate_reset_token() -> String {
    use base64::{engine::general_purpose, Engine as _};
    use rand::{rngs::OsRng, RngCore};

    let mut bytes = [0u8; 32]; // 32 bytes = 256 bits of entropy.
    OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

/// Creates a full frontend URL for account activation.
pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url =
        env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    format!("{}/auth/activate?code={}", frontend_url, activation_code)
}

/// Creates a full frontend URL for password reset.
pub fn generate_reset_link(reset_token: &str) -> String {
    let frontend_url =
        env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    format!("{}/auth/reset-password?token={}", frontend_url, reset_token)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex do synchronizacji testów modyfikujących zmienne środowiskowe
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_generate_activation_link() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("FRONTEND_URL", "https://example.com");
        assert_eq!(
            generate_activation_link("test-code"),
            "https://example.com/auth/activate?code=test-code"
        );
        std::env::remove_var("FRONTEND_URL");
    }

    #[test]
    fn test_generate_reset_link_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("FRONTEND_URL");
        assert_eq!(
            generate_reset_link("test-token"),
            "http://localhost:3000/auth/reset-password?token=test-token"
        );
    }

    #[test]
    fn test_generate_activation_code() {
        let code1 = generate_activation_code();
        let code2 = generate_activation_code();
        assert_ne!(code1, code2);
        assert_eq!(code1.len(), 36);
        assert!(uuid::Uuid::parse_str(&code1).is_ok());
    }

    #[test]
    fn test_generate_reset_token() {
        let token1 = generate_reset_token();
        let token2 = generate_reset_token();
        assert_ne!(token1, token2);
        assert_eq!(token1.len(), 43);
    }

    #[test]
    fn test_is_test_mode() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("TEST_MODE");
        assert!(!EmailConfig::is_test_mode());

        std::env::set_var("TEST_MODE", "true");
        assert!(EmailConfig::is_test_mode());
        std::env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_send_email_invalid_recipient_returns_validation_error() {
        // Ten test sprawdza logikę parsowania adresu odbiorcy, a nie wysyłkę.
        let config = EmailConfig::dummy();
        let result = config.send_email("not-an-email", "Subject", "Body", "unit");
        assert!(matches!(
            result,
            Err(AuthServiceError::Validation { ref field, .. }) if field == "email"
        ));
    }

    #[test]
    fn test_send_email_invalid_sender_returns_configuration_error() {
        // Ten test sprawdza logikę parsowania adresu nadawcy.
        let config = EmailConfig {
            from_address: "invalid-sender".into(),
            mailer: SmtpTransport::builder_dangerous("localhost")
                .port(2525)
                .build(),
        };
        let result = config.send_email("user@example.com", "Subject", "Body", "unit");
        assert!(matches!(result, Err(AuthServiceError::Configuration(_))));
    }
}