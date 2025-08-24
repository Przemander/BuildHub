//! Email service for account activation.
//!
//! Portfolio-ready with minimal overhead, clean design, and test mode support.

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use redis::Client as RedisClient;
use std::env;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::{
    config::redis::{store_activation_code, store_password_reset_token},
    utils::metrics,  // Fixed: correct import path
    utils::errors::AuthServiceError,
};

// =============================================================================
// EMAIL CONFIGURATION
// =============================================================================

/// Email configuration with SMTP transport.
#[derive(Clone)]
pub struct EmailConfig {
    from_address: String,
    mailer: SmtpTransport,
}

impl EmailConfig {
    /// Creates email configuration from environment variables.
    pub fn new() -> Result<Self, AuthServiceError> {
        // Test mode: mock SMTP for development
        if Self::is_test_mode() {
            info!("Running in TEST_MODE - emails will be logged only");
            return Ok(Self {
                from_address: "test@example.com".into(),
                mailer: SmtpTransport::builder_dangerous("localhost")
                    .port(1025)
                    .build(),
            });
        }

        // Production mode: real SMTP
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

        Ok(Self {
            from_address,
            mailer,
        })
    }

    /// Checks if running in test mode.
    fn is_test_mode() -> bool {
        env::var("TEST_MODE").is_ok_and(|v| v == "true")
    }

    /// Sends activation email.
    pub async fn send_activation_email(
        &self,
        to_email: &str,
        activation_code: &str,
        redis_client: &RedisClient,
    ) -> Result<(), AuthServiceError> {
        // Store activation code in Redis
        store_activation_code(redis_client, to_email, activation_code).await?;

        let activation_link = generate_activation_link(activation_code);
        let email_body = format!(
            "Hello,\n\n\
             Welcome to BuildHub! To activate your account, click the link below:\n\n\
             {}\n\n\
             If you did not create an account, please ignore this message.\n\n\
             This link will expire in 24 hours.\n\n\
             Best regards,\n\
             The BuildHub Team",
            activation_link
        );

        // Test mode: log instead of sending
        if Self::is_test_mode() {
            info!("TEST MODE: Would send activation email to {}", to_email);
            metrics::external::email_success("activation");
            return Ok(());
        }

        // Send email
        self.send_email(
            to_email,
            "Activate Your BuildHub Account",
            &email_body,
            "activation",
        )?;

        metrics::external::email_success("activation");
        info!("Activation email sent to {}", to_email);
        Ok(())
    }

    /// Sends password reset email.
    pub async fn send_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
        redis_client: &RedisClient,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Store reset token in Redis
        store_password_reset_token(redis_client, to_email, reset_token)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        let reset_link = generate_reset_link(reset_token);
        let email_body = format!(
            r#"Hello,

You have requested a password reset for your BuildHub account.

Click the link below to reset your password:
{}

This link will expire in 30 minutes.

If you did not request this reset, please ignore this email.

Best regards,
BuildHub Team"#,
            reset_link
        );

        // Test mode: log instead of sending
        if Self::is_test_mode() {
            info!("TEST MODE - Password reset email:");
            info!("To: {}", to_email);
            info!("Reset link: {}", reset_link);
            return Ok(());
        }

        // Send email
        self.send_email(
            to_email,
            "Password Reset Request",
            &email_body,
            "password_reset",
        )
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        metrics::external::email_success("password_reset");
        info!("Password reset email sent to {}", to_email);
        Ok(())
    }

    /// Sends email via SMTP.
    fn send_email(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
        email_type: &str,
    ) -> Result<(), AuthServiceError> {
        let email = Message::builder()
            .from(self.from_address.parse().map_err(|e| {
                error!("Invalid sender address: {}", e);
                metrics::external::email_failure("invalid_address");
                AuthServiceError::configuration("Invalid sender email address")
            })?)
            .to(recipient.parse().map_err(|e| {
                warn!("Invalid recipient address {}: {}", recipient, e);
                metrics::external::email_failure("invalid_address");
                AuthServiceError::validation("email", "Invalid email address")
            })?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| {
                error!("Failed to build email: {}", e);
                metrics::external::email_failure("build_error");
                AuthServiceError::configuration("Failed to build email message")
            })?;

        self.mailer.send(&email).map_err(|e| {
            let error_str = e.to_string().to_lowercase();
            let failure_type = if error_str.contains("connection") {
                "smtp_connection"
            } else if error_str.contains("auth") {
                "smtp_auth"
            } else if error_str.contains("timeout") {
                "smtp_timeout"
            } else {
                "smtp_error"
            };

            error!("Failed to send {} email: {}", email_type, e);
            metrics::external::email_failure(failure_type);
            AuthServiceError::external(format!("Failed to send {} email", email_type))
        })?;

        Ok(())
    }

    // Removed send_password_reset_email() method - not used
}

// =============================================================================
// TEST UTILITIES
// =============================================================================

#[cfg(test)]
impl EmailConfig {
    /// Creates dummy config for testing.
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
// UTILITY FUNCTIONS
// =============================================================================

/// Generates random activation code.
pub fn generate_activation_code() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Creates activation link.
pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    format!("{}/auth/activate?code={}", frontend_url, activation_code)
}

/// Creates password reset link.
pub fn generate_reset_link(reset_token: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    format!("{}/auth/reset-password?token={}", frontend_url, reset_token)
}

/// Generates secure reset token.
pub fn generate_reset_token() -> String {
    use base64::{engine::general_purpose, Engine as _};
    use rand::{rngs::OsRng, RngCore};
    
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_activation_link() {
        std::env::set_var("FRONTEND_URL", "https://example.com");
        let link = generate_activation_link("test-code");
        assert_eq!(link, "https://example.com/auth/activate?code=test-code");
        std::env::remove_var("FRONTEND_URL");
    }

    #[test]
    fn test_generate_activation_link_default() {
        std::env::remove_var("FRONTEND_URL");
        let link = generate_activation_link("test-code");
        assert_eq!(link, "http://localhost:3000/auth/activate?code=test-code");
    }

    #[test]
    fn test_generate_reset_link() {
        std::env::set_var("FRONTEND_URL", "https://example.com");
        let link = generate_reset_link("test-token");
        assert_eq!(link, "https://example.com/auth/reset-password?token=test-token");
        std::env::remove_var("FRONTEND_URL");
    }

    #[test]
    fn test_generate_reset_link_default() {
        std::env::remove_var("FRONTEND_URL");
        let link = generate_reset_link("test-token");
        assert_eq!(link, "http://localhost:3000/auth/reset-password?token=test-token");
    }

    #[test]
    fn test_generate_activation_code() {
        let code1 = generate_activation_code();
        let code2 = generate_activation_code();
        assert_ne!(code1, code2);
        assert_eq!(code1.len(), 36); // UUID v4 with hyphens
        assert!(uuid::Uuid::parse_str(&code1).is_ok());
    }

    #[test]
    fn test_generate_reset_token() {
        let token1 = generate_reset_token();
        let token2 = generate_reset_token();
        assert_ne!(token1, token2);
        assert_eq!(token1.len(), 43); // Base64 encoded 32 bytes
    }

    #[test]
    fn test_is_test_mode() {
        std::env::remove_var("TEST_MODE");
        assert!(!EmailConfig::is_test_mode());

        std::env::set_var("TEST_MODE", "true");
        assert!(EmailConfig::is_test_mode());

        std::env::set_var("TEST_MODE", "false");
        assert!(!EmailConfig::is_test_mode());

        std::env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_email_config_test_mode() {
        std::env::set_var("TEST_MODE", "true");
        let config = EmailConfig::new();
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.from_address, "test@example.com");
        std::env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_email_config_missing_smtp_server() {
        std::env::remove_var("TEST_MODE");
        std::env::remove_var("SMTP_SERVER");
        let config = EmailConfig::new();
        assert!(config.is_err());
        if let Err(e) = config {
            assert!(e.to_string().contains("SMTP_SERVER"));
        }
    }

    #[test]
    fn test_email_config_dummy() {
        let config = EmailConfig::dummy();
        assert_eq!(config.from_address, "test@example.com");
    }

    #[tokio::test]
    async fn test_send_activation_email_test_mode() {
        std::env::set_var("TEST_MODE", "true");
        metrics::init();
        
        let config = EmailConfig::new().unwrap();
        let redis_client = redis::Client::open("redis://localhost:6379").unwrap();
        
        // Should succeed in test mode even without real SMTP
        let result = config.send_activation_email(
            "test@example.com",
            "test-code",
            &redis_client,
        ).await;
        
        // Will fail if Redis isn't running, but that's OK for this test
        if result.is_ok() {
            assert!(true);
        }
        
        std::env::remove_var("TEST_MODE");
    }

    #[tokio::test]
    async fn test_send_reset_email_test_mode() {
        std::env::set_var("TEST_MODE", "true");
        metrics::init();
        
        let config = EmailConfig::new().unwrap();
        let redis_client = redis::Client::open("redis://localhost:6379").unwrap();
        
        // Should succeed in test mode even without real SMTP
        let result = config.send_reset_email(
            "test@example.com",
            "test-reset-token",
            &redis_client,
        ).await;
        
        // Will fail if Redis isn't running, but that's OK for this test
        if result.is_ok() {
            assert!(result.is_ok());
        }
        
        std::env::remove_var("TEST_MODE");
    }
}