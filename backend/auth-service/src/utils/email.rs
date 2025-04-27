//! Email service utilities for user account management.
//!
//! This module provides functionality for sending transactional emails
//! and managing activation codes via Redis. It uses Lettre for email delivery 
//! and integrates structured logging and Prometheus metrics to track configuration,
//! email sending attempts, and Redis operations.

use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use std::env;
use redis::{AsyncCommands, Client as RedisClient};
use crate::{log_info, log_warn, log_error, log_debug};
use crate::utils::errors::{ServiceError, EmailError};
use crate::utils::metrics::{EMAILS_SENT, REDIS_OPERATIONS};

/// Configuration for sending emails via SMTP.
#[derive(Clone)]
pub struct EmailConfig {
    from_address: String,
    mailer: SmtpTransport,
}

impl EmailConfig {
    /// Creates a new EmailConfig instance from environment variables.
    pub fn new() -> Result<Self, ServiceError> {
        let smtp_server = env::var("SMTP_SERVER").map_err(|_| {
            log_error!("Email Configuration", "SMTP server variable missing", "failure");
            EMAILS_SENT.with_label_values(&["config", "failure"]).inc();
            ServiceError::Email(EmailError::Configuration("SMTP_SERVER must be set".to_string()))
        })?;
        
        let smtp_username = env::var("SMTP_USERNAME").map_err(|_| {
            log_error!("Email Configuration", "SMTP username variable missing", "failure");
            EMAILS_SENT.with_label_values(&["config", "failure"]).inc();
            ServiceError::Email(EmailError::Configuration("SMTP_USERNAME must be set".to_string()))
        })?;
        
        let smtp_password = env::var("SMTP_PASSWORD").map_err(|_| {
            log_error!("Email Configuration", "SMTP password variable missing", "failure");
            EMAILS_SENT.with_label_values(&["config", "failure"]).inc();
            ServiceError::Email(EmailError::Configuration("SMTP_PASSWORD must be set".to_string()))
        })?;
        
        let from_address = env::var("SMTP_FROM_ADDRESS")
            .unwrap_or_else(|_| "no-reply@example.com".to_string());
        
        log_info!("Email Configuration", "Initializing SMTP connection", "success");
        
        let creds = Credentials::new(smtp_username, smtp_password);
        let mailer = SmtpTransport::relay(&smtp_server).map_err(|_| {
            log_error!("Email Configuration", "Creation of SMTP transport failed", "failure");
            EMAILS_SENT.with_label_values(&["transport_init", "failure"]).inc();
            ServiceError::Email(EmailError::Internal("Failed to create email transport".to_string()))
        })?
        .credentials(creds)
        .build();

        log_debug!("Email Configuration", "SMTP transport configured", "success");
        EMAILS_SENT.with_label_values(&["config", "success"]).inc();
        
        Ok(Self { from_address, mailer })
    }

    /// Sends an activation email containing the provided activation code.
    pub async fn send_activation_email(
        &self, 
        to_email: &str, 
        activation_code: &str,
        redis_client: &RedisClient
    ) -> Result<(), ServiceError> {
        log_debug!("Account Activation", "Begin email send process", "success");
        
        let activation_link = generate_activation_link(activation_code);
        let email_body = format!(
            "Hello,\n\nTo activate your account, click the link below:\n{}\n\n\
             If you did not create an account, please ignore this message.\n\n\
             This link will expire in 24 hours.",
            activation_link
        );

        log_debug!("Account Activation", "Email content prepared", "success");
        
        let email = Message::builder()
            .from(self.from_address.parse().map_err(|_| {
                log_error!("Account Activation", "Parsing sender address failed", "failure");
                EMAILS_SENT.with_label_values(&["addressing", "failure"]).inc();
                ServiceError::Email(EmailError::Internal("Invalid from address".to_string()))
            })?)
            .to(to_email.parse().map_err(|_| {
                log_error!("Account Activation", "Parsing recipient address failed", "failure");
                EMAILS_SENT.with_label_values(&["addressing", "failure"]).inc();
                ServiceError::Email(EmailError::Internal("Invalid recipient address".to_string()))
            })?)
            .subject("Activate Your BuildHub Account")
            .body(email_body)
            .map_err(|_| {
                log_error!("Account Activation", "Building email message failed", "failure");
                EMAILS_SENT.with_label_values(&["build", "failure"]).inc();
                ServiceError::Email(EmailError::Internal("Failed to build email".to_string()))
            })?;

        // Attempt to store the activation code in Redis.
        if let Err(e) = store_activation_code(redis_client, to_email, activation_code).await {
            log_error!("Account Activation", &format!("Storing activation code in Redis failed: {e}"), "failure");
            // Proceed to send email even if code storage fails.
        }

        EMAILS_SENT.with_label_values(&["activation", "attempt"]).inc();
        self.mailer.send(&email).map_err(|_| {
            log_error!("Account Activation", "Sending email failed", "failure");
            EMAILS_SENT.with_label_values(&["activation", "failure"]).inc();
            ServiceError::Email(EmailError::Internal("Failed to send activation email".to_string()))
        })?;

        log_info!("Account Activation", "Activation email sent", "success");
        EMAILS_SENT.with_label_values(&["activation", "success"]).inc();
        Ok(())
    }
}

/// Sends a password reset email with a reset link containing the token.
pub async fn send_password_reset_email(
    email_config: &EmailConfig,
    to_email: &str,
    reset_token: &str,
) -> Result<(), ServiceError> {
    let frontend_url = std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let reset_link = format!("{}/reset-password?token={}", frontend_url, reset_token);

    let email_body = format!(
        "Hello,\n\nTo reset your password, click the link below:\n{}\n\n\
         If you did not request a password reset, please ignore this message.\n\n\
         This link will expire in 30 minutes.",
        reset_link
    );

    let email = Message::builder()
        .from(email_config.from_address.parse().map_err(|_| {
            EMAILS_SENT.with_label_values(&["password_reset", "failure"]).inc();
            ServiceError::Email(EmailError::Internal("Invalid from address".to_string()))
        })?)
        .to(to_email.parse().map_err(|_| {
            EMAILS_SENT.with_label_values(&["password_reset", "failure"]).inc();
            ServiceError::Email(EmailError::Internal("Invalid recipient address".to_string()))
        })?)
        .subject("Reset Your BuildHub Password")
        .body(email_body)
        .map_err(|_| {
            EMAILS_SENT.with_label_values(&["password_reset", "failure"]).inc();
            ServiceError::Email(EmailError::Internal("Failed to build email".to_string()))
        })?;

    EMAILS_SENT.with_label_values(&["password_reset", "attempt"]).inc();
    email_config.mailer.send(&email).map_err(|_| {
        EMAILS_SENT.with_label_values(&["password_reset", "failure"]).inc();
        ServiceError::Email(EmailError::Internal("Failed to send password reset email".to_string()))
    })?;

    EMAILS_SENT.with_label_values(&["password_reset", "success"]).inc();
    Ok(())
}

/// Generates a unique activation code using UUID v4.
pub fn generate_activation_code() -> String {
    let code = uuid::Uuid::new_v4().to_string();
    log_debug!("Account Activation", "Generated activation code", "success");
    code
}

/// Creates an activation link by combining the frontend URL with the activation code.
pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL").unwrap_or_else(|_| {
        log_debug!("Account Activation", "FRONTEND_URL not set", "defaulting to localhost");
        "http://localhost:3000".to_string()
    });
    log_debug!("Account Activation", "Generated activation link", "success");
    format!("{}/activate?code={}", frontend_url, activation_code)
}

/// Stores an activation code in Redis with an expiration of 24 hours.
pub async fn store_activation_code(
    redis_client: &RedisClient,
    email: &str,
    code: &str
) -> Result<(), ServiceError> {
    log_debug!("Account Activation", "Begin code storage", "success");
    
    let mut conn = redis_client.get_async_connection().await.map_err(|_| {
        log_error!("Account Activation", "Acquiring Redis connection failed", "failure");
        REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
        ServiceError::Email(EmailError::Internal("Service unavailable - please try again later".to_string()))
    })?;
    
    REDIS_OPERATIONS.with_label_values(&["connection", "success"]).inc();
    let key = format!("activation:code:{}", code);
    const EXPIRY: u64 = 86_400;
    
    REDIS_OPERATIONS.with_label_values(&["set_ex", "attempt"]).inc();
    conn.set_ex::<_, _, ()>(key, email, EXPIRY as usize).await.map_err(|_| {
        log_error!("Account Activation", "Storing key in Redis failed", "failure");
        REDIS_OPERATIONS.with_label_values(&["set_ex", "failure"]).inc();
        ServiceError::Email(EmailError::Internal("Failed to complete registration. Please try again later.".to_string()))
    })?;
    
    REDIS_OPERATIONS.with_label_values(&["set_ex", "success"]).inc();
    log_info!("Account Activation", "Activation code stored in Redis", "success");
    Ok(())
}

/// Verifies an activation code by retrieving and then deleting the associated email in Redis.
pub async fn verify_activation_code(
    redis_client: &RedisClient,
    code: &str
) -> Result<String, ServiceError> {
    log_debug!("Account Activation", "Begin code verification", "success");
    
    let mut conn = redis_client.get_async_connection().await.map_err(|_| {
        log_error!("Account Activation", "Acquiring Redis connection failed", "failure");
        REDIS_OPERATIONS.with_label_values(&["connection", "failure"]).inc();
        ServiceError::Email(EmailError::Internal("Service unavailable - please try again later".to_string()))
    })?;
    
    REDIS_OPERATIONS.with_label_values(&["connection", "success"]).inc();
    let key = format!("activation:code:{}", code);
    REDIS_OPERATIONS.with_label_values(&["get", "attempt"]).inc();
    
    let email: Option<String> = conn.get(&key).await.map_err(|_| {
        log_error!("Account Activation", "Lookup of activation code failed", "failure");
        REDIS_OPERATIONS.with_label_values(&["get", "failure"]).inc();
        ServiceError::Email(EmailError::Internal("Failed to verify activation code".to_string()))
    })?;
    
    REDIS_OPERATIONS.with_label_values(&["get", "success"]).inc();
    match email {
        Some(email) => {
            log_debug!("Account Activation", "Valid code found", "success");
            REDIS_OPERATIONS.with_label_values(&["del", "attempt"]).inc();
            let _: () = conn.del(&key).await.map_err(|_| {
                log_error!("Account Activation", "Deleting activation code failed", "failure");
                REDIS_OPERATIONS.with_label_values(&["del", "failure"]).inc();
                ServiceError::Email(EmailError::Internal("Failed to complete activation process".to_string()))
            })?;
            REDIS_OPERATIONS.with_label_values(&["del", "success"]).inc();
            log_info!("Account Activation", "Activation code verified and deleted", "success");
            Ok(email)
        },
        None => {
            log_warn!("Account Activation", "Activation code invalid or expired", "failure");
            REDIS_OPERATIONS.with_label_values(&["get", "not_found"]).inc();
            Err(ServiceError::Email(EmailError::InvalidCode("Invalid or expired activation code".to_string())))
        }
    }
}