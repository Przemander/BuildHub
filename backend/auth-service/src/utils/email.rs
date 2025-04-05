//! Email service utilities for user account management.
//!
//! This module provides functionality for sending transactional emails
//! and managing email-related activation codes through Redis.

use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use std::env;
use log::{info, error};
use uuid::Uuid;
use redis::{AsyncCommands, Client as RedisClient};

use crate::utils::errors::ApiError;

/// Configuration for sending emails via SMTP.
#[derive(Clone)]
pub struct EmailConfig {
    /// The email address used as the sender for all outgoing emails
    from_address: String,
    /// The configured SMTP transport client
    mailer: SmtpTransport,
}

impl EmailConfig {
    /// Creates a new EmailConfig instance from environment variables.
    pub fn new() -> Result<Self, ApiError> {
        // Get SMTP configuration from environment
        let smtp_server = env::var("SMTP_SERVER")
            .map_err(|_| {
                error!("SMTP_SERVER environment variable not set");
                ApiError::configuration_error("SMTP_SERVER must be set")
            })?;
        
        let smtp_username = env::var("SMTP_USERNAME")
            .map_err(|_| {
                error!("SMTP_USERNAME environment variable not set");
                ApiError::configuration_error("SMTP_USERNAME must be set")
            })?;
        
        let smtp_password = env::var("SMTP_PASSWORD")
            .map_err(|_| {
                error!("SMTP_PASSWORD environment variable not set");
                ApiError::configuration_error("SMTP_PASSWORD must be set")
            })?;
        
        let from_address = env::var("SMTP_FROM_ADDRESS")
            .unwrap_or_else(|_| "no-reply@example.com".to_string());
        
        info!("Initializing SMTP connection to {} as {}", smtp_server, smtp_username);
        
        // Create SMTP transport with credentials
        let creds = Credentials::new(smtp_username, smtp_password);
        let mailer = SmtpTransport::relay(&smtp_server)
            .map_err(|e| {
                error!("Failed to create SMTP transport: {}", e);
                ApiError::internal_error(&format!("Failed to create mailer: {}", e))
            })?
            .credentials(creds)
            .build();

        Ok(Self {
            from_address,
            mailer,
        })
    }

    /// Sends an activation email with a link containing the provided activation code.
    ///
    /// # Arguments
    /// * `to_email` - The recipient's email address
    /// * `activation_code` - The unique activation code to include in the email
    /// * `redis_client` - Redis client for storing the activation code
    ///
    /// # Returns
    /// * `Ok(())` - If the email was sent successfully
    /// * `Err(ApiError)` - If sending failed
    pub async fn send_activation_email(
        &self, 
        to_email: &str, 
        activation_code: &str,
        redis_client: &RedisClient
    ) -> Result<(), ApiError> {
        // Generate the activation link with the provided code
        let activation_link = generate_activation_link(activation_code);

        // Create email body
        let email_body = format!(
            "Hello,\n\nTo activate your account, click the link below:\n{}\n\n
            If you did not create an account, please ignore this message.\n\n
            This link will expire in 24 hours.",
            activation_link
        );

        info!("Sending activation email to {}", to_email);
        
        // Build the email message
        let email = Message::builder()
            .from(self.from_address.parse().map_err(|e| {
                error!("Invalid from address: {}", e);
                ApiError::internal_error(&format!("Invalid from address: {}", e))
            })?)
            .to(to_email.parse().map_err(|e| {
                error!("Invalid recipient address: {}", e);
                ApiError::internal_error(&format!("Invalid to address: {}", e))
            })?)
            .subject("Activate Your BuildHub Account")
            .body(email_body)
            .map_err(|e| {
                error!("Failed to build email: {}", e);
                ApiError::internal_error(&format!("Failed to build email: {}", e))
            })?;

        // Store the activation code in Redis
        let to_email_clone = to_email.to_string();
        let activation_code_clone = activation_code.to_string();
        
        // Store activation code directly (no need for spawn)
        if let Err(e) = store_activation_code(redis_client, &to_email_clone, &activation_code_clone).await {
            error!("Failed to store activation code: {}", e);
            // Continue with sending email even if Redis storage fails
        }

        // Send the email
        self.mailer.send(&email)
            .map_err(|e| {
                error!("Failed to send activation email: {}", e);
                ApiError::internal_error(&format!("Failed to send activation email: {}", e))
            })?;

        info!("Activation email sent successfully to {}", to_email);
        Ok(())
    }
}

/// Generates a unique activation code.
///
/// Creates a UUID v4 string for use as an activation code.
///
/// # Returns
/// A unique string that can be used as an activation code
pub fn generate_activation_code() -> String {
    let code = Uuid::new_v4().to_string();
    info!("Generated new activation code");
    code
}

/// Creates an activation link from an activation code.
///
/// Combines the frontend URL from the environment with the activation code
/// to create a complete activation link.
///
/// # Arguments
/// * `activation_code` - The code to include in the activation link
///
/// # Returns
/// A complete URL string for account activation
pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| {
            info!("FRONTEND_URL not set, using default localhost:3000");
            "http://localhost:3000".to_string()
        });

    format!("{}/activate?code={}", frontend_url, activation_code)
}

/// Stores an activation code in Redis with the user's email as the value.
///
/// # Arguments
/// * `redis_client` - Redis client instance
/// * `email` - The user's email to associate with the code
/// * `code` - The activation code to store
///
/// # Returns
/// * `Ok(())` - If the code was stored successfully
/// * `Err(ApiError)` - If storage failed
pub async fn store_activation_code(
    redis_client: &RedisClient,
    email: &str,
    code: &str
) -> Result<(), ApiError> {
    info!("Storing activation code for {}", email);
    
    // Get an async Redis connection
    let mut conn = redis_client.get_async_connection().await
        .map_err(|e| {
            error!("Redis connection error: {}", e);
            ApiError::internal_error(&format!("Service unavailable - please try again later"))
        })?;
    
    // Create the key in the format: activation:code:{uuid}
    let key = format!("activation:code:{}", code);
    
    // Activation code expiration time (24 hours)
    const ACTIVATION_CODE_EXPIRY: u64 = 86_400; // 24 hours in seconds
    
    // Store the email as the value with expiration time
    conn.set_ex::<_, _, ()>(key, email, ACTIVATION_CODE_EXPIRY as usize).await
        .map_err(|e| {
            error!("Failed to store activation code: {}", e);
            ApiError::internal_error("Failed to complete registration. Please try again later.")
        })?;
    
    info!("Activation code stored successfully for {}", email);
    Ok(())
}

/// Verifies an activation code and returns the associated email if valid.
///
/// If the code is valid, it retrieves the associated email and deletes
/// the code from Redis to prevent reuse.
///
/// # Arguments
/// * `redis_client` - Redis client instance
/// * `code` - The activation code to verify
///
/// # Returns
/// * `Ok(String)` - The email associated with the activation code
/// * `Err(ApiError)` - If verification failed or code is invalid
pub async fn verify_activation_code(
    redis_client: &RedisClient,
    code: &str
) -> Result<String, ApiError> {
    info!("Verifying activation code");
    
    // Get Redis connection
    let mut conn = redis_client.get_async_connection().await
        .map_err(|e| {
            error!("Redis connection error during verification: {}", e);
            ApiError::internal_error(&format!("Service unavailable - please try again later"))
        })?;
    
    // Construct the key to look up
    let key = format!("activation:code:{}", code);
    
    // Get the email associated with this code
    let email: Option<String> = conn.get(&key).await
        .map_err(|e| {
            error!("Failed to query Redis for activation code: {}", e);
            ApiError::internal_error(&format!("Failed to verify activation code"))
        })?;
    
    match email {
        Some(email) => {
            info!("Valid activation code found for {}", email);
            
            // Delete the code after successful verification to prevent reuse
            let _: () = conn.del(&key).await
                .map_err(|e| {
                    error!("Failed to delete used activation code: {}", e);
                    ApiError::internal_error("Failed to complete activation process")
                })?;
            
            info!("Activation code verified and deleted for {}", email);
            Ok(email)
        },
        None => {
            info!("Invalid or expired activation code");
            Err(ApiError::bad_request_error("Invalid or expired activation code"))
        }
    }
}
