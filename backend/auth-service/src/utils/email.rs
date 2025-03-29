use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use std::env;
use crate::utils::errors::ApiError;
use uuid::Uuid;
use redis::{AsyncCommands, Client as RedisClient};

#[derive(Clone)]
pub struct EmailConfig {
    from_address: String,
    mailer: SmtpTransport,
}

impl EmailConfig {
    pub fn new() -> Result<Self, ApiError> {
        let smtp_server = env::var("SMTP_SERVER")
            .map_err(|_| ApiError::configuration_error("SMTP_SERVER must be set"))?;
        let smtp_username = env::var("SMTP_USERNAME")
            .map_err(|_| ApiError::configuration_error("SMTP_USERNAME must be set"))?;
        let smtp_password = env::var("SMTP_PASSWORD")
            .map_err(|_| ApiError::configuration_error("SMTP_PASSWORD must be set"))?;
        let from_address = env::var("SMTP_FROM_ADDRESS")
            .unwrap_or_else(|_| "no-reply@example.com".to_string());
        
        let creds = Credentials::new(smtp_username, smtp_password);
        let mailer = SmtpTransport::relay(&smtp_server)
            .map_err(|e| ApiError::internal_error(&format!("Failed to create mailer: {}", e)))?
            .credentials(creds)
            .build();

        Ok(Self {
            from_address,
            mailer,
        })
    }

    pub fn send_activation_email(&self, to_email: &str, activation_code: &str) -> Result<(), ApiError> {
        let activation_link = generate_activation_link(activation_code);

        let email_body = format!(
            "Hello,\n\nTo activate your account, click the link below:\n{}\n\nIf you did not create an account, please ignore this message.\n\nThis link will expire in 24 hours.",
            activation_link
        );

        let email = Message::builder()
            .from(self.from_address.parse().map_err(|e| ApiError::internal_error(&format!("Invalid from address: {}", e)))?)
            .to(to_email.parse().map_err(|e| ApiError::internal_error(&format!("Invalid to address: {}", e)))?)
            .subject("Activate Your BuildHub Account")
            .body(email_body)
            .map_err(|e| ApiError::internal_error(&format!("Failed to build email: {}", e)))?;

        self.mailer.send(&email)
            .map_err(|e| ApiError::internal_error(&format!("Failed to send activation email: {}", e)))?;

        Ok(())
    }
    
    // Test connection method remains the same
}

// Generate a UUID for activation
pub fn generate_activation_code() -> String {
    Uuid::new_v4().to_string()
}

// Create the activation link - we'll still use frontend URL
pub fn generate_activation_link(activation_code: &str) -> String {
    let frontend_url = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    format!("{}/activate?code={}", frontend_url, activation_code)
}

// Store the activation code in Redis with the user's email
#[allow(dead_code)]
pub async fn store_activation_code(redis_client: &RedisClient, email: &str, code: &str) -> Result<(), ApiError> {
    let mut conn = redis_client.get_async_connection().await
        .map_err(|e| ApiError::internal_error(&format!("Redis connection error: {}", e)))?;
    
    // Key format: activation:code:{uuid}
    let key = format!("activation:code:{}", code);
    
    // Store email as the value
    let _: () = conn.set_ex(key, email, 86400).await
        .map_err(|e| ApiError::internal_error(&format!("Failed to store activation code: {}", e)))?;
    
    Ok(())
}

// Retrieve and verify an activation code
pub async fn verify_activation_code(redis_client: &RedisClient, code: &str) -> Result<String, ApiError> {
    let mut conn = redis_client.get_async_connection().await
        .map_err(|e| ApiError::internal_error(&format!("Redis connection error: {}", e)))?;
    
    let key = format!("activation:code:{}", code);
    
    // Get the email associated with this code
    let email: Option<String> = conn.get(&key).await
        .map_err(|e| ApiError::internal_error(&format!("Failed to verify activation code: {}", e)))?;
    
    match email {
        Some(email) => {
            // Delete the code after successful verification
            let _: () = conn.del(&key).await
                .map_err(|e| ApiError::internal_error(&format!("Failed to delete used activation code: {}", e)))?;
            
            Ok(email)
        },
        None => Err(ApiError::bad_request_error("Invalid or expired activation code"))
    }
}