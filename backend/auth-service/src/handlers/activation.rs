//! Account activation handler implementation.
//!
//! This module provides functionality for activating user accounts
//! via email activation links with verification codes.

use axum::{Extension, extract::Query};
use axum::response::{IntoResponse, Html};
use serde::Deserialize;
use log::{info, error, warn};
use redis::Client as RedisClient;

use crate::config::database::DbPool;
use crate::db::users::User;
use crate::utils::email::verify_activation_code;
use crate::utils::errors::ApiError;

/// Request parameters for account activation.
#[derive(Debug, Deserialize)]
pub struct ActivationParams {
    code: String,
}

/// Handler for account activation requests.
///
/// This handler processes account activation links by:
/// 1. Verifying the activation code in Redis
/// 2. Retrieving the associated email address
/// 3. Finding the user account with that email
/// 4. Setting the account to active status
/// 5. Returning an HTML response to the user
///
/// # Returns
/// * HTML response indicating success or failure
pub async fn activate_account_handler(
    Query(params): Query<ActivationParams>,
    Extension(pool): Extension<DbPool>,
    Extension(redis_client): Extension<RedisClient>,
) -> impl IntoResponse {
    // Log the activation attempt
    info!("Processing account activation request with code: {}", params.code);
    
    // Process the activation and handle errors with appropriate HTML responses
    match process_activation(pool, redis_client, params.code).await {
        Ok(_) => render_success_page(),
        Err(error) => render_error_page(&error),
    }
}

/// Core activation logic separated for better testability and error handling.
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `redis_client` - Redis client for code verification
/// * `code` - The activation code to verify
///
/// # Returns
/// * `Ok(String)` - The email of the activated user
/// * `Err(ApiError)` - If activation fails
async fn process_activation(
    pool: DbPool, 
    redis_client: RedisClient,
    code: String
) -> Result<String, ApiError> {
    // Verify activation code and get the associated email
    let email = verify_activation_code(&redis_client, &code).await
        .map_err(|e| {
            info!("Activation failed: Invalid or expired code: {}", e);
            ApiError::bad_request_error("Invalid or expired activation code")
        })?;
    
    // Get database connection
    let mut conn = pool.get()
        .map_err(|e| {
            error!("Database connection failed during activation: {}", e);
            ApiError::internal_error("Database connection error")
        })?;
    
    // Find user by email
    let mut user = User::find_by_email(&mut conn, &email)
        .map_err(|e| {
            error!("User not found during activation for email {}: {}", email, e);
            ApiError::not_found_error("User account")
        })?;
    
    // Check if the account is already active
    if let Some(is_active) = user.is_active {
        if is_active {
            warn!("Account already active for: {}", email);
            return Ok(email); // Return success even if already active
        }
    }
    
    // Set user as active
    user.is_active = Some(true);
    
    // Save the changes
    user.update(&mut conn)
        .map_err(|e| {
            error!("Failed to update user status for {}: {}", email, e);
            ApiError::internal_error("Failed to activate account")
        })?;
    
    info!("Account activated successfully for: {}", email);
    Ok(email)
}

/// Renders a success page after successful account activation.
///
/// # Returns
/// An HTML response with a styled success message
fn render_success_page() -> Html<String> {
    Html(
        r#"<!DOCTYPE html>
        <html>
        <head>
            <title>Account Activated - BuildHub</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    color: #333;
                    background-color: #f9f9f9;
                }
                .container {
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    padding: 30px;
                    margin-top: 50px;
                }
                h1 {
                    color: #4a86e8;
                    margin-top: 0;
                }
                .button {
                    background-color: #4a86e8;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 5px;
                    display: inline-block;
                    font-weight: 500;
                    margin-top: 15px;
                    transition: background-color 0.3s;
                }
                .button:hover {
                    background-color: #3a76d8;
                }
                .check-icon {
                    color: #4CAF50;
                    font-size: 48px;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="check-icon">✓</div>
                <h1>Account Activated!</h1>
                <p>Your account has been successfully activated. You can now log in to access your BuildHub account.</p>
                <a href="/login" class="button">Go to Login</a>
            </div>
        </body>
        </html>"#.to_string()
    )
}

/// Renders an error page when activation fails.
///
/// # Arguments
/// * `error` - The API error that occurred
///
/// # Returns
/// An HTML response with a styled error message
fn render_error_page(error: &ApiError) -> Html<String> {
    // Determine the appropriate error heading and message
    let (heading, message) = match error.status.as_str() {
        "bad_request" => (
            "Invalid Activation Link",
            "The activation link is invalid or has expired. Please request a new activation link."
        ),
        "not_found" => (
            "Account Not Found",
            "We couldn't find an account associated with this activation link."
        ),
        _ => (
            "Activation Failed",
            "There was a problem activating your account. Please try again later or contact support."
        ),
    };

    Html(format!(
        r#"<!DOCTYPE html>
        <html>
        <head>
            <title>Activation Failed - BuildHub</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    color: #333;
                    background-color: #f9f9f9;
                }}
                .container {{
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    padding: 30px;
                    margin-top: 50px;
                }}
                h1 {{
                    color: #e74c3c;
                    margin-top: 0;
                }}
                .button {{
                    background-color: #4a86e8;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 5px;
                    display: inline-block;
                    font-weight: 500;
                    margin-top: 15px;
                    transition: background-color 0.3s;
                }}
                .button:hover {{
                    background-color: #3a76d8;
                }}
                .error-icon {{
                    color: #e74c3c;
                    font-size: 48px;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">✗</div>
                <h1>{}</h1>
                <p>{}</p>
                <a href="/" class="button">Return to Home</a>
            </div>
        </body>
        </html>"#,
        heading,
        message
    ))
}