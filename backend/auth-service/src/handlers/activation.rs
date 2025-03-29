use axum::{Extension, extract::Query};
use axum::response::{IntoResponse, Html};
use serde::Deserialize;
use log::{info, error};
use redis::Client as RedisClient;

use crate::config::database::DbPool;
use crate::db::users::User;
use crate::utils::email::verify_activation_code;

#[derive(Debug, Deserialize)]
pub struct ActivationParams {
    code: String,
}

pub async fn activate_account_handler(
    Query(params): Query<ActivationParams>,
    Extension(pool): Extension<DbPool>,
    Extension(redis_client): Extension<RedisClient>,
) -> impl IntoResponse {
    // First verify the activation code in Redis and get the associated email
    let email = match verify_activation_code(&redis_client, &params.code).await {
        Ok(email) => email,
        Err(_) => {
            info!("Activation failed: Invalid or expired activation code");
            return Html("<html><body><h1>Invalid Activation Link</h1><p>The activation link is invalid or has expired.</p></body></html>".to_string());
        }
    };
    
    // Now get a database connection
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(_) => {
            error!("Database connection failed during activation");
            return Html("<html><body><h1>Server Error</h1><p>Could not connect to database.</p></body></html>".to_string());
        }
    };
    
    // Find and activate the user
    let mut user = match User::find_by_email(&mut conn, &email) {
        Ok(user) => user,
        Err(_) => {
            error!("User not found during activation: {}", email);
            return Html("<html><body><h1>Activation Failed</h1><p>Could not find user account.</p></body></html>".to_string());
        }
    };
    
    // Set user as active
    user.is_active = Some(true);
    
    // Save the changes
    if let Err(e) = user.update(&mut conn) {
        error!("Failed to update user status: {}", e);
        return Html("<html><body><h1>Activation Failed</h1><p>Could not update account status.</p></body></html>".to_string());
    }
    
    info!("Account activated successfully for: {}", email);
    
    // Return success HTML
    Html(
        r#"<html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 20px; }
                h1 { color: #4a86e8; }
                .button { background-color: #4a86e8; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; }
            </style>
        </head>
        <body>
            <h1>Account Activated!</h1>
            <p>Your account has been successfully activated. You can now log in.</p>
            <p><a href="/login" class="button">Go to Login</a></p>
        </body>
        </html>"#.to_string()
    )
}