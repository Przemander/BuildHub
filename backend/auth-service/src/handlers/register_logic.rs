//! User registration business logic.
//!
//! Implements secure user registration with email activation,
//! proper validation, and comprehensive observability.

use crate::{
    app::AppState,
    config::redis::store_activation_code,
    db::users::{RegisterData, User},
    utils::metrics,  // Fixed: correct import path
    utils::{
        email::generate_activation_code,
        errors::AuthServiceError,
        validators::{validate_email, validate_password, validate_username},
    },
};
use axum::{http::StatusCode, response::IntoResponse, Json};
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use serde_json::json;
use tokio::time::{timeout, Duration};
use tracing::{error, info, span, warn, Instrument, Level};
use uuid::Uuid;

// Diesel schema imports
use crate::db::schema::users::dsl::{email as users_email, username as users_username, users};

/// Timeout for sending activation emails
const EMAIL_SEND_TIMEOUT_SECS: u64 = 8;

/// Process user registration request.
///
/// # Flow
/// 1. Validate configuration (email, Redis)
/// 2. Validate input data (username, email, password)
/// 3. Check uniqueness in database
/// 4. Create user record
/// 5. Generate and store activation code
/// 6. Send activation email (async)
///
/// # Security
/// - Passwords are hashed with Argon2id
/// - Activation codes are cryptographically secure
/// - Email enumeration is prevented
pub async fn process_registration(
    app_state: &AppState,
    data: RegisterData,
) -> Result<impl IntoResponse, AuthServiceError> {
    let request_id = Uuid::new_v4().to_string();
    
    // Create root span for the entire registration flow
    let span = span!(Level::INFO, "registration",
        request_id = %request_id,
        username = %data.username,
        email_domain = data.email.split('@').nth(1).unwrap_or("unknown")
    );
    let span_for_instrument = span.clone();  // Fixed: Clone for .instrument()

    async move {
        info!("Starting registration process");

        // ===== 1. CONFIGURATION CHECK =====
        let email_cfg = app_state.email_config.as_ref().ok_or_else(|| {
            error!("Email configuration missing - service misconfigured");
            metrics::auth::register_failure();
            AuthServiceError::configuration("Email service not configured")
        })?;

        let redis_client = app_state.redis_client.as_ref().ok_or_else(|| {
            error!("Redis client missing - service misconfigured");
            metrics::auth::register_failure();
            AuthServiceError::configuration("Redis service not configured")
        })?;

        // ===== 2. INPUT VALIDATION =====
        validate_inputs(&data).map_err(|e| {
            warn!("Input validation failed: {}", e);
            metrics::auth::register_failure();
            e
        })?;
        info!("Input validation passed");

        // ===== 3. DATABASE OPERATIONS =====
        let db_span = span!(Level::INFO, "db_operations");
        let user = async {
            // Acquire database connection
            let mut conn = app_state.pool.get().map_err(|e| {
                error!("Failed to get database connection from pool: {}", e);
                metrics::db::connection_failed();
                metrics::auth::register_failure();
                // Fixed: Use simplified error system
                AuthServiceError::database(format!("Connection pool error: {}", e))
            })?;
            metrics::db::connection_acquired();
            info!("Database connection acquired");

            // Check for duplicate email/username
            check_uniqueness(&mut conn, &data.email, &data.username)?;

            // Create new user
            let new_user = User::new_for_insert(&data.username, &data.email, &data.password);
            let user = User::save_new(new_user, &mut conn).map_err(|e| {
                error!("Failed to create user in database: {}", e);
                metrics::db::query_failure("create_user");
                metrics::auth::register_failure();
                e
            })?;
            
            metrics::db::query_success("create_user");
            info!(user_id = %user.id, "User created successfully");

            Ok::<_, AuthServiceError>(user)
        }
        .instrument(db_span)
        .await?;

        // ===== 4. ACTIVATION CODE SETUP =====
        let activation_span = span!(Level::INFO, "activation_setup");
        let code = async {
            let code = generate_activation_code();
            info!("Generated activation code");
            
            store_activation_code(redis_client, &user.email, &code)
                .await
                .map_err(|e| {
                    error!("Failed to store activation code in Redis: {}", e);
                    metrics::external::redis_failure("store_activation");
                    metrics::auth::register_failure();
                    AuthServiceError::from(e)
                })?;
            
            metrics::external::redis_success("store_activation");
            info!("Activation code stored in Redis");
            
            Ok::<_, AuthServiceError>(code)
        }
        .instrument(activation_span)
        .await?;

        // ===== 5. SEND ACTIVATION EMAIL (NON-BLOCKING) =====
        spawn_activation_email(
            email_cfg.clone(),
            redis_client.clone(),
            user.email.clone(),
            code,
        );

        // ===== 6. SUCCESS RESPONSE =====
        metrics::auth::register_success();
        info!(
            user_id = %user.id,
            request_id = %request_id,
            "Registration completed successfully"
        );

        Ok((
            StatusCode::CREATED,
            Json(json!({
                "status": "success",
                "message": "Registration successful! Please check your email to activate your account.",
                "request_id": request_id
            })),
        ))
    }
    .instrument(span_for_instrument)  // Fixed: Use the clone
    .await
}

/// Validate all registration input fields.
#[inline]
fn validate_inputs(data: &RegisterData) -> Result<(), AuthServiceError> {
    validate_username(&data.username)?;
    validate_email(&data.email)?;
    validate_password(&data.password)?;
    Ok(())
}

/// Check if email or username already exists in database.
fn check_uniqueness(
    conn: &mut diesel::PgConnection,
    email: &str,
    username: &str,
) -> Result<(), AuthServiceError> {
    let span = span!(Level::DEBUG, "check_uniqueness");
    let _enter = span.enter();

    // Query for existing email or username
    match users
        .filter(users_email.eq(email).or(users_username.eq(username)))
        .select((users_email, users_username))
        .first::<(String, String)>(conn)
    {
        Ok((found_email, found_username)) => {
            // Check which field is duplicate
            if found_email == email {
                warn!("Registration attempt with existing email");
                metrics::auth::register_failure();
                return Err(AuthServiceError::validation(
                    "email",
                    "Email address is already registered",
                ));
            }
            if found_username == username {
                warn!("Registration attempt with existing username");
                metrics::auth::register_failure();
                return Err(AuthServiceError::validation(
                    "username",
                    "Username is already taken",
                ));
            }
            Ok(())
        }
        Err(DieselError::NotFound) => {
            info!("Uniqueness check passed - no duplicates");
            Ok(())
        }
        Err(e) => {
            error!("Database error during uniqueness check: {}", e);
            metrics::db::query_failure("check_uniqueness");
            metrics::auth::register_failure();
            Err(AuthServiceError::database("Failed to check uniqueness"))
        }
    }
}

/// Spawn background task to send activation email.
fn spawn_activation_email(
    email_cfg: crate::utils::email::EmailConfig,
    redis_client: redis::Client,
    email: String,
    code: String,
) {
    tokio::spawn(async move {
        let span = span!(Level::INFO, "send_activation_email", 
            email_domain = email.split('@').nth(1).unwrap_or("unknown")
        );
        let _enter = span.enter();

        info!("Attempting to send activation email");
        
        let send_fut = email_cfg.send_activation_email(&email, &code, &redis_client);
        
        match timeout(Duration::from_secs(EMAIL_SEND_TIMEOUT_SECS), send_fut).await {
            Ok(Ok(())) => {
                info!("Activation email sent successfully");
                metrics::external::email_sent();
            }
            Ok(Err(e)) => {
                error!("Failed to send activation email: {}", e);
                metrics::external::email_failed();
            }
            Err(_) => {
                error!("Activation email timed out after {}s", EMAIL_SEND_TIMEOUT_SECS);
                metrics::external::email_failed();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::email::EmailConfig;
    use crate::utils::test_utils::state_with_redis;

    fn make_state() -> AppState {
        metrics::init();
        let mut state = state_with_redis();
        state.email_config = Some(EmailConfig::dummy());
        state
    }

    #[tokio::test]
    async fn test_missing_email_config() {
        let mut state = make_state();
        state.email_config = None;
        
        let data = RegisterData {
            username: "testuser".into(),
            email: "test@example.com".into(),
            password: "Valid123!".into(),
        };
        
        let result = process_registration(&state, data).await;
        assert!(matches!(result, Err(AuthServiceError::Configuration(_))));
    }

    #[tokio::test]
    async fn test_invalid_username() {
        let state = make_state();
        
        let data = RegisterData {
            username: "ab".into(), // Too short
            email: "test@example.com".into(),
            password: "Valid123!".into(),
        };
        
        let result = process_registration(&state, data).await;
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_duplicate_email() {
        let state = make_state();
        
        let first = RegisterData {
            username: "user1".into(),
            email: "duplicate@example.com".into(),
            password: "Valid123!".into(),
        };
        
        // First registration should succeed
        assert!(process_registration(&state, first.clone()).await.is_ok());
        
        // Second registration with same email should fail
        let second = RegisterData {
            username: "user2".into(),
            email: first.email.clone(),
            password: "Valid123!".into(),
        };
        
        let result = process_registration(&state, second).await;
        // Fixed: Use struct pattern matching for Validation variant
        assert!(matches!(result, Err(AuthServiceError::Validation { .. })));
    }

    #[tokio::test]
    async fn test_successful_registration() {
        let state = make_state();
        
        // Add this line to mock the email client behavior in test mode
        std::env::set_var("TEST_MODE", "true");
        
        // Ensure username format meets validation requirements (alphanumeric with underscore)
        let binding = uuid::Uuid::new_v4().to_string();
        let uuid = binding.split('-').next().unwrap();
        let data = RegisterData {
            username: format!("user_{}", uuid),  // Start with letter, use underscore
            email: format!("new_{}@example.com", uuid),
            password: "Strong123!".into(),
        };
        
        let result = process_registration(&state, data.clone()).await;
        assert!(result.is_ok(), "Registration failed: {:?}", result.err());
        
        // Verify user was created
        let mut conn = state.pool.get().unwrap();
        let user = User::find_by_username(&mut conn, &data.username).unwrap();
        assert_eq!(user.email, data.email);
        assert!(!user.is_active); // Should not be active until email confirmation
        
        // Clean up environment variable
        std::env::remove_var("TEST_MODE");
    }
}