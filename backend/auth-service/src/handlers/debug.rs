// filepath: /home/przemander/projects/BuildHub/backend/auth-service/src/handlers/debug.rs

use std::sync::Arc;
use axum::{extract::State, http::StatusCode, Json, Router};
use axum::routing::post;
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use serde::Deserialize;
use serde_json::json;

use crate::{app::AppState, log_info, log_error, log_warn, config::database};
use crate::db::users::User;
use crate::handlers::password_reset_logic::REDIS_KEY_PREFIX;

pub fn debug_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/debug/clean-user", post(clean_test_user))
        .route("/debug/reset-rate-limiter", post(reset_rate_limiter))
        .route("/debug/activate-account", post(activate_account))
        .route("/debug/verify-user", post(verify_user))
        .route("/debug/create-reset-token", post(create_reset_token))
}

#[derive(Deserialize)]
pub struct TestRequest {
    test_secret: String,
}

#[derive(Deserialize)]
pub struct TestUserRequest {
    username: String,
    test_secret: String,
}

#[derive(Deserialize)]
pub struct TestEmailRequest {
    email: String,
    test_secret: String,
}

// Funkcja do weryfikacji klucza testowego
fn verify_test_secret(secret: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let expected_secret = std::env::var("TEST_SECRET").unwrap_or_default();
    if secret != expected_secret || expected_secret.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "status": "error",
                "message": "Invalid test secret"
            })),
        ));
    }

    // Sprawdź czy jesteśmy w środowisku testowym
    if std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) == "production" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "Debug endpoints disabled in production"
            })),
        ));
    }

    Ok(())
}

async fn clean_test_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    verify_test_secret(&payload.test_secret)?;

    // Clone username for use in both the log and the async closure
    let username = payload.username.clone();
    log_info!("Test", &format!("Cleaning test user: {}", username), "debug");

    // Clone for closure
    let username_for_closure = username.clone();
    
    // Usuń użytkownika z bazy danych
    let result = tokio::task::spawn_blocking(move || {
        use crate::db::schema::users::dsl;
        
        let mut conn = match database::get_connection(&state.pool) {
            Ok(c) => c,
            Err(e) => {
                log_error!("Test", &format!("Database connection error: {}", e), "error");
                return Err(DieselError::BrokenTransactionManager);
            }
        };

        diesel::delete(dsl::users.filter(dsl::username.eq(username_for_closure)))
            .execute(&mut conn)
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": "Task execution error" })),
        )
    })?;

    match result {
        Ok(deleted) => Ok(Json(json!({
            "status": "success", 
            "message": "User deleted successfully",
            "deleted": deleted
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR, 
            Json(json!({ 
                "status": "error", 
                "message": format!("Database error: {}", e) 
            }))
        ))
    }
}

async fn reset_rate_limiter(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    verify_test_secret(&payload.test_secret)?;

    log_info!("Test", "Resetting rate limiter", "debug");

    // Resetuj rate limiter dla wszystkich IP
    if let Some(redis_client) = &state.redis_client {
        let mut conn = redis_client.get_connection().map_err(|e| {
            log_error!("Test", &format!("Redis connection error: {}", e), "error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Redis connection error" })),
            )
        })?;

        // Znajdź i usuń wszystkie możliwe klucze rate limitera
        // Dodaj konkretne wzorce kluczy używane w aplikacji
        let patterns = vec![
            "ratelimit:*",   // Oryginalny prefix
            "rate_limit:*",  // Prefix z utils/rate_limit.rs
            "rate:*",        // Prefix często używany w middleware
            "rate:/auth/register:*",   // Klucze dla endpointu rejestracji
            "rate:/auth/login:*",      // Klucze dla endpointu logowania
            "rate:/auth/password-reset*", // Klucze dla endpointów resetowania hasła
            "rate:login:*",  // Klucze z login_checks.rs
        ];
        
        let mut total_deleted = 0;
        
        for pattern in patterns {
            log_info!("Test", &format!("Searching for pattern: {}", pattern), "debug");
            match redis::cmd("KEYS")
                .arg(pattern)
                .query::<Vec<String>>(&mut conn)
            {
                Ok(keys) => {
                    if !keys.is_empty() {
                        // Wypisz znalezione klucze (opcjonalnie)
                        log_info!("Test", &format!("Found keys: {:?}", keys), "debug");
                        
                        let _: () = redis::cmd("DEL")
                            .arg(&keys)
                            .query(&mut conn)
                            .map_err(|e| {
                                log_error!("Test", &format!("Redis delete error: {}", e), "error");
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({ "status": "error", "message": "Redis delete error" })),
                                )
                            })?;
                        log_info!("Test", &format!("Deleted {} rate limit keys with pattern {}", keys.len(), pattern), "debug");
                        total_deleted += keys.len();
                    } else {
                        log_info!("Test", &format!("No keys found for pattern: {}", pattern), "debug");
                    }
                }
                Err(e) => {
                    log_error!("Test", &format!("Redis keys error for pattern {}: {}", pattern, e), "error");
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "status": "error", "message": "Redis keys error" })),
                    ));
                }
            }
        }

        // Dodaj listę wszystkich kluczy w Redis dla diagnostyki
        log_info!("Test", "Listing all keys in Redis for diagnosis", "debug");
        match redis::cmd("KEYS").arg("*").query::<Vec<String>>(&mut conn) {
            Ok(all_keys) => {
                if !all_keys.is_empty() {
                    log_info!("Test", &format!("All keys in Redis: {:?}", all_keys), "debug");
                } else {
                    log_info!("Test", "Redis database is empty", "debug");
                }
            }
            Err(e) => {
                log_error!("Test", &format!("Redis list all keys error: {}", e), "error");
            }
        }

        if total_deleted > 0 {
            log_info!("Test", &format!("Deleted a total of {} rate limit keys", total_deleted), "debug");
        } else {
            log_info!("Test", "No rate limit keys found", "debug");
        }

        Ok(Json(json!({
            "status": "success",
            "message": format!("Rate limiter reset successfully, deleted {} keys", total_deleted)
        })))
    } else {
        log_warn!("Test", "Redis not configured, rate limiter not reset", "warning");
        Ok(Json(json!({
            "status": "success",
            "message": "Redis not configured, rate limiter not reset"
        })))
    }
}

async fn activate_account(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    verify_test_secret(&payload.test_secret)?;

    // Clone username for use in both the log and the async closure
    let username = payload.username.clone();
    log_info!("Test", &format!("Activating account: {}", username), "debug");

    // Aktualizuj status użytkownika na aktywny
    let username_for_closure = username.clone(); // Clone for closure
    
    let result = tokio::task::spawn_blocking(move || {
        use crate::db::schema::users::dsl;
        
        let mut conn = match database::get_connection(&state.pool) {
            Ok(c) => c,
            Err(e) => {
                log_error!("Test", &format!("Database connection error: {}", e), "error");
                return Err(DieselError::BrokenTransactionManager);
            }
        };
        
        diesel::update(dsl::users.filter(dsl::username.eq(username_for_closure)))
            .set(dsl::is_active.eq(true))
            .execute(&mut conn)
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": "Task execution error" })),
        )
    })?;

    match result {
        Ok(updated) => {
            if updated > 0 {
                Ok(Json(json!({
                    "status": "success", 
                    "message": "Account activated successfully"
                })))
            } else {
                Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "status": "error", "message": "User not found" })),
                ))
            }
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR, 
            Json(json!({ 
                "status": "error", 
                "message": format!("Database error: {}", e) 
            }))
        ))
    }
}

async fn verify_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TestUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    verify_test_secret(&payload.test_secret)?;

    log_info!("Test", &format!("Verifying user status: {}", payload.username), "debug");

    // Sprawdź stan konta użytkownika
    let username = payload.username.clone();
    
    let result = tokio::task::spawn_blocking(move || {
        use crate::db::schema::users::dsl;
        
        let mut conn = match database::get_connection(&state.pool) {
            Ok(c) => c,
            Err(e) => {
                log_error!("Test", &format!("Database connection error: {}", e), "error");
                return Err::<_, DieselError>(DieselError::BrokenTransactionManager);
            }
        };
        
        dsl::users.filter(dsl::username.eq(username))
            .first::<User>(&mut conn)
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": "Task execution error" })),
        )
    })?;

    match result {
        Ok(user) => {
            Ok(Json(json!({
                "status": "success", 
                "message": "User found",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_active": user.is_active.unwrap_or(false)
                }
            })))
        },
        Err(e) => {
            if let DieselError::NotFound = e {
                Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "status": "error", "message": "User not found" })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR, 
                    Json(json!({ 
                        "status": "error", 
                        "message": format!("Database error: {}", e) 
                    }))
                ))
            }
        }
    }
}

/// Endpoint tworzący token do resetowania hasła na potrzeby testów
async fn create_reset_token(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<TestEmailRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    verify_test_secret(&payload.test_secret)?;

    log_info!("PasswordReset", &format!("Creating password reset token for testing: {}", payload.email), "debug");

    // Sprawdź czy Redis jest dostępny
    let redis_client = match &app_state.redis_client {
        Some(client) => client,
        None => {
            log_error!("PasswordReset", "Redis unavailable for token creation", "error");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": "Redis unavailable"
                })),
            ));
        }
    };

    // Sprawdź czy email istnieje w bazie danych
    use crate::config::database;
    
    let mut conn = match database::get_connection(&app_state.pool) {
        Ok(c) => c,
        Err(e) => {
            log_error!("PasswordReset", &format!("Database connection error: {}", e), "error");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": format!("Database error: {}", e)
                })),
            ));
        }
    };

    // Spróbuj znaleźć użytkownika
    let _user = match User::find_by_email(&mut conn, &payload.email) {
        Ok(user) => user,
        Err(_) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({
                    "status": "error",
                    "message": format!("User with email {} not found", payload.email)
                })),
            ));
        }
    };

    // Wygeneruj token
    let token = {
        use rand::{thread_rng, Rng};
        use base64::{engine::general_purpose, Engine as _};
        
        // Generuj 32 bajty losowych danych
        let mut bytes = [0u8; 32];
        thread_rng().fill(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    
    // Zapisz mapowanie token → email w Redis
    let token_key = format!("{}{}", REDIS_KEY_PREFIX, token);
    let token_ttl = 30 * 60; // 30 minut

    let mut redis_conn = match redis_client.get_connection() {
        Ok(conn) => conn,
        Err(e) => {
            log_error!("PasswordReset", &format!("Redis connection error: {}", e), "error");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": "Redis connection error"
                })),
            ));
        }
    };

    match redis::cmd("SET")
        .arg(&token_key)
        .arg(&payload.email)
        .arg("EX")
        .arg(token_ttl)
        .query::<()>(&mut redis_conn)
    {
        Ok(_) => {
            Ok(Json(json!({
                "status": "success",
                "message": "Password reset token created",
                "token": token
            })))
        }
        Err(e) => {
            log_error!("PasswordReset", &format!("Failed to store token in Redis: {}", e), "error");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": format!("Redis error: {}", e)
                })),
            ))
        }
    }
}