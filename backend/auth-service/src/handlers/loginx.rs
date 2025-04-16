//! User authentication handlers.
//!
//! This module provides functionality for user authentication:
//! - Login with username/password credentials
//! - Token-based authentication using JWTs
//! - Refresh token functionality and secure logout with token revocation.
//!
//! Logging is focused on critical state changes and errors, while high-frequency events
//! are tracked via metrics.

// Lines 1-10: Module documentation explaining the purpose of this file: handling user login, logout, and token refresh, along with the strategy for logging and metrics.

use axum::{
    extract::{State, Json}, // Imports Axum extractors for accessing shared application state and JSON request bodies.
    http::StatusCode,      // Imports HTTP status codes (e.g., OK, Unauthorized).
    response::IntoResponse, // Imports the trait needed to convert return types into HTTP responses.
};
use serde::{Deserialize, Serialize}; // Imports traits for serializing Rust structs into formats like JSON and deserializing JSON into Rust structs.
use serde_json::json;             // Imports the `json!` macro for easily creating JSON values.
use redis::Client as RedisClient; // Imports the Redis client type, renaming it to `RedisClient`.
use diesel::SqliteConnection;     // Imports the specific Diesel connection type for SQLite.

use crate::{log_info, log_warn, log_error}; // Imports custom logging macros from your project.
use crate::app::AppState;                 // Imports the shared application state struct.
use crate::config::database::DbPool;      // Imports the database connection pool type.
use crate::db::users::User;               // Imports the `User` struct, likely representing your database user model.
use crate::utils::errors::ApiError;       // Imports the custom error type used for API responses.
use crate::utils::jwt::{generate_token, validate_token, revoke_token, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH}; // Imports JWT utility functions and constants for token types.
use crate::utils::metrics::{
    AUTH_LOGIN_ATTEMPTS, TOKEN_OPERATIONS, TOKEN_VALIDATIONS, // Imports Prometheus metrics counters/gauges related to authentication and tokens.
    REQUESTS_TOTAL, DB_OPERATIONS, RequestTimer,             // Imports general request/DB metrics and the `RequestTimer` utility.
};

// Lines 12-31: Import necessary components from Axum, Serde, Redis, Diesel, and internal project modules (state, DB, errors, JWT utils, metrics).

#[derive(Debug, Deserialize)] // Derives `Debug` for printing and `Deserialize` to read from JSON.
pub struct LoginRequest {      // Defines the structure expected in the JSON body of a login request.
    pub username: String,      // The user's username.
    pub password: String,      // The user's password.
}

// Lines 33-38: Defines the `LoginRequest` struct to deserialize login credentials from the request body.

#[derive(Debug, Serialize)] // Derives `Debug` for printing and `Serialize` to write to JSON.
pub struct UserResponse {    // Defines the structure for user information included in responses.
    pub username: String,    // The user's username.
    pub email: String,       // The user's email.
}

// Lines 40-45: Defines the `UserResponse` struct for serializing basic user details in responses.

#[derive(Debug, Serialize)] // Derives `Debug` for printing and `Serialize` to write to JSON.
pub struct TokenResponse {   // Defines the structure for responses containing authentication tokens.
    pub access_token: String, // The generated access token.
    pub refresh_token: String,// The generated refresh token.
    pub token_type: String,   // The token type (usually "Bearer").
    pub user: UserResponse,   // Nested user information.
}

// Lines 47-54: Defines the `TokenResponse` struct, although it doesn't seem to be directly used in the current code (the JSON response is built manually).

#[derive(Debug, Deserialize)] // Derives `Debug` for printing and `Deserialize` to read from JSON.
pub struct TokenRequest {      // Defines the structure for requests that only contain a token (like logout or refresh).
    pub token: String,         // The token string.
}

// Lines 56-60: Defines the `TokenRequest` struct for deserializing requests containing a single token.

/// Handler for processing user login requests.
///
/// Measures overall request duration through a RequestTimer and
/// uses metrics to track the outcomes. Logging is kept minimal:
/// errors and overall outcome are logged.
pub async fn login_handler( // Defines the asynchronous function that handles POST requests to the login endpoint.
    State(app_state): State<AppState>, // Extracts the shared application state (`AppState`).
    Json(login_request): Json<LoginRequest>, // Extracts and deserializes the JSON request body into a `LoginRequest`.
) -> impl IntoResponse { // Returns a type that can be converted into an HTTP response.
    let mut timer = RequestTimer::start("/auth/login"); // Starts a timer to measure the request duration, associated with the "/auth/login" route.
    REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "pending"]).inc(); // Increments the total requests metric, marking this one as "pending".

    let result = process_login(app_state.pool.clone(), login_request).await; // Calls the `process_login` function, passing a clone of the DB pool and the request data. Awaits its result.

    match &result { // Matches on the `Result` returned by `process_login`.
        Ok(_) => { // If `process_login` succeeded:
            AUTH_LOGIN_ATTEMPTS.with_label_values(&["success"]).inc(); // Increments the login success metric.
            log_info!("Authentication", "User login complete", "success"); // Logs a success message.
            timer.set_status("200"); // Sets the status code on the timer for metrics.
            REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", "200"]).inc(); // Increments the total requests metric again, now with status "200".
        },
        Err(api_error) => { // If `process_login` returned an `ApiError`:
            AUTH_LOGIN_ATTEMPTS.with_label_values(&["failure"]).inc(); // Increments the login failure metric.
            log_warn!("Authentication", "User login failed", "failure"); // Logs a warning message.
            let status_code = match api_error.status.as_str() { // Determines the HTTP status code string based on the `ApiError` type.
                "unauthorized" => "401",
                "internal_error" => "500",
                _ => "400", // Default to 400 Bad Request for other errors.
            };
            timer.set_status(status_code); // Sets the determined status code on the timer.
            REQUESTS_TOTAL.with_label_values(&["/auth/login", "POST", status_code]).inc(); // Increments the total requests metric with the determined error status code.
        },
    }

    timer.complete("POST"); // Stops the timer and records the duration metric for the "POST" method.
    result.into_response() // Converts the `Result` (either the success JSON or the `ApiError`) into an HTTP response.
}

// Lines 62-95: Defines the main `login_handler`. It sets up metrics/timing, calls `process_login`, updates metrics/logs based on the outcome, completes timing, and returns the response.

/// Separates out login processing into authentication and token generation.
async fn process_login( // Defines an async helper function containing the core login logic.
    pool: DbPool,             // Takes ownership of the database pool.
    login_request: LoginRequest, // Takes ownership of the login request data.
) -> Result<impl IntoResponse, ApiError> { // Returns a `Result` containing a response or an `ApiError`.
    // Obtain a database connection (metrics track success/failure).
    let mut conn = match pool.get() { // Attempts to get a connection from the pool.
        Ok(conn) => { // If successful:
            DB_OPERATIONS.with_label_values(&["connection", "success"]).inc(); // Increments DB connection success metric.
            conn // Assign the connection to `conn`.
        },
        Err(_) => { // If getting a connection fails:
            DB_OPERATIONS.with_label_values(&["connection", "failure"]).inc(); // Increments DB connection failure metric.
            log_error!("Authentication", "Database connection failed", "failure"); // Logs a critical error.
            return Err(ApiError::internal_error("Database connection error")); // Returns an internal server error immediately.
        }
    };

    // Calls `authenticate_user` to find and verify the user using the DB connection. Propagates errors using `?`.
    let user = authenticate_user(&mut conn, &login_request)?;
    // Calls `generate_auth_tokens` to create access and refresh tokens for the authenticated user. Propagates errors using `?`.
    let (access_token, refresh_token) = generate_auth_tokens(&user.username)?;

    Ok(( // If authentication and token generation succeed, returns an OK response.
        StatusCode::OK, // Sets the HTTP status to 200 OK.
        Json(json!({ // Creates a JSON response body using the `json!` macro.
            "status": "success",
            "message": "Login successful",
            "data": { // Nests the tokens and user info under a "data" key.
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer", // Standard token type.
                "user": { // Includes basic user details.
                    "username": user.username,
                    "email": user.email,
                }
            }
        }))
    ))
}

// Lines 97-129: Defines `process_login`. It gets a DB connection, calls functions to authenticate the user and generate tokens, and builds the success JSON response.

/// Authenticates a user by looking up by username and verifying the password.
/// Only logs error conditions and overall outcome.
fn authenticate_user( // Defines a synchronous function to handle user lookup and password verification.
    conn: &mut SqliteConnection, // Takes a mutable reference to the database connection.
    login_request: &LoginRequest, // Takes an immutable reference to the login request data.
) -> Result<User, ApiError> { // Returns a `Result` containing the `User` or an `ApiError`.
    let user = match User::find_by_username(conn, &login_request.username) { // Attempts to find the user by username in the database.
        Ok(user) => { // If found:
            DB_OPERATIONS.with_label_values(&["query", "success"]).inc(); // Increments DB query success metric.
            user // Assign the found user.
        },
        Err(_) => { // If not found or other DB error:
            DB_OPERATIONS.with_label_values(&["query", "failure"]).inc(); // Increments DB query failure metric.
            log_warn!("Authentication", "User lookup failed", "failure"); // Logs a warning (user not found is expected sometimes).
            return Err(ApiError::unauthorized_error("Invalid username or password")); // Returns a generic unauthorized error.
        }
    };

    match user.verify_password(&login_request.password) { // Calls the `verify_password` method on the `User` struct.
        Ok(true) => { /* Password verified – metric already recorded if needed */ }, // If password matches, do nothing here.
        Ok(false) => { // If password does not match:
            log_warn!("Authentication", "Password verification failed", "failure"); // Log a warning.
            return Err(ApiError::unauthorized_error("Invalid username or password")); // Return a generic unauthorized error.
        },
        Err(_) => { // If the password hashing/verification process itself fails:
            log_error!("Authentication", "Password verification error", "failure"); // Log a critical error.
            return Err(ApiError::internal_error("Password verification failed")); // Return an internal server error.
        }
    }

    if let Some(false) = user.is_active { // Checks if the `is_active` field exists and is `false`.
        log_warn!("Authentication", "Inactive account", "failure"); // Log a warning.
        return Err(ApiError::unauthorized_error("Account is not activated")); // Return an unauthorized error specifically for inactive accounts.
    }

    log_info!("Authentication", "User authenticated", "success"); // Log success if all checks pass.
    Ok(user) // Return the authenticated `User` struct.
}

// Lines 131-166: Defines `authenticate_user`. It finds the user, verifies the password, checks activation status, and returns the `User` or an appropriate `ApiError`.

/// Generates an access and refresh token for a user.
/// Logs only error scenarios along with a summary metric update.
fn generate_auth_tokens(username: &str) -> Result<(String, String), ApiError> { // Defines a synchronous function to generate both tokens.
    let access_token = match generate_token(username, TOKEN_TYPE_ACCESS, None) { // Calls the utility function to generate an access token.
        Ok(token) => { // If successful:
            TOKEN_OPERATIONS.with_label_values(&["access", "generate"]).inc(); // Increment token generation metric for access tokens.
            token // Assign the generated token.
        },
        Err(_) => { // If generation fails:
            TOKEN_OPERATIONS.with_label_values(&["access", "error"]).inc(); // Increment token error metric for access tokens.
            log_error!("Authentication", "Access token generation failed", "failure"); // Log a critical error.
            return Err(ApiError::internal_error("Authentication error")); // Return an internal server error.
        }
    };

    let refresh_token = match generate_token(username, TOKEN_TYPE_REFRESH, None) { // Calls the utility function to generate a refresh token.
        Ok(token) => { // If successful:
            TOKEN_OPERATIONS.with_label_values(&["refresh", "generate"]).inc(); // Increment token generation metric for refresh tokens.
            token // Assign the generated token.
        },
        Err(_) => { // If generation fails:
            TOKEN_OPERATIONS.with_label_values(&["refresh", "error"]).inc(); // Increment token error metric for refresh tokens.
            log_error!("Authentication", "Refresh token generation failed", "failure"); // Log a critical error.
            return Err(ApiError::internal_error("Authentication error")); // Return an internal server error.
        }
    };

    Ok((access_token, refresh_token)) // Return the pair of generated tokens.
}

// Lines 168-197: Defines `generate_auth_tokens`. It calls the `generate_token` utility twice (once for access, once for refresh) and handles potential errors.

/// Handler for logout which revokes a token.
/// Logs errors and overall summary, relying on metrics for high-frequency events.
pub async fn logout_handler( // Defines the asynchronous function that handles POST requests to the logout endpoint.
    State(app_state): State<AppState>, // Extracts the shared application state.
    Json(logout_request): Json<TokenRequest>, // Extracts the JSON body containing the token to be revoked.
) -> impl IntoResponse { // Returns a type convertible to an HTTP response.
    let mut timer = RequestTimer::start("/auth/logout"); // Starts a timer for the logout request.
    REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "pending"]).inc(); // Increments total requests metric for logout, status "pending".

    let redis_client = match app_state.redis_client { // Attempts to get the Redis client from the application state.
        Some(client) => client, // If present, assign it.
        None => { // If the Redis client is not configured/available in the state:
            log_error!("Session Management", "Missing Redis client", "failure"); // Log a critical error.
            timer.set_status("500"); // Set timer status to 500.
            timer.complete("POST"); // Complete the timer immediately.
            REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "500"]).inc(); // Increment total requests metric with status 500.
            return ApiError::internal_error("Redis client not available").into_response(); // Return an internal server error response.
        },
    };

    // Calls `process_logout`, passing a clone of the Redis client and the token string.
    let result = process_logout(redis_client.clone(), logout_request.token).await;

    match &result { // Matches on the result of `process_logout`.
        Ok(_) => { // If logout (token revocation) succeeded:
            log_info!("Session Management", "Logout successful", "success"); // Log success.
            timer.set_status("200"); // Set timer status to 200.
            REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "200"]).inc(); // Increment total requests metric with status 200.
        },
        Err(_) => { // If logout (token revocation) failed:
            log_error!("Session Management", "Logout failed", "failure"); // Log an error.
            timer.set_status("500"); // Set timer status to 500.
            REQUESTS_TOTAL.with_label_values(&["/auth/logout", "POST", "500"]).inc(); // Increment total requests metric with status 500.
        },
    }

    timer.complete("POST"); // Stop the timer and record the duration.
    result.into_response() // Convert the result to an HTTP response.
}

// Lines 199-235: Defines the `logout_handler`. It gets the Redis client, calls `process_logout`, handles metrics/logging/timing based on the outcome, and returns the response.

/// Processes logout by validating and revoking the token.
/// Logs errors only when token revocation fails.
async fn process_logout( // Defines an async helper function for the core logout logic.
    redis_client: RedisClient, // Takes ownership of the Redis client.
    token: String,             // Takes ownership of the token string.
) -> Result<impl IntoResponse, ApiError> { // Returns a `Result` with a response or an `ApiError`.
    // Attempts to validate the token. This is optional for logout but useful for metrics/logging.
    let _user_info = match validate_token(&token, &redis_client).await {
        Ok(claims) => { // If valid:
            TOKEN_VALIDATIONS.with_label_values(&["valid"]).inc(); // Increment valid token metric.
            claims.sub // Extract the subject (username/ID).
        },
        Err(_) => { // If invalid/expired:
            TOKEN_VALIDATIONS.with_label_values(&["invalid"]).inc(); // Increment invalid token metric.
            "unknown".to_string() // Use "unknown" if validation fails.
        }
    };
    // Note: The `_user_info` is currently unused.

    match revoke_token(&token, &redis_client).await { // Calls the utility function to revoke the token (add it to a denylist in Redis).
        Ok(_) => { // If revocation succeeds:
            TOKEN_OPERATIONS.with_label_values(&["any", "revoke"]).inc(); // Increment token revocation metric.
            log_info!("Session Management", "Token revoked", "success"); // Log success.
        },
        Err(_) => { // If revocation fails:
            TOKEN_OPERATIONS.with_label_values(&["any", "revoke_error"]).inc(); // Increment token revocation error metric.
            log_error!("Session Management", "Token revocation failed", "failure"); // Log a critical error.
            return Err(ApiError::internal_error("Failed to logout")); // Return an internal server error.
        }
    }

    Ok(( // If revocation succeeds, return an OK response.
        StatusCode::OK, // Set status to 200 OK.
        axum::Json(json!({ // Create a simple JSON success message.
            "status": "success",
            "message": "Successfully logged out"
        }))
    ))
}

// Lines 237-270: Defines `process_logout`. It optionally validates the token for metrics, then attempts to revoke it using Redis, returning success or an error.

/// Handler for token refresh requests.
/// Logs overall outcome and critical errors while using metrics for each step.
pub async fn refresh_token_handler( // Defines the asynchronous function that handles POST requests to the refresh endpoint.
    State(app_state): State<AppState>, // Extracts the shared application state.
    Json(refresh_request): Json<TokenRequest>, // Extracts the JSON body containing the refresh token.
) -> impl IntoResponse { // Returns a type convertible to an HTTP response.
    let mut timer = RequestTimer::start("/auth/refresh"); // Starts a timer for the refresh request.
    REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", "pending"]).inc(); // Increments total requests metric for refresh, status "pending".

    let redis_client = match app_state.redis_client { // Attempts to get the Redis client from the application state.
        Some(client) => client, // If present, assign it.
        None => { // If the Redis client is not configured/available:
            log_error!("Token Management", "Missing Redis client", "failure"); // Log a critical error.
            timer.set_status("500"); // Set timer status to 500.
            timer.complete("POST"); // Complete the timer immediately.
            REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", "500"]).inc(); // Increment total requests metric with status 500.
            return ApiError::internal_error("Redis client not available").into_response(); // Return an internal server error response.
        },
    };

    // Calls `process_token_refresh`, passing a clone of the Redis client and the refresh token string.
    let result = process_token_refresh(redis_client.clone(), refresh_request.token).await;

    match &result { // Matches on the result of `process_token_refresh`.
        Ok(_) => { // If refresh succeeded:
            log_info!("Token Management", "Token refresh successful", "success"); // Log success.
            timer.set_status("200"); // Set timer status to 200.
            REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", "200"]).inc(); // Increment total requests metric with status 200.
        },
        Err(api_error) => { // If refresh failed:
            log_warn!("Token Management", "Token refresh failed", "failure"); // Log a warning.
            let status_code = match api_error.status.as_str() { // Determine the HTTP status code based on the error type.
                "unauthorized" => "401", // Invalid/expired token.
                "bad_request" => "400",  // Wrong token type.
                _ => "500",             // Internal errors (e.g., token generation failure).
            };
            timer.set_status(status_code); // Set the determined status code on the timer.
            REQUESTS_TOTAL.with_label_values(&["/auth/refresh", "POST", status_code]).inc(); // Increment total requests metric with the error status code.
        },
    }

    timer.complete("POST"); // Stop the timer and record the duration.
    result.into_response() // Convert the result to an HTTP response.
}

// Lines 272-312: Defines the `refresh_token_handler`. It gets the Redis client, calls `process_token_refresh`, handles metrics/logging/timing based on the outcome, and returns the response.

/// Processes token refresh by verifying and revoking the old token.
/// Generates new tokens and logs only key failures or overall success.
async fn process_token_refresh( // Defines an async helper function for the core token refresh logic.
    redis_client: RedisClient, // Takes ownership of the Redis client.
    token: String,             // Takes ownership of the refresh token string.
) -> Result<impl IntoResponse, ApiError> { // Returns a `Result` with a response or an `ApiError`.
    let claims = match validate_token(&token, &redis_client).await { // Validates the provided refresh token using the JWT utility.
        Ok(claims) => { // If valid:
            TOKEN_VALIDATIONS.with_label_values(&["valid"]).inc(); // Increment valid token metric.
            log_info!("Token Management", "Refresh token validated", "success"); // Log success.
            claims // Assign the decoded claims.
        },
        Err(_) => { // If invalid/expired:
            TOKEN_VALIDATIONS.with_label_values(&["invalid"]).inc(); // Increment invalid token metric.
            log_warn!("Token Management", "Refresh token validation failed", "failure"); // Log a warning.
            return Err(ApiError::unauthorized_error("Invalid or expired token")); // Return an unauthorized error.
        }
    };

    if claims.token_type != TOKEN_TYPE_REFRESH { // Checks if the validated token's type is actually "refresh".
        TOKEN_VALIDATIONS.with_label_values(&["wrong_type"]).inc(); // Increment wrong token type metric.
        log_warn!("Token Management", "Incorrect token type", "failure"); // Log a warning.
        return Err(ApiError::bad_request_error("Not a refresh token")); // Return a bad request error.
    }

    log_info!("Token Management", "Token type verified", "success"); // Log success if type is correct.

    let new_access_token = match generate_token(&claims.sub, TOKEN_TYPE_ACCESS, None) { // Generates a new access token for the user identified in the claims (`claims.sub`).
        Ok(token) => { // If successful:
            TOKEN_OPERATIONS.with_label_values(&["access", "issue"]).inc(); // Increment access token issue metric.
            token // Assign the new access token.
        },
        Err(_) => { // If generation fails:
            TOKEN_OPERATIONS.with_label_values(&["access", "error"]).inc(); // Increment access token error metric.
            log_error!("Token Management", "Access token generation failed", "failure"); // Log a critical error.
            return Err(ApiError::internal_error("Token refresh failed")); // Return an internal server error.
        }
    };

    match revoke_token(&token, &redis_client).await { // Attempts to revoke the *old* refresh token that was just used.
        Ok(_) => { // If revocation succeeds:
            TOKEN_OPERATIONS.with_label_values(&["refresh", "revoke"]).inc(); // Increment refresh token revoke metric.
            log_info!("Token Management", "Old refresh token revoked", "success"); // Log success.
        },
        Err(_) => { // If revocation fails:
            TOKEN_OPERATIONS.with_label_values(&["refresh", "revoke_error"]).inc(); // Increment refresh token revoke error metric.
            // Log a warning but *do not* return an error. The user still gets new tokens.
            log_warn!("Token Management", "Failed to revoke old refresh token", "failure");
        }
    }

    let new_refresh_token = match generate_token(&claims.sub, TOKEN_TYPE_REFRESH, None) { // Generates a *new* refresh token for the user.
        Ok(token) => { // If successful:
            TOKEN_OPERATIONS.with_label_values(&["refresh", "issue"]).inc(); // Increment refresh token issue metric.
            token // Assign the new refresh token.
        },
        Err(_) => { // If generation fails:
            TOKEN_OPERATIONS.with_label_values(&["refresh", "error"]).inc(); // Increment refresh token error metric.
            log_error!("Token Management", "Refresh token generation failed", "failure"); // Log a critical error.
            return Err(ApiError::internal_error("Token refresh failed")); // Return an internal server error.
        }
    };

    Ok(( // If everything succeeds (or revocation warning was ignored), return an OK response with the new tokens.
        StatusCode::OK, // Set status to 200 OK.
        axum::Json(json!({ // Create the JSON response body.
            "status": "success",
            "message": "Tokens refreshed successfully",
            "data": { // Nest the new tokens under "data".
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer"
            }
        }))
    ))
}
// Lines 314-392: Defines `process_token_refresh`. It validates the old refresh token, checks its type, generates a new access token, revokes the old refresh token, generates a new refresh token, and returns the new tokens in the response.