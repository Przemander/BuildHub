//! JWT authentication middleware for BuildHub.
//!
//! This middleware validates JWT tokens on protected routes using the shared JWT utility functions.
//! It checks for token presence, validity, and revocation (via Redis blocklist).
//! On failure, it returns a 401 Unauthorized response and logs the event.

use crate::app::AppState;
use crate::utils::errors::ApiError;
use crate::utils::jwt;
use crate::log_info;
use crate::log_warn;
use crate::log_error;
use axum::{extract::State, http::Request, middleware::Next, response::IntoResponse};
use std::sync::Arc;

/// JWT authentication middleware for protected routes.
///
/// Expects the `Authorization: Bearer <token>` header.
/// On success, passes the request to the next handler.
/// On failure, returns 401 Unauthorized and logs the event.
pub async fn jwt_auth_middleware<B>(
    State(app_state): State<Arc<AppState>>,
    req: Request<B>,
    next: Next<B>,
) -> impl IntoResponse {
    // Extract the Authorization header
    let token = match req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
    {
        Some(header) if header.starts_with("Bearer ") => {
            header.trim_start_matches("Bearer ").trim()
        }
        _ => {
            log_warn!("JWTAuth", "Missing or invalid Authorization header", "unauthorized");
            return ApiError::unauthorized("Missing or invalid Authorization header")
                .into_response();
        }
    };

    // Validate the token using the shared JWT utility
    let redis_client = match &app_state.redis_client {
        Some(redis) => redis,
        None => {
            log_error!("JWTAuth", "Redis unavailable for token validation", "system_error");
            return ApiError::internal("Redis unavailable for token validation").into_response();
        }
    };

    match jwt::validate_token(token, redis_client).await {
        Ok(claims) => {
            log_info!("JWTAuth", &format!("Token valid for user {}", claims.sub), "success");
            next.run(req).await
        }
        Err(err) => {
            log_warn!(
                "JWTAuth",
                &format!("Invalid or expired token: {}", err),
                "unauthorized"
            );
            ApiError::unauthorized(&format!("Invalid or expired token: {}", err)).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::config::database::{init_pool, run_migrations};
    // bring in the token helpers and the ACCESS constant
    use crate::utils::jwt::{self, TOKEN_TYPE_ACCESS};
    // chrono is already a project dependency
    use chrono::Duration;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
        middleware::from_fn_with_state,
    };
    use redis::Client;
    use std::sync::Arc;
    use std::env;
    use tower::ServiceExt;

    // a dummy handler that returns "OK"
    async fn ok_handler() -> &'static str {
        "OK"
    }

    // build AppState with optional redis URL, using an in-memory SQLite DB for tests
    fn make_state(redis_url: Option<&str>) -> Arc<AppState> {
        // 0) configure a JWT secret for token generation/validation
        env::set_var("JWT_SECRET", "test-secret");
        // 1) force SQLite to use in-memory
        env::set_var("DATABASE_URL", ":memory:");
        // 2) init pool and run migrations
        let pool = init_pool();
        run_migrations(&pool).expect("Failed to run migrations on in-memory DB");
        // 3) optional redis client
        let redis_client = redis_url.map(Client::open).transpose().unwrap();
        Arc::new(AppState { pool, redis_client, email_config: None })
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let state = make_state(Some("redis://127.0.0.1/"));
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_calls_next() {
        let state = make_state(Some("redis://127.0.0.1/"));
        // use the real TOKEN_TYPE_ACCESS and chrono::Duration
        let token = jwt::generate_token("test-user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1))).unwrap();

        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(state.clone(), jwt_auth_middleware));

        let req = Request::builder()
            .uri("/")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(resp.into_response().into_body())
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK");
    }
}