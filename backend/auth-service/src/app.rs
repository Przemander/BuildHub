use axum::{routing::{get, post}, Extension, Router};
use tower_http::cors::{CorsLayer, Any};
use redis::Client;

use crate::config::database::DbPool;
use crate::handlers::register::register_handler;
use crate::handlers::login::{login_handler, logout_handler, refresh_token_handler};

pub async fn build_app(pool: DbPool, redis_client: Option<Client>) -> Router {
    let mut app = Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .route("/auth/register", post(register_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/auth/refresh", post(refresh_token_handler))
        .layer(Extension(pool))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers(Any),
        );
    
    // Add Redis client to the app if available
    if let Some(client) = redis_client {
        app = app.layer(Extension(client));
    } else {
        log::warn!("Redis client not available. Token functionality will be limited.");
    }
    
    app
}