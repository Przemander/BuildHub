use axum::{routing::{get, post}, Extension, Router};
use tower_http::cors::{CorsLayer, Any};
use redis::Client as RedisClient;

use crate::config::database::DbPool;
use crate::utils::email::EmailConfig;
use crate::handlers::register::register_handler;
use crate::handlers::login::{login_handler, logout_handler, refresh_token_handler};
use crate::handlers::activation::activate_account_handler;

pub async fn build_app(
    pool: DbPool, 
    redis_client: Option<RedisClient>,
    email_config: Option<EmailConfig>
) -> Router {
    let mut app = Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .route("/auth/register", post(register_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/auth/refresh", post(refresh_token_handler))
        .route("/auth/activate", get(activate_account_handler))
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
    
    // Add Email configuration to the app if available
    if let Some(config) = email_config {
        app = app.layer(Extension(config));
    } else {
        log::warn!("Email configuration not available. Email functionality will be disabled.");
    }
    
    app
}