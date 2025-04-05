//! Application router and middleware configuration.
//!
//! This module is responsible for setting up the application's routes,
//! middleware stack, and overall API structure.

use std::sync::Arc;
use axum::{
    routing::{get, post}, 
    Extension, 
    Router,
    middleware
};
use tower_http::cors::{CorsLayer, Any};
use redis::Client as RedisClient;

use crate::config::database::DbPool;
use crate::utils::email::EmailConfig;
use crate::middleware::jwt_auth::jwt_auth_middleware;

// Import existing handlers only
use crate::handlers::register::register_handler;
use crate::handlers::login::{login_handler, logout_handler, refresh_token_handler};
use crate::handlers::activation::activate_account_handler;

/// Builds the application router with all routes and middleware.
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `redis_client` - Optional Redis client
/// * `email_config` - Optional email configuration
///
/// # Returns
/// A configured Router ready to be served
pub async fn build_app(
    pool: DbPool, 
    redis_client: Option<RedisClient>,
    email_config: Option<EmailConfig>
) -> Router {
    // Convert Redis client to Arc for sharing across handlers if available
    let redis_client_arc = redis_client.map(Arc::new);
    
    // Set up public routes (no authentication required)
    let public_routes = Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .route("/auth/register", post(register_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/refresh", post(refresh_token_handler))
        .route("/auth/activate", get(activate_account_handler));
    
    // Set up protected routes (require authentication)
    let protected_routes = Router::new()
        .route("/auth/logout", post(logout_handler))
        // Add the JWT authentication middleware to all protected routes
        .route_layer(middleware::from_fn_with_state(
            redis_client_arc.as_ref().cloned(),
            jwt_auth_middleware
        ));
    
    // Merge routes and add shared layers
    let mut app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
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
                .allow_headers(Any)
                .allow_credentials(true)
        )
        // Add Redis client to the app state if available
        .with_state(redis_client_arc.clone());
    
    // Add Redis client to the app as Extension (for compatibility with existing code)
    if let Some(client) = redis_client_arc.clone() {
        app = app.layer(Extension(client));
        log::info!("Redis client added to application");
    } else {
        log::warn!("Redis client not available. Token functionality will be limited.");
    }
    
    // Add Email configuration to the app if available
    if let Some(config) = email_config {
        app = app.layer(Extension(config));
        log::info!("Email configuration added to application");
    } else {
        log::warn!("Email configuration not available. Email functionality will be disabled.");
    }
    
    app
}