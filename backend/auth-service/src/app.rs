use axum::{routing::{get, post}, Extension, Router};
use tower_http::cors::{CorsLayer, Any};
use redis::Client;

use crate::config::database::DbPool;
use crate::handlers::register::register_handler;

pub async fn build_app(pool: DbPool, redis_client: Option<Client>) -> Router {
    let mut app = Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .route("/auth/register", post(register_handler))
        .layer(Extension(pool))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers(Any),
        );
    
    // Add Redis client to the app if available
    if let Some(client) = redis_client {
        app = app.layer(Extension(client));
    }
    
    app
}