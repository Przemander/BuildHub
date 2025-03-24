use axum::{routing::{get, post}, Extension, Router};
use tower_http::cors::{CorsLayer, Any};

use crate::config::database::DbPool;
use crate::handlers::register::register_handler;


pub async fn build_app(pool: DbPool) -> Router {
    Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .route("/auth/register", post(register_handler))
        .layer(Extension(pool))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers(Any),
        )
}