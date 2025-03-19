use axum::{Router, routing::get};
use tower_http::cors::{CorsLayer, Any};

use crate::config::database::DbPool;


pub async fn build_app(pool: DbPool) -> Router {
    Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers(Any),
        )
}