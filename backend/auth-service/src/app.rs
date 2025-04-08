//// filepath: /home/przemander/projects/BuildHub/backend/auth-service/src/app.rs
use axum::{
    extract::State,
    http::{Method, header::HeaderName, StatusCode},
    routing::{get, post},
    Router, response::IntoResponse,
};
use tower_http::cors::CorsLayer;
use redis::Client as RedisClient;
use std::sync::Arc;
use crate::{
    config::database::DbPool,
    handlers::{
        activation::activate_account_handler,
        login::{login_handler, logout_handler, refresh_token_handler},
        register::register_handler,
    },
    utils::{
        email::EmailConfig,
        metric::Metrics,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub redis_client: Option<RedisClient>,
    pub email_config: Option<EmailConfig>,
    pub metrics: Arc<Metrics>,
}

pub async fn build_app(
    pool: DbPool,
    redis_client: Option<RedisClient>,
    email_config: Option<EmailConfig>,
) -> Router {
    // Initialize metrics
    let metrics = Arc::new(Metrics::init());
    
    let state = AppState {
        pool,
        redis_client,
        email_config,
        metrics,
    };

    let public_routes = Router::new()
        .route("/", get(|| async { "🚀 BuildHub Authorization Service is running" }))
        .route("/auth/register", post(register_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/refresh", post(refresh_token_handler))
        .route("/auth/activate", get(activate_account_handler))
        .route("/metrics", get(metrics_handler)); // Add metrics endpoint

    let protected_routes = Router::new()
        .route("/auth/logout", post(logout_handler));

    let allowed_headers = vec![
        axum::http::header::CONTENT_TYPE,
        axum::http::header::AUTHORIZATION,
        axum::http::header::ACCEPT,
        HeaderName::from_static("x-requested-with"),
    ];

    let allowed_methods = vec![
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
    ];

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "http://localhost:3000".parse().unwrap(),
                    "http://127.0.0.1:3000".parse().unwrap(),
                ])
                .allow_methods(allowed_methods)
                .allow_headers(allowed_headers)
                .allow_credentials(true),
        )
}

/// Handler for the metrics endpoint that returns Prometheus metrics
async fn metrics_handler(
    State(app_state): State<AppState>
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        app_state.metrics.render()
    )
}