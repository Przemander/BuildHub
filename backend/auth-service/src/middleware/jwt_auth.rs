//! # Enterprise JWT Authentication Middleware
//!
//! Production-grade JWT authentication middleware with comprehensive security features:
//!
//! ## 🛡️ **Security Features**
//! - **Token validation** with signature verification and expiration checks
//! - **Token revocation** support via Redis blocklist integration
//! - **Bearer token extraction** with proper format validation
//! - **Fail-secure design** - blocks access when Redis is unavailable
//! - **Security headers** and structured error responses
//!
//! ## 📊 **Enterprise Observability**
//! - **OpenTelemetry integration** with detailed span attributes
//! - **Comprehensive metrics** for authentication monitoring
//! - **Error classification** for security incident analysis
//! - **Performance timing** for latency optimization
//! - **Privacy-aware logging** (no sensitive token data)
//!
//! ## 🚀 **Production Features**
//! - **Non-blocking operations** with proper async/await patterns
//! - **Graceful error handling** with structured API responses
//! - **Memory efficient** with minimal allocations in hot path
//! - **Integration ready** with existing middleware stack
//!
//! ## Usage
//!
//! ```rust
//! use axum::{routing::get, Router, middleware::from_fn_with_state};
//! use crate::middleware::jwt_auth::jwt_auth_middleware;
//!
//! // Apply to protected routes
//! Router::new()
//!     .route("/protected", get(protected_handler))
//!     .layer(from_fn_with_state(app_state, jwt_auth_middleware))
//! ```

use crate::app::AppState;
use crate::utils::error_new::ApiError;
use crate::utils::jwt;
use crate::utils::log_new::Log;
use crate::utils::telemetry::{http_middleware_span, business_operation_span, SpanExt};
use crate::metricss::middleware_metrics::jwt_auth;
use axum::{extract::State, http::Request, middleware::Next, response::IntoResponse};
use std::sync::Arc;
use std::time::Instant;
use tracing::Instrument;

// =============================================================================
// MIDDLEWARE IMPLEMENTATION
// =============================================================================

/// Enterprise JWT authentication middleware with comprehensive security validation.
///
/// This middleware provides robust authentication for protected endpoints by:
///
/// 1. **Token Extraction** - Safely extracts Bearer tokens from Authorization headers
/// 2. **Format Validation** - Validates JWT structure and encoding
/// 3. **Signature Verification** - Cryptographically validates token authenticity
/// 4. **Expiration Check** - Ensures tokens haven't expired
/// 5. **Revocation Check** - Validates against Redis blocklist
/// 6. **Security Logging** - Records authentication events for audit trails
///
/// ## Security Design
///
/// - **Fail-secure policy** - Blocks access when Redis is unavailable (unlike rate limiting)
/// - **Privacy-preserving logs** - Never logs actual token content
/// - **Structured errors** - Returns consistent API error responses
/// - **Comprehensive telemetry** - Full observability for security monitoring
///
/// ## Error Handling
///
/// - **401 Unauthorized** - Invalid, expired, or missing tokens
/// - **503 Service Unavailable** - Redis dependency failure
/// - **Structured responses** - JSON format with error details
///
/// ## Performance
///
/// - **Async operations** - Non-blocking Redis operations
/// - **Efficient validation** - Minimal CPU overhead per request
/// - **Memory conscious** - Reuses connection pools and minimal allocations
pub async fn jwt_auth_middleware<B>(
    State(app_state): State<Arc<AppState>>,
    req: Request<B>,
    next: Next<B>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    
    // Create comprehensive middleware span for request tracing
    let span = http_middleware_span("jwt_authentication");
    span.record("http.method", &req.method().to_string());
    span.record("http.path", &req.uri().path());
    span.record("middleware.type", &"authentication");
    span.record("auth.method", &"jwt_bearer");
    
    let span_clone = span.clone();
    
    async move {
        // ─────────────────────────────────────────────────────────────────
        // PHASE 1: Bearer Token Extraction
        // ─────────────────────────────────────────────────────────────────
        let extraction_span = business_operation_span("bearer_token_extraction");
        extraction_span.record("operation", &"extract_authorization_header");
        
        let token = match extract_bearer_token(&req) {
            Some(token) => {
                extraction_span.record("result", &"success");
                extraction_span.record("token.present", &true);
                extraction_span.record("token.length", &token.len());
                
                // Record token metadata for observability (never the actual token)
                span.record("auth.token_present", &true);
                span.record("auth.token_length", &token.len());
                
                Log::event(
                    "DEBUG",
                    "JWTAuth",
                    &format!("Bearer token extracted successfully (length: {})", token.len()),
                    "token_extraction_success",
                    "jwt_auth_middleware"
                );
                
                token
            }
            None => {
                extraction_span.record("result", &"failure");
                extraction_span.record("token.present", &false);
                extraction_span.record("failure.reason", &"missing_or_invalid_header");
                
                span.record("auth.result", &"failure");
                span.record("auth.failure_reason", &"missing_bearer_token");
                span.record("auth.token_present", &false);
                span.record("http.status_code", &401);
                
                Log::event(
                    "WARN",
                    "JWTAuth",
                    "Authentication failed - missing or invalid Authorization header",
                    "missing_auth_header",
                    "jwt_auth_middleware"
                );
                
                // Record authentication failure metrics
                jwt_auth::record_unauthorized("protected", "missing_header");
                
                return ApiError::unauthorized("Missing or invalid Authorization header")
                    .into_response();
            }
        };

        // ─────────────────────────────────────────────────────────────────
        // PHASE 2: Redis Dependency Check
        // ─────────────────────────────────────────────────────────────────
        let redis_client = match &app_state.redis_client {
            Some(redis) => {
                span.record("redis.available", &true);
                span.record("dependencies.redis", &"available");
                redis
            }
            None => {
                span.record("auth.result", &"failure");
                span.record("auth.failure_reason", &"redis_dependency_unavailable");
                span.record("redis.available", &false);
                span.record("dependencies.redis", &"unavailable");
                span.record("http.status_code", &503);
                
                Log::event(
                    "ERROR",
                    "JWTAuth",
                    "Authentication service failure - Redis dependency unavailable",
                    "redis_dependency_failure",
                    "jwt_auth_middleware"
                );
                
                // Record service dependency failure
                jwt_auth::record_service_unavailable("protected");
                
                return ApiError::service_unavailable(
                    "Authentication service temporarily unavailable"
                ).into_response();
            }
        };

        // ─────────────────────────────────────────────────────────────────
        // PHASE 3: JWT Token Validation
        // ─────────────────────────────────────────────────────────────────
        let validation_span = business_operation_span("jwt_token_validation");
        validation_span.record("operation", &"validate_jwt_token");
        validation_span.record("token.length", &token.len());
        validation_span.record("validation.includes_signature", &true);
        validation_span.record("validation.includes_expiration", &true);
        validation_span.record("validation.includes_revocation_check", &true);
        
        let validation_span_clone = validation_span.clone();

        let validation_result = async {
            match jwt::validate_token(token, redis_client).await {
                Ok(claims) => {
                    validation_span.record("validation.result", &"success");
                    validation_span.record("user.id", &claims.sub);
                    validation_span.record("token.type", &claims.token_type);
                    validation_span.record("token.exp", &claims.exp);
                    validation_span.record("token.issued_at", &claims.iat);
                    
                    Log::event(
                        "INFO",
                        "JWTAuth",
                        &format!("JWT validation successful for user: {}", claims.sub),
                        "token_validation_success",
                        "jwt_auth_middleware"
                    );
                    
                    Ok(claims)
                }
                Err(validation_error) => {
                    validation_span.record("validation.result", &"failure");
                    validation_span.record("validation.error", &validation_error.to_string());
                    validation_span.record_error(&validation_error);
                    
                    // Classify errors for better monitoring and security analysis
                    let error_classification = classify_jwt_error(&validation_error);
                    validation_span.record("validation.error_type", &error_classification);
                    
                    Log::event(
                        "WARN",
                        "JWTAuth",
                        &format!("JWT validation failed ({}): {}", error_classification, validation_error),
                        "token_validation_failure",
                        "jwt_auth_middleware"
                    );
                    
                    Err((validation_error, error_classification))
                }
            }
        }
        .instrument(validation_span_clone)
        .await;

        // ─────────────────────────────────────────────────────────────────
        // PHASE 4: Result Processing & Response Generation
        // ─────────────────────────────────────────────────────────────────
        match validation_result {
            Ok(claims) => {
                // Record successful authentication with user context
                span.record("auth.result", &"success");
                span.record("user.id", &claims.sub);
                span.record("token.type", &claims.token_type);
                span.record("auth.validated_at", &chrono::Utc::now().timestamp());
                span.record("http.status_code", &200);
                
                Log::event(
                    "INFO",
                    "JWTAuth",
                    &format!("Authentication successful for user: {}", claims.sub),
                    "authentication_success",
                    "jwt_auth_middleware"
                );
                
                // Record successful authentication metrics
                jwt_auth::record_success("protected");
                
                // Forward to next middleware/handler with authenticated context
                let response = next.run(req).await;
                
                // Record final processing metrics
                let total_duration = start_time.elapsed();
                span.record("duration_ms", &total_duration.as_millis());
                span.record("processing.completed", &true);
                
                response
            }
            Err((validation_error, error_classification)) => {
                // Record comprehensive failure context
                span.record("auth.result", &"failure");
                span.record("auth.failure_reason", &"token_validation_failed");
                span.record("auth.failure_type", &error_classification);
                span.record("auth.error_message", &validation_error.to_string());
                span.record("http.status_code", &401);
                span.record_error(&validation_error);
                
                Log::event(
                    "WARN",
                    "JWTAuth",
                    &format!("Authentication failed ({}): {}", error_classification, validation_error),
                    "authentication_failure",
                    "jwt_auth_middleware"
                );
                
                // Record detailed failure metrics for security monitoring
                jwt_auth::record_unauthorized("protected", &error_classification);
                
                // Generate structured error response based on error type
                let api_error = match error_classification {
                    "token_expired" => ApiError::unauthorized("Token has expired"),
                    "invalid_signature" => ApiError::unauthorized("Invalid token signature"),
                    "token_revoked" => ApiError::unauthorized("Token has been revoked"),
                    "malformed_token" => ApiError::unauthorized("Invalid token format"),
                    _ => ApiError::unauthorized("Authentication failed"),
                };
                
                api_error.into_response()
            }
        }
    }
    .instrument(span_clone)
    .await
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/// Safely extracts a Bearer token from the Authorization header.
///
/// This function implements secure header parsing with comprehensive validation:
/// - Checks for Authorization header presence
/// - Validates UTF-8 encoding of header values
/// - Ensures proper "Bearer " prefix format
/// - Trims whitespace and validates token content
/// - Handles edge cases gracefully (empty tokens, malformed headers)
///
/// ## Security Considerations
///
/// - **Input validation** - Rejects malformed authorization headers
/// - **Encoding safety** - Handles non-UTF8 header values gracefully
/// - **Format enforcement** - Strict Bearer token format requirement
/// - **Memory safety** - No buffer overflows or panics on invalid input
///
/// # Arguments
///
/// * `req` - HTTP request containing headers to examine
///
/// # Returns
///
/// * `Some(token)` - Successfully extracted and validated JWT token
/// * `None` - Missing header, invalid format, encoding issues, or empty token
fn extract_bearer_token<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|header_value| {
            // Safely convert header value to UTF-8 string
            header_value.to_str().ok()
        })
        .and_then(|auth_header| {
            // Validate Bearer token format and extract token portion
            if auth_header.starts_with("Bearer ") {
                let token = auth_header.trim_start_matches("Bearer ").trim();
                if !token.is_empty() {
                    Some(token)
                } else {
                    None // Empty token after Bearer prefix
                }
            } else {
                None // Not a Bearer token format
            }
        })
}

/// Classifies JWT validation errors for enhanced security monitoring.
///
/// This function categorizes JWT validation failures into specific types
/// to enable better security analysis, alerting, and incident response.
/// The classification helps distinguish between different attack vectors
/// and operational issues.
///
/// ## Error Classifications
///
/// - **token_expired** - Token past its expiration time
/// - **invalid_signature** - Cryptographic signature validation failed
/// - **token_revoked** - Token found in Redis blocklist
/// - **malformed_token** - Invalid JWT format or encoding
/// - **validation_error** - Other validation failures
///
/// # Arguments
///
/// * `error` - JWT validation error to classify
///
/// # Returns
///
/// * String slice containing the error classification
fn classify_jwt_error(error: &dyn std::error::Error) -> &'static str {
    let error_string = error.to_string().to_lowercase();
    
    if error_string.contains("expired") {
        "token_expired"
    } else if error_string.contains("signature") || error_string.contains("verify") {
        "invalid_signature"
    } else if error_string.contains("revoked") || error_string.contains("blocked") || error_string.contains("blacklist") {
        "token_revoked"
    } else if error_string.contains("format") || error_string.contains("decode") || error_string.contains("malformed") {
        "malformed_token"
    } else {
        "validation_error"
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::config::database::{init_pool, run_migrations};
    use crate::utils::jwt::{self, TOKEN_TYPE_ACCESS};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware::from_fn_with_state,
        routing::get,
        Router,
    };
    use chrono::Duration;
    use redis::Client;
    use std::env;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "Protected content"
    }

    fn create_test_state(redis_available: bool) -> Arc<AppState> {
        // Set up test environment variables
        env::set_var("JWT_SECRET", "test-secret-key-minimum-32-characters-for-security-compliance");
        env::set_var("DATABASE_URL", ":memory:");
        
        // Initialize in-memory database
        let pool = init_pool();
        run_migrations(&pool).expect("Failed to run test migrations");
        
        // Create Redis client if requested
        let redis_client = if redis_available {
            Some(Client::open("redis://127.0.0.1/").expect("Failed to create test Redis client"))
        } else {
            None
        };
        
        Arc::new(AppState {
            pool,
            redis_client,
            email_config: None,
        })
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let state = create_test_state(true);
        let app = Router::new()
            .route("/protected", get(test_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let response = app
            .oneshot(Request::builder().uri("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_bearer_format() {
        let state = create_test_state(true);
        let app = Router::new()
            .route("/protected", get(test_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let request = Request::builder()
            .uri("/protected")
            .header("authorization", "Basic dXNlcjpwYXNz") // Basic auth instead of Bearer
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_valid_token_success() {
        let state = create_test_state(true);
        let token = jwt::generate_token("test-user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .expect("Failed to generate test token");

        let app = Router::new()
            .route("/protected", get(test_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let request = Request::builder()
            .uri("/protected")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_expired_token() {
        let state = create_test_state(true);
        let expired_token = jwt::generate_token("test-user", TOKEN_TYPE_ACCESS, Some(Duration::seconds(-1)))
            .expect("Failed to generate expired token");

        let app = Router::new()
            .route("/protected", get(test_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let request = Request::builder()
            .uri("/protected")
            .header("authorization", format!("Bearer {}", expired_token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_redis_unavailable_service_error() {
        let state = create_test_state(false); // No Redis client
        let token = jwt::generate_token("test-user", TOKEN_TYPE_ACCESS, Some(Duration::hours(1)))
            .expect("Failed to generate test token");

        let app = Router::new()
            .route("/protected", get(test_handler))
            .layer(from_fn_with_state(state, jwt_auth_middleware));

        let request = Request::builder()
            .uri("/protected")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_extract_bearer_token_edge_cases() {
        // Valid Bearer token
        let req = Request::builder()
            .header("authorization", "Bearer valid-jwt-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("valid-jwt-token"));

        // Bearer token with whitespace
        let req = Request::builder()
            .header("authorization", "Bearer  token-with-spaces  ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("token-with-spaces"));

        // Missing authorization header
        let req = Request::builder()
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Wrong auth scheme
        let req = Request::builder()
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Empty Bearer token
        let req = Request::builder()
            .header("authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);

        // Bearer with only whitespace
        let req = Request::builder()
            .header("authorization", "Bearer   ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);
    }

    #[test]
    fn test_jwt_error_classification() {
        use std::fmt;

        // Create a test error type
        #[derive(Debug)]
        struct TestError(String);
        
        impl fmt::Display for TestError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        
        impl std::error::Error for TestError {}

        // Test expired token classification
        let expired_error = TestError("Token has expired".to_string());
        assert_eq!(classify_jwt_error(&expired_error), "token_expired");

        // Test signature error classification
        let signature_error = TestError("Invalid signature verification failed".to_string());
        assert_eq!(classify_jwt_error(&signature_error), "invalid_signature");

        // Test revoked token classification
        let revoked_error = TestError("Token has been revoked".to_string());
        assert_eq!(classify_jwt_error(&revoked_error), "token_revoked");

        // Test malformed token classification
        let format_error = TestError("Malformed JWT format".to_string());
        assert_eq!(classify_jwt_error(&format_error), "malformed_token");

        // Test generic validation error
        let generic_error = TestError("Unknown validation failure".to_string());
        assert_eq!(classify_jwt_error(&generic_error), "validation_error");
    }
}