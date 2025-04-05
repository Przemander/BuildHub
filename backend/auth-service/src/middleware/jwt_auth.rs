use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use crate::utils::jwt::{validate_token, decode_token, TokenClaims, TOKEN_TYPE_ACCESS};
use crate::utils::errors::ApiError;
use log::{debug, warn};
use redis::Client as RedisClient;
use std::sync::Arc;

/// JWT Authentication Middleware
///
/// This middleware validates the JWT token in the Authorization header
/// and extracts user information for protected routes.
///
/// It performs the following checks:
/// 1. Presence of Authorization header
/// 2. Valid Bearer token format
/// 3. JWT signature validation
/// 4. Token expiration check
/// 5. Token type verification
/// 6. Token blacklist check (if Redis is available)
pub async fn jwt_auth_middleware<B>(
    State(redis_client): State<Option<Arc<RedisClient>>>,
    mut req: Request<B>,
    next: Next<B>,
) -> Response
where
    B: Send + 'static,
{
    // Extract Authorization header
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => header,
        None => {
            debug!("No Authorization header found");
            return ApiError::unauthorized_error("Authorization header missing")
                .into_response();
        }
    };

    // Parse the Authorization header to string
    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            debug!("Invalid Authorization header format");
            return ApiError::unauthorized_error("Invalid Authorization header format")
                .into_response();
        }
    };

    // Check if it's a Bearer token
    if !auth_str.starts_with("Bearer ") {
        debug!("Invalid Authorization scheme");
        return ApiError::unauthorized_error("Bearer authentication required")
            .into_response();
    }

    // Extract the token by removing "Bearer " prefix
    let token = &auth_str[7..];
    if token.is_empty() {
        debug!("Empty token provided");
        return ApiError::unauthorized_error("Empty token")
            .into_response();
    }

    // Authenticate the token
    let claims = match authenticate_token(token, redis_client.as_deref()).await {
        Ok(claims) => claims,
        Err(error) => return error.into_response(),
    };
    
    debug!("Authentication successful for user: {}", claims.sub);

    // Add both the complete claims object and just the username for convenience
    req.extensions_mut().insert(claims.clone());
    req.extensions_mut().insert(claims.sub);

    // Continue to the next middleware or handler
    next.run(req).await
}

/// Helper function to authenticate a token consistently
async fn authenticate_token(
    token: &str,
    redis_client: Option<&RedisClient>,
) -> Result<TokenClaims, ApiError> {
    // If Redis is available, use complete validation including blacklist check
    if let Some(redis) = redis_client {
        validate_token(token, redis).await
    } else {
        // Without Redis - use basic validation without blacklist check
        let claims = decode_token(token)?;
        
        // Additional validation for token type
        if claims.token_type != TOKEN_TYPE_ACCESS {
            debug!("Invalid token type: {}", claims.token_type);
            return Err(ApiError::unauthorized_error("Invalid token type"));
        }
        
        // Manual extra checks that validate_token would normally do
        let now = chrono::Utc::now().timestamp() as usize;
        
        // Check if token was issued in the future (clock skew)
        if claims.iat > now + 60 { // Allow 1 minute of clock skew
            warn!("Token validation failed: token issued in the future (possible clock skew)");
            return Err(ApiError::unauthorized_error("Invalid token issue time"));
        }
        
        Ok(claims)
    }
}