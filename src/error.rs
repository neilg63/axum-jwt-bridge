use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    status: u16,
}

/// Errors from JWT authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingHeader,

    #[error("Invalid authorization header format")]
    InvalidHeaderFormat,

    #[error("Invalid bearer token format")]
    InvalidBearerFormat,

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Token has expired")]
    TokenExpired,

    #[error("Token is not yet valid")]
    TokenNotYetValid,

    #[error("Invalid issuer")]
    InvalidIssuer,

    #[error("Invalid audience")]
    InvalidAudience,

    #[error("Invalid provider hash {0}")]
    InvalidProvider(String),

    #[error("Invalid subject: {0}")]
    InvalidSubject(String),

    #[error("Auth not configured: {0}")]
    ConfigError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match &self {
            AuthError::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        };

        let body = ErrorBody {
            error: self.to_string(),
            status: status.as_u16(),
        };

        (status, axum::Json(body)).into_response()
    }
}
