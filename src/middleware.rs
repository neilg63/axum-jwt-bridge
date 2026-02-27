use axum::extract::FromRequestParts;
use http::request::Parts;
use serde::de::DeserializeOwned;

use crate::claims::{Claims, NoExtraClaims};
use crate::config::{JwtConfig, MultiJwtConfig};
use crate::error::AuthError;
use crate::token::{verify_jwt_any_as, verify_jwt_as};

/// Axum extractor: validates the JWT and provides the user ID.
///
/// Generic over extra claims `E`, defaulting to [`NoExtraClaims`]
/// which silently ignores unknown fields.
///
/// ## Default (no extra claims)
///
/// ```rust,no_run
/// use axum::{routing::get, Extension, Router};
/// use axum_jwt_bridge::{AuthUser, JwtConfig};
///
/// async fn handler(user: AuthUser) -> String {
///     format!("user_id = {}", user.user_id)
/// }
///
/// # async fn example() {
/// let cfg = JwtConfig::from_env().unwrap();
/// let app: Router = Router::new()
///     .route("/me", get(handler))
///     .layer(Extension(cfg));
/// # }
/// ```
///
/// ## With custom extra claims
///
/// ```rust,no_run
/// use serde::Deserialize;
/// use axum_jwt_bridge::AuthUser;
///
/// #[derive(Debug, Clone, Deserialize)]
/// struct MyExtra {
///     #[serde(default)]
///     tenant_id: Option<String>,
/// }
///
/// async fn handler(user: AuthUser<MyExtra>) -> String {
///     format!("tenant: {:?}", user.claims.extra.tenant_id)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthUser<E = NoExtraClaims> {
    /// Numeric user ID parsed from `sub`.
    pub user_id: u32,

    /// Full decoded claims, including extra claims of type `E`.
    pub claims: Claims<E>,

    /// Raw bearer token (useful for forwarding to the primary API).
    pub token: String,
}

impl<S, E> FromRequestParts<S> for AuthUser<E>
where
    S: Send + Sync,
    E: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = extract_bearer(parts)?;

        // MultiJwtConfig takes precedence; fall back to a single JwtConfig.
        let claims = if let Some(multi) = parts.extensions.get::<MultiJwtConfig>() {
            verify_jwt_any_as::<E>(&token, multi)?
        } else {
            let config = parts
                .extensions
                .get::<JwtConfig>()
                .cloned()
                .ok_or_else(|| {
                    AuthError::ConfigError(
                        "JwtConfig (or MultiJwtConfig) not found — add `.layer(Extension(config))`"
                            .into(),
                    )
                })?;
            verify_jwt_as::<E>(&token, &config)?
        };

        let user_id = claims.user_id_u32().ok_or_else(|| {
            AuthError::InvalidSubject(format!("`sub` is not a valid u32: {:?}", claims.sub))
        })?;

        Ok(AuthUser {
            user_id,
            claims,
            token,
        })
    }
}

/// Like [`AuthUser`] but yields `None` when no `Authorization` header
/// is present.  A malformed header still returns an error.
#[derive(Debug, Clone)]
pub struct OptionalAuthUser<E = NoExtraClaims>(Option<AuthUser<E>>);

impl<E> OptionalAuthUser<E> {
    pub fn into_inner(self) -> Option<AuthUser<E>> {
        self.0
    }
    pub fn as_ref(&self) -> Option<&AuthUser<E>> {
        self.0.as_ref()
    }
}

impl<S, E> FromRequestParts<S> for OptionalAuthUser<E>
where
    S: Send + Sync,
    E: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if parts.headers.get(http::header::AUTHORIZATION).is_none() {
            return Ok(Self(None));
        }
        AuthUser::from_request_parts(parts, state)
            .await
            .map(|u| Self(Some(u)))
    }
}

fn extract_bearer(parts: &Parts) -> Result<String, AuthError> {
    let header = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .ok_or(AuthError::MissingHeader)?
        .to_str()
        .map_err(|_| AuthError::InvalidHeaderFormat)?;

    header
        .strip_prefix("Bearer ")
        .map(|t| t.to_owned())
        .ok_or(AuthError::InvalidBearerFormat)
}

