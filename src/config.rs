use crate::error::AuthError;

/// How to compute the `prv` claim.
#[derive(Debug, Clone)]
pub enum ProviderStrategy {
    /// No `prv` claim.
    None,
    /// SHA-1 of the given string (Laravel convention).
    Sha1(String),
    /// A pre-computed literal value.
    Literal(String),
}

impl ProviderStrategy {
    pub fn laravel(class: impl Into<String>) -> Self {
        Self::Sha1(class.into())
    }

    pub fn compute(&self) -> Option<String> {
        match self {
            Self::None => Option::None,
            Self::Sha1(input) => {
                use sha1::Digest;
                let hash = sha1::Sha1::new_with_prefix(input.as_bytes()).finalize();
                Some(hex_encode(&hash))
            }
            Self::Literal(v) => Some(v.clone()),
        }
    }
}

/// Configuration for JWT encode/decode.
///
/// Build with [`new`](Self::new), [`laravel_compat`](Self::laravel_compat),
/// or [`from_env`](Self::from_env).  See `from_env` for supported env vars.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub base_url: String,
    pub auth_path: String,
    pub provider: ProviderStrategy,
    pub ttl_days: u64,
    pub validate_issuer: bool,
    pub validate_provider: bool,
    /// When `Some`, the `aud` claim is both written into generated tokens
    /// and enforced during verification.  `None` means no audience claim.
    pub audience: Option<Vec<String>>,
}

impl JwtConfig {
    /// New config with framework-agnostic defaults (no `prv` claim).
    ///
    /// For Laravel compatibility use [`laravel_compat`](Self::laravel_compat)
    /// or [`from_env`](Self::from_env) with `USER_MODEL_PATH` set.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            base_url: "http://localhost:8000".into(),
            auth_path: "/api/login".into(),
            provider: ProviderStrategy::None,
            ttl_days: 14,
            validate_issuer: false,
            validate_provider: false,
            audience: None,
        }
    }

    /// Drop-in config for Laravel `tymon/jwt-auth` compatibility.
    ///
    /// Sets the `prv` claim to `sha1(model_class)` and enables its validation,
    /// matching what `tymon/jwt-auth` issues and expects.  Use the same
    /// `JWT_SECRET` as the Laravel application.
    ///
    /// ```rust
    /// use axum_jwt_auth::{JwtConfig, ProviderStrategy};
    ///
    /// let config = JwtConfig::laravel_compat("your-jwt-secret", "App\\Models\\User");
    /// // Optionally chain .validate_issuer(true) if BASE_URL / AUTH_PATH match.
    /// ```
    pub fn laravel_compat(
        secret: impl Into<String>,
        model_class: impl Into<String>,
    ) -> Self {
        Self::new(secret)
            .provider(ProviderStrategy::laravel(model_class))
            .validate_provider(true)
    }

    /// Build from environment variables already set in the process.
    ///
    /// | Variable              | Required | Default                 | Notes                                    |
    /// |-----------------------|----------|-------------------------|------------------------------------------|
    /// | `JWT_SECRET`          | **yes**  | —                       |                                          |
    /// | `BASE_URL`            | no       | `http://localhost:8000` |                                          |
    /// | `AUTH_PATH`           | no       | `/api/login`            |                                          |
    /// | `JWT_TTL_DAYS`        | no       | `14`                    | Token lifetime in days                   |
    /// | `USER_MODEL_PATH`     | no       | *(unset)*               | Sets `prv` and **enables** its validation|
    /// | `JWT_VALIDATE_ISSUER` | no       | `false`                 | `true` or `1` to enable                 |
    /// | `JWT_AUDIENCE`        | no       | *(unset)*               | Comma-separated; sets and validates `aud`|
    ///
    /// Setting `USER_MODEL_PATH` automatically enables `validate_provider`.
    pub fn from_env() -> Result<Self, AuthError> {
        let secret = std::env::var("JWT_SECRET")
            .map_err(|_| AuthError::ConfigError("JWT_SECRET is not set".into()))?;

        let base_url =
            std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8000".into());
        let auth_path =
            std::env::var("AUTH_PATH").unwrap_or_else(|_| "/api/login".into());

        let ttl_days = std::env::var("JWT_TTL_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(14);

        // Setting USER_MODEL_PATH implies you want the prv claim enforced.
        let (provider, validate_provider) = match std::env::var("USER_MODEL_PATH") {
            Ok(class) if !class.is_empty() => (ProviderStrategy::laravel(class), true),
            _ => (ProviderStrategy::None, false),
        };

        let validate_issuer = std::env::var("JWT_VALIDATE_ISSUER")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        // Comma-separated list, e.g. "https://api.example.com,https://admin.example.com"
        let audience = std::env::var("JWT_AUDIENCE")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());

        Ok(Self {
            secret,
            base_url,
            auth_path,
            provider,
            ttl_days,
            validate_issuer,
            validate_provider,
            audience,
        })
    }

    /// Full issuer URI: `{base_url}/{auth_path}`.
    pub fn issuer(&self) -> String {
        let base = self.base_url.trim_end_matches('/');
        let path = self.auth_path.trim_start_matches('/');
        format!("{base}/{path}")
    }

    pub fn base_url(mut self, v: impl Into<String>) -> Self {
        self.base_url = v.into();
        self
    }
    pub fn auth_path(mut self, v: impl Into<String>) -> Self {
        self.auth_path = v.into();
        self
    }
    pub fn provider(mut self, v: ProviderStrategy) -> Self {
        self.provider = v;
        self
    }
    pub fn ttl_days(mut self, v: u64) -> Self {
        self.ttl_days = v;
        self
    }
    pub fn validate_issuer(mut self, v: bool) -> Self {
        self.validate_issuer = v;
        self
    }
    pub fn validate_provider(mut self, v: bool) -> Self {
        self.validate_provider = v;
        self
    }
    pub fn audience(mut self, v: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.audience = Some(v.into_iter().map(Into::into).collect());
        self
    }
}

/// An ordered list of [`JwtConfig`]s tried in sequence during verification.
///
/// Register as an Axum extension instead of (or alongside) a single
/// `JwtConfig` to accept tokens from multiple issuers.
///
/// ```rust,no_run
/// use axum::{routing::get, Extension, Router};
/// use axum_jwt_auth::{AuthUser, JwtConfig, MultiJwtConfig};
///
/// # async fn handler(_: AuthUser) {}
/// # async fn example() {
/// let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
/// let dotnet  = JwtConfig::new("dotnet-secret").validate_issuer(true);
///
/// let app: Router = Router::new()
///     .route("/me", get(handler))
///     .layer(Extension(MultiJwtConfig::new([laravel, dotnet])));
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MultiJwtConfig(Vec<JwtConfig>);

impl MultiJwtConfig {
    /// Create from any iterable of [`JwtConfig`]s.
    pub fn new(configs: impl IntoIterator<Item = JwtConfig>) -> Self {
        Self(configs.into_iter().collect())
    }

    /// Iterate over the contained configs.
    pub fn iter(&self) -> impl Iterator<Item = &JwtConfig> {
        self.0.iter()
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}