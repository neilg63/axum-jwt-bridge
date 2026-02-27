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
/// This crate does **not** load `.env` files.  Ensure environment
/// variables are set before calling [`from_env`](Self::from_env).
///
/// ## Expected env vars
///
/// | Variable           | Default                  |
/// |--------------------|--------------------------|
/// | `JWT_SECRET`       | *(required)*             |
/// | `BASE_URL`         | `http://localhost:8000`  |
/// | `AUTH_PATH`        | `/api/login`             |
/// | `USER_MODEL_PATH`  | *(unset — no `prv` claim)* |
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
    /// For Laravel compatibility, chain `.provider(ProviderStrategy::laravel("App\\Models\\User"))`,
    /// or use [`from_env`](Self::from_env) which reads `USER_MODEL_PATH`.
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

    /// Build from environment variables already set in the process.
    ///
    /// The `prv` claim (Laravel provider hash) is only included when
    /// `USER_MODEL_PATH` is explicitly set and non-empty.
    pub fn from_env() -> Result<Self, AuthError> {
        let secret = std::env::var("JWT_SECRET")
            .map_err(|_| AuthError::ConfigError("JWT_SECRET is not set".into()))?;

        let base_url =
            std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8000".into());
        let auth_path =
            std::env::var("AUTH_PATH").unwrap_or_else(|_| "/api/login".into());

        let provider = match std::env::var("USER_MODEL_PATH") {
            Ok(class) if !class.is_empty() => ProviderStrategy::laravel(class),
            _ => ProviderStrategy::None,
        };

        Ok(Self {
            secret,
            base_url,
            auth_path,
            provider,
            ttl_days: 14,
            validate_issuer: false,
            validate_provider: false,
            audience: None,
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

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}