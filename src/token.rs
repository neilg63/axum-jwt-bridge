use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngExt;
use serde::{de::DeserializeOwned, Serialize};

use crate::claims::{Claims, NoExtraClaims};
use crate::config::{JwtConfig, MultiJwtConfig};
use crate::error::AuthError;

/// Random alphanumeric `jti`.
pub fn generate_jti(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect()
}

/// Create a signed HS256 JWT.  `user_id` becomes the `sub` claim.
///
/// Extra claims are set to [`NoExtraClaims`] (nothing).  To include
/// framework-specific claims, use [`generate_jwt_with`].
pub fn generate_jwt(user_id: impl ToString, config: &JwtConfig) -> Result<String, AuthError> {
    generate_jwt_with(user_id, config, NoExtraClaims)
}

/// Create a signed HS256 JWT with custom extra claims flattened into the
/// payload.
///
/// ```rust,no_run
/// use serde::Serialize;
/// use axum_jwt_auth::{generate_jwt_with, JwtConfig};
///
/// #[derive(Serialize)]
/// struct Extra { tenant_id: String }
///
/// # fn main() -> Result<(), axum_jwt_auth::AuthError> {
/// let config = JwtConfig::new("secret");
/// let token = generate_jwt_with(42, &config, Extra { tenant_id: "acme".into() })?;
/// # Ok(())
/// # }
/// ```
pub fn generate_jwt_with<E: Serialize>(
    user_id: impl ToString,
    config: &JwtConfig,
    extra: E,
) -> Result<String, AuthError> {
    let sub = user_id.to_string();
    if sub.is_empty() {
        return Err(AuthError::InvalidSubject("user_id must not be empty".into()));
    }
    if config.secret.is_empty() {
        return Err(AuthError::ConfigError("JWT secret must not be empty".into()));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64;

    let claims = Claims {
        iss: Some(config.issuer()),
        iat: now,
        exp: now + (config.ttl_days as i64) * 86_400,
        nbf: now,
        jti: generate_jti(16),
        sub,
        aud: config.audience.clone(),
        prv: config.provider.compute(),
        extra,
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )
    .map_err(|e| AuthError::InvalidToken(e.to_string()))
}

/// Verify an HS256 JWT, ignoring any extra claims.
///
/// Returns `Claims<NoExtraClaims>`.  To deserialize framework-specific
/// extra claims, use [`verify_jwt_as`].
pub fn verify_jwt(token: &str, config: &JwtConfig) -> Result<Claims, AuthError> {
    verify_jwt_as::<NoExtraClaims>(token, config)
}

/// Try each config in [`MultiJwtConfig`] in order; return the first success.
///
/// Intended for services that accept tokens from multiple issuers (e.g. a
/// Laravel backend and a .NET Core service during a migration).  Each config
/// is tried independently — a wrong-secret failure on one does not affect
/// the others.  The last error is returned only if every config fails.
pub fn verify_jwt_any(token: &str, configs: &MultiJwtConfig) -> Result<Claims, AuthError> {
    verify_jwt_any_as::<NoExtraClaims>(token, configs)
}

/// Like [`verify_jwt_any`] but deserializes extra claims into `E`.
pub fn verify_jwt_any_as<E: DeserializeOwned>(
    token: &str,
    configs: &MultiJwtConfig,
) -> Result<Claims<E>, AuthError> {
    let mut last_err = AuthError::InvalidToken("no configs provided".into());
    for config in configs.iter() {
        match verify_jwt_as::<E>(token, config) {
            Ok(claims) => return Ok(claims),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Verify an HS256 JWT, deserializing extra claims into `E`.
///
/// ```rust,no_run
/// use serde::Deserialize;
/// use axum_jwt_auth::{Claims, verify_jwt_as, JwtConfig};
///
/// #[derive(Deserialize)]
/// struct Extra { tenant_id: Option<String> }
///
/// # fn main() -> Result<(), axum_jwt_auth::AuthError> {
/// # let token = String::new();
/// let config = JwtConfig::new("secret");
/// let claims: Claims<Extra> = verify_jwt_as(&token, &config)?;
/// println!("tenant: {:?}", claims.extra.tenant_id);
/// # Ok(())
/// # }
/// ```
pub fn verify_jwt_as<E: DeserializeOwned>(
    token: &str,
    config: &JwtConfig,
) -> Result<Claims<E>, AuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "sub", "iat"]);

    if config.validate_issuer {
        validation.set_issuer(&[config.issuer()]);
    }

    if let Some(aud) = &config.audience {
        validation.set_audience(aud);
    } else {
        validation.validate_aud = false;
    }

    let data = decode::<Claims<E>>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        jsonwebtoken::errors::ErrorKind::ImmatureSignature => AuthError::TokenNotYetValid,
        jsonwebtoken::errors::ErrorKind::InvalidIssuer => AuthError::InvalidIssuer,
        jsonwebtoken::errors::ErrorKind::InvalidAudience => AuthError::InvalidAudience,
        _ => AuthError::InvalidToken(e.to_string()),
    })?;

    let claims = data.claims;

    if config.validate_provider {
        if let Some(expected) = config.provider.compute() {
            match &claims.prv {
                Some(prv) if *prv == expected => {}
                _ => return Err(AuthError::InvalidProvider),
            }
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cfg = JwtConfig::new("test-secret");
        let token = generate_jwt(42u32, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert_eq!(claims.user_id_u32(), Some(42));
        assert_eq!(claims.sub, "42");
        assert!(claims.prv.is_none());
    }

    #[test]
    fn roundtrip_laravel() {
        use crate::config::ProviderStrategy;
        let cfg = JwtConfig::new("test-secret")
            .provider(ProviderStrategy::laravel("App\\Models\\User"));
        let token = generate_jwt(42u32, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert_eq!(claims.user_id_u32(), Some(42));
        assert_eq!(claims.sub, "42");
        assert!(claims.prv.is_some());
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = generate_jwt(1, &JwtConfig::new("good")).unwrap();
        assert!(verify_jwt(&token, &JwtConfig::new("bad")).is_err());
    }

    #[test]
    fn issuer_normalised() {
        let cfg = JwtConfig::new("s")
            .base_url("https://example.com/")
            .auth_path("/api/login");
        assert_eq!(cfg.issuer(), "https://example.com/api/login");
    }

    #[test]
    fn no_provider_omits_prv() {
        use crate::config::ProviderStrategy;
        let cfg = JwtConfig::new("s").provider(ProviderStrategy::None);
        let token = generate_jwt(1, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert!(claims.prv.is_none());
    }

    #[test]
    fn prv_hash_is_deterministic() {
        use crate::config::ProviderStrategy;
        let a = ProviderStrategy::laravel("App\\Models\\User").compute();
        let b = ProviderStrategy::laravel("App\\Models\\User").compute();
        assert_eq!(a, b);
        assert_eq!(a.unwrap().len(), 40); // SHA-1 hex
    }

    #[test]
    fn roundtrip_with_extra_claims() {
        use serde::Deserialize;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct Extra {
            tenant_id: String,
        }

        let cfg = JwtConfig::new("test-secret");
        let token = generate_jwt_with(7, &cfg, Extra { tenant_id: "acme".into() }).unwrap();
        let claims = verify_jwt_as::<Extra>(&token, &cfg).unwrap();
        assert_eq!(claims.sub, "7");
        assert_eq!(claims.extra.tenant_id, "acme");
    }

    // ── Audience (aud) tests ──────────────────────────────────────────────────
    //
    // The `aud` claim (RFC 7519 §4.1.3) is used by:
    //   - Auth0          — identifies the API the token is issued for
    //   - Keycloak        — the client/resource-server the token targets
    //   - Okta            — the authorization server audience URI
    //   - AWS Cognito     — the app client ID
    //   - Firebase Auth   — the Firebase project ID
    //   - OAuth 2.0 JWT Bearer (RFC 9068) — mandatory `aud` field
    //
    // Laravel (tymon/jwt-auth) and Django REST Framework SimpleJWT do NOT
    // use `aud` by default, so `config.audience` is `None` for those.

    #[test]
    fn aud_roundtrip_single() {
        let cfg = JwtConfig::new("secret").audience(["https://api.example.com"]);
        let token = generate_jwt(1, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert_eq!(claims.aud.as_deref(), Some(["https://api.example.com".to_string()].as_slice()));
    }

    #[test]
    fn aud_roundtrip_multiple() {
        // Auth0 / Keycloak sometimes issue tokens with multiple audiences.
        let cfg = JwtConfig::new("secret")
            .audience(["https://api.example.com", "https://admin.example.com"]);
        let token = generate_jwt(1, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        let aud = claims.aud.unwrap();
        assert!(aud.contains(&"https://api.example.com".to_string()));
        assert!(aud.contains(&"https://admin.example.com".to_string()));
    }

    #[test]
    fn wrong_audience_rejected() {
        let issuing_cfg = JwtConfig::new("secret").audience(["https://api.example.com"]);
        let token = generate_jwt(1, &issuing_cfg).unwrap();

        // Verifier expects a different audience.
        let verifying_cfg = JwtConfig::new("secret").audience(["https://other.example.com"]);
        assert!(matches!(
            verify_jwt(&token, &verifying_cfg),
            Err(AuthError::InvalidAudience)
        ));
    }

    #[test]
    fn no_audience_config_ignores_aud_claim() {
        // Tokens that carry an aud claim should not be rejected when the
        // verifier has no audience configured (Laravel / Django behaviour).
        let issuing_cfg = JwtConfig::new("secret").audience(["https://api.example.com"]);
        let token = generate_jwt(1, &issuing_cfg).unwrap();

        let verifying_cfg = JwtConfig::new("secret"); // no audience check
        assert!(verify_jwt(&token, &verifying_cfg).is_ok());
    }

    // ── Multi-issuer tests ────────────────────────────────────────────────────

    #[test]
    fn multi_config_accepts_first_issuer() {
        use crate::config::MultiJwtConfig;
        let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
        let dotnet  = JwtConfig::new("dotnet-secret").validate_issuer(true);
        let multi   = MultiJwtConfig::new([laravel.clone(), dotnet]);

        let token = generate_jwt(1, &laravel).unwrap();
        assert!(verify_jwt_any(&token, &multi).is_ok());
    }

    #[test]
    fn multi_config_accepts_second_issuer() {
        use crate::config::MultiJwtConfig;
        let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
        let dotnet  = JwtConfig::new("dotnet-secret");
        let multi   = MultiJwtConfig::new([laravel, dotnet.clone()]);

        let token = generate_jwt(2, &dotnet).unwrap();
        assert!(verify_jwt_any(&token, &multi).is_ok());
    }

    #[test]
    fn multi_config_rejects_unknown_issuer() {
        use crate::config::MultiJwtConfig;
        let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
        let dotnet  = JwtConfig::new("dotnet-secret");
        let multi   = MultiJwtConfig::new([laravel, dotnet]);

        // Token signed with a completely different secret.
        let other = JwtConfig::new("unknown-secret");
        let token = generate_jwt(3, &other).unwrap();
        assert!(verify_jwt_any(&token, &multi).is_err());
    }

    #[test]
    fn extra_claims_ignored_by_default() {
        use serde::Deserialize;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct Extra {
            custom_field: String,
        }

        let cfg = JwtConfig::new("test-secret");
        // Generate with extra claims
        let token = generate_jwt_with(1, &cfg, Extra { custom_field: "hello".into() }).unwrap();
        // Verify without — extra field is silently ignored
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert_eq!(claims.sub, "1");
    }
}

