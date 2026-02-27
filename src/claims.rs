use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Silently absorbs any unknown claims during deserialization and
/// serializes to nothing.  This is the default `E` parameter on
/// [`Claims`], so `Claims` and `Claims<NoExtraClaims>` are the same type.
#[derive(Debug, Clone, Default)]
pub struct NoExtraClaims;

impl Serialize for NoExtraClaims {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        s.serialize_map(Some(0))?.end()
    }
}

impl<'de> Deserialize<'de> for NoExtraClaims {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Sink;
        impl<'de> serde::de::Visitor<'de> for Sink {
            type Value = NoExtraClaims;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("extra claims (ignored)")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(NoExtraClaims)
            }
        }
        d.deserialize_map(Sink)
    }
}

/// JWT claims with an extensible extra-claims slot.
///
/// The standard registered fields (`iss`, `iat`, `exp`, `nbf`, `jti`,
/// `sub`) plus Laravel's optional `prv` are always present.  Any
/// additional issuer-specific claims live in `extra`.
///
/// ## Default usage (Laravel / no extra claims)
///
/// ```rust
/// use axum_jwt_auth::Claims;
///
/// // Claims is Claims<NoExtraClaims> — unknown fields silently ignored.
/// fn handle(claims: Claims) {
///     println!("user {}", claims.sub);
/// }
/// ```
///
/// ## Custom extra claims
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use axum_jwt_auth::Claims;
///
/// #[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// struct MyExtra {
///     #[serde(default)]
///     tenant_id: Option<String>,
///     #[serde(default)]
///     roles: Vec<String>,
/// }
///
/// fn handle(claims: Claims<MyExtra>) {
///     println!("tenant {:?}, roles {:?}", claims.extra.tenant_id, claims.extra.roles);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims<E = NoExtraClaims> {
    /// RFC 7519 §4.1.1 — optional; absent on many non-Laravel issuers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    pub iat: i64,
    pub exp: i64,
    pub nbf: i64,
    pub jti: String,
    pub sub: String,

    /// RFC 7519 §4.1.3 — identifies intended recipients.
    /// Used by Auth0, Keycloak, Okta, AWS Cognito, Firebase, and OAuth 2.0
    /// JWT Bearer (RFC 9068).  Absent on Laravel/Django tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,

    /// Laravel `prv` claim (SHA-1 of the user model class).
    /// Absent for tokens issued by non-Laravel systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prv: Option<String>,

    /// Framework-specific extra claims, flattened into the JWT payload.
    #[serde(flatten)]
    pub extra: E,
}

impl<E> Claims<E> {
    /// Parse `sub` as `u32`.
    pub fn user_id_u32(&self) -> Option<u32> {
        self.sub.parse().ok()
    }

    /// Parse `sub` as `usize`.
    pub fn user_id_usize(&self) -> Option<usize> {
        self.sub.parse().ok()
    }

    /// The raw subject string.
    pub fn subject(&self) -> &str {
        &self.sub
    }
}

