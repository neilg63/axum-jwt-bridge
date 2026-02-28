[![Mirror](https://img.shields.io/badge/mirror-github-blue)](https://github.com/neilg63/axum-jwt-bridge)
[![Crates.io](https://img.shields.io/crates/v/axum-jwt-bridge.svg)](https://crates.io/crates/axum-jwt-bridge)
[![Docs.rs](https://docs.rs/axum-jwt-bridge/badge.svg)](https://docs.rs/axum-jwt-bridge)

# axum-jwt-bridge

JWT encode/decode for [Axum](https://docs.rs/axum) microservices, compatible with any HS256 JWT issuer with an audience claim (`aud`) as well as Laravel's `tymon/jwt-auth` with a provider claim (`prv`). Supports accepting tokens from multiple issuers simultaneously.

## Differences from `axum-jwt-auth`

- `axum-jwt-bridge` is focused on interoperability and migration scenarios (notably Laravel `prv` compatibility and multi-issuer acceptance during transitions).
- This crate can generate JWTs with standard registered claims (`iss`, `iat`, `exp`, `nbf`, `jti`, `sub`) plus optional `aud`/`prv`, while still prioritizing simple decode/extract middleware usage.
- [`axum-jwt-auth`](https://crates.io/crates/axum-jwt-auth) also supports standard-claims workflows and includes additional features that may be useful depending on your auth model; review both crates for your project needs.



Extracts `user_id: u32` from the `sub` claim. Role-based authorization is the consuming application's responsibility.

## Sample decoded token format

```json
{
    "iss": "https://subdomain.domain.tld/api/login",
    "iat": 1771440754,
    "exp": 1772650354,
    "nbf": 1771440754,
    "jti": "EzPm7S7qiUe0UVGw",
    "sub": "1232",
    "prv": "23bd5c8949f600adb39e701c400872db7a5976f7"
}
```

## Usage

The simplest pattern: add `AuthUser` as a handler parameter. Any route that includes it rejects unauthenticated requests automatically. Routes without it remain public.

```rust
use axum::{routing::get, Extension, Router};
use axum_jwt_bridge::{AuthUser, JwtConfig};

async fn handler(user: AuthUser) -> String {
    // user.user_id is the u32 parsed from "sub"
    // use it to query roles/permissions from your DB
    format!("user_id = {}", user.user_id)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok(); // your app loads .env, not this crate
    let config = JwtConfig::from_env().unwrap();

    let app: Router = Router::new()
        .route("/me", get(handler))
        .layer(Extension(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## Environment variables

This crate does **not** load `.env` files.

| Variable              | Required | Default                  | Notes                                      |
|-----------------------|----------|--------------------------|--------------------------------------------|
| `JWT_SECRET`          | **yes**  | —                        |                                            |
| `BASE_URL`            | no       | `http://localhost:8000`  |                                            |
| `AUTH_PATH`           | no       | `/api/login`             |                                            |
| `JWT_TTL_DAYS`        | no       | `14`                     | Token lifetime in days                     |
| `USER_MODEL_PATH`     | no       | *(unset)*                | Sets `prv` and enables its validation      |
| `JWT_VALIDATE_ISSUER` | no       | `false`                  | Set to `true` or `1` to enable             |
| `JWT_AUDIENCE`        | no       | *(unset)*                | Comma-separated; sets and validates `aud`  |

## Programmatic configuration

```rust
use axum_jwt_bridge::{JwtConfig, ProviderStrategy};

// Framework-agnostic (no prv claim)
let config = JwtConfig::new("my-secret");

// Laravel tymon/jwt-auth compatible
// Note: This Rust string literal decodes to runtime value: App\Models\User.
// Keep runtime value aligned with your Laravel model class string.
// See Troubleshooting for .env / Node / PHP escaping differences.
// See the Troubleshooting section for details.
let config = JwtConfig::laravel_compat("my-secret", "App\\Models\\User");

// With audience claim (Auth0, Keycloak, Okta, etc.)
let config = JwtConfig::new("my-secret")
    .audience(["https://api.example.com"]);

// Custom issuer
let config = JwtConfig::new("my-secret")
    .base_url("https://auth.example.com")
    .auth_path("/v2/token");
```

## Token generation

```rust
use axum_jwt_bridge::{generate_jwt, JwtConfig};

let config = JwtConfig::new("my-secret");
let token = generate_jwt(1264, &config).unwrap();
```

## Token verification

```rust
use axum_jwt_bridge::{verify_jwt, JwtConfig};

let config = JwtConfig::new("my-secret");
let claims = verify_jwt(&token, &config).unwrap();
assert_eq!(claims.user_id_u32(), Some(1264));
```

## Optional authentication

```rust
use axum_jwt_bridge::OptionalAuthUser;

async fn handler(user: OptionalAuthUser) -> String {
    match user.into_inner() {
        Some(u) => format!("Hello, user {}!", u.user_id),
        None    => "Hello, anonymous!".into(),
    }
}
```

## Extra claims

Define a struct for any non-standard JWT fields your issuer includes:

```rust
use serde::Deserialize;
use axum_jwt_bridge::AuthUser;

#[derive(Debug, Clone, Deserialize)]
struct MyExtra {
    #[serde(default)]
    tenant_id: Option<String>,
}

async fn handler(user: AuthUser<MyExtra>) -> String {
    format!("tenant: {:?}", user.claims.extra.tenant_id)
}
```

Unknown fields are silently ignored when using the default `AuthUser` (no type parameter).

## Multi-issuer support

Accept tokens from multiple issuers simultaneously — useful when migrating between services. Each config is tried in order; the first success wins.

```rust
use axum::{routing::get, Extension, Router};
use axum_jwt_bridge::{AuthUser, JwtConfig, MultiJwtConfig};

# async fn handler(_: AuthUser) {}
# async fn example() {
let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
let dotnet  = JwtConfig::new("dotnet-secret").validate_issuer(true);

let app: Router = Router::new()
    .route("/me", get(handler))
    .layer(Extension(MultiJwtConfig::new([laravel, dotnet])));
# }
```

`AuthUser` detects `MultiJwtConfig` automatically — no changes to handler code.

## Middleware for route groups

To protect an entire sub-router without touching individual handler signatures, use `axum::middleware::from_fn`:

```rust
use axum::{
    middleware::{self, Next},
    extract::Request,
    response::Response,
    routing::get,
    Extension, Router,
};
use axum_jwt_bridge::{verify_jwt, AuthError, JwtConfig};

async fn require_auth(
    Extension(config): Extension<JwtConfig>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let token = extract_bearer(&request)?;
    let claims = verify_jwt(&token, &config)?;
    request.extensions_mut().insert(claims); // available to handlers via Extension
    Ok(next.run(request).await)
}

fn extract_bearer(req: &Request) -> Result<String, AuthError> {
    req.headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or(AuthError::MissingHeader)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let config = JwtConfig::from_env().unwrap();

    // All routes in this sub-router require a valid JWT.
    let protected = Router::new()
        .route("/me", get(me_handler))
        .route("/orders", get(orders_handler))
        .route_layer(middleware::from_fn(require_auth)); // use route_layer, not layer

    let app = Router::new()
        .route("/health", get(health_handler)) // public
        .merge(protected)                       // all protected
        .layer(Extension(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

> **Note:** Use `.route_layer` rather than `.layer` so the middleware only runs on matched routes. This prevents unauthenticated 404 responses for unknown paths.

### Which pattern to use

| Goal | Pattern |
|------|---------|
| Per-route auth, varying access levels | `AuthUser` / `OptionalAuthUser` extractor |
| Protect an entire router uniformly | `route_layer(from_fn(require_auth))` |
| Mix public + protected routes | Merge a protected sub-router |
| Multi-issuer (migration) | `Extension(MultiJwtConfig)` + either pattern |

## Troubleshooting

### "Invalid provider hash" error

If you're getting this error when verifying Laravel JWTs, the `prv` claim in your token doesn't match what this crate expects. This is usually due to **escaping differences between runtime values and source-code string literals**.

For standard Laravel 8+ setups, the intended runtime model path is usually:

```text
App\Models\User
```

That same runtime value may appear differently depending on where you set it:

- `.env`: `USER_MODEL_PATH=App\Models\User`
- Rust source literal: `"App\\Models\\User"`
- Node/JS source literal: `"App\\Models\\User"` (or `'App\\Models\\User'`)
- Laravel/PHP quoted string: often written with escaped backslashes, but should evaluate to `App\Models\User`

**Diagnose the issue:**

```bash
# Decode your JWT to see the actual prv value
cargo run --example decode -- YOUR_JWT_TOKEN_HERE
```

**Hash mapping (for quick checks):**

| Your JWT's `prv` hash | Runtime model path | Rust source literal |
|----------------------|-------------------------|-----------|
| `23bd5c8949f600adb39e701c400872db7a5976f7` | `App\Models\User` (Laravel 8+) | `"App\\Models\\User"` |
| `3bb14b87c47aabc7635b62725877baa20182812f` | `App\\Models\\User` (double backslashes in runtime value) | `"App\\\\Models\\\\User"` |
| `87e0af1ef9fd15812fdec97153a14e0b047546aa` | `App\User` (Laravel 5-7) | `"App\\User"` |

**Important:** match on **runtime value**, not how it is escaped in source files.

**How PHP quoting affects runtime value:**

- PHP single-quoted: `'App\\Models\\User'` → runtime `App\\Models\\User`
- PHP double-quoted: `"App\\Models\\User"` → runtime `App\Models\User`

Check your Laravel `config/auth.php` to see how the model is configured, then adjust your Rust code accordingly.

**Quick fix:** If you don't need the `prv` validation, disable it:

```rust
let config = JwtConfig::new("secret"); // no USER_MODEL_PATH or provider
```

This validates signature, expiry, and issuer but skips the provider hash check.

## CLI example

```bash
JWT_SECRET=my-secret cargo run --example token -- generate 42
JWT_SECRET=my-secret cargo run --example token -- verify eyJhbG...

# Decode a JWT to inspect claims (no verification)
cargo run --example decode -- eyJhbG...
```

## License

MIT

## Examples

AuthUser implements FromRequestParts, so it works directly as a handler parameter. Any route that lists it will reject unauthenticated requests automatically.

```rust
use axum::{routing::get, Extension, Router};
use axum_jwt_bridge::{AuthUser, JwtConfig};

async fn me(user: AuthUser) -> String {
    format!("user_id = {}", user.user_id)
}

#[tokio::main]
async fn main() {
    let config = JwtConfig::from_env().unwrap();

    let app = Router::new()
        .route("/me", get(me))
        .layer(Extension(config));

    // ...
}
```

### Middleware for route groups
If you want to protect an entire sub-router without touching individual handler signatures — the pattern the user described as "a special function passed as authenticated middleware":

```rust
use axum::{
    middleware::{self, Next},
    extract::Request,
    response::Response,
    routing::get,
    Extension, Router,
};
use axum_jwt_bridge::{verify_jwt, AuthError, JwtConfig};

async fn require_auth(
    Extension(config): Extension<JwtConfig>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let token = extract_bearer(&request)?;
    let claims = verify_jwt(&token, &config)?;
    // Optionally inject claims for downstream handlers:
    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

fn extract_bearer(req: &Request) -> Result<String, AuthError> {
    req.headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or(AuthError::MissingHeader)
}

#[tokio::main]
async fn main() {
    let config = JwtConfig::from_env().unwrap();

    let protected = Router::new()
        .route("/me", get(me))
        .route("/orders", get(orders))
        .route_layer(middleware::from_fn(require_auth)); // applied to all routes above

    let app = Router::new()
        .route("/health", get(health))  // public
        .merge(protected)               // all protected
        .layer(Extension(config));
}
```

### Multi-issuer migration (Laravel + Rust during migration)

```rust
use axum_jwt_auth::{AuthUser, JwtConfig, MultiJwtConfig};

let laravel = JwtConfig::laravel_compat(laravel_secret, "App\\Models\\User");
let rust    = JwtConfig::new(rust_secret);
let multi   = MultiJwtConfig::new([laravel, rust]);

let app = Router::new()
    .route("/me", get(me))
    .layer(Extension(multi)); // AuthUser checks MultiJwtConfig first
```