[![Mirror](https://img.shields.io/badge/mirror-github-blue)](https://github.com/neilg63/axum-jwt-auth)
[![Crates.io](https://img.shields.io/crates/v/axum-jwt-auth.svg)](https://crates.io/crates/axum-jwt-auth)
[![Docs.rs](https://docs.rs/axum-jwt-auth/badge.svg)](https://docs.rs/axum-jwt-auth)

# axum-jwt-auth

JWT encode/decode for [Axum](https://docs.rs/axum) microservices, compatible with any HS256 JWT issuer with an audience claim  as well as Laravel's `tymon/jwt-auth` with a provider claim. This crate lets you keep your current API 

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

```rust
use axum::{routing::get, Extension, Router};
use axum_jwt_auth::{AuthUser, JwtConfig};

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

| Variable           | Required | Default                  |
|--------------------|----------|--------------------------|
| `JWT_SECRET`       | **yes**  | —                        |
| `BASE_URL`         | no       | `http://localhost:8000`  |
| `AUTH_PATH`        | no       | `/api/login`             |
| `USER_MODEL_PATH`  | no       | `App\Models\User`        |

## Programmatic configuration

```rust
use axum_jwt_auth::{JwtConfig, ProviderStrategy};

// Laravel (default)
let config = JwtConfig::new("my-secret");

// Non-Laravel — no prv claim
let config = JwtConfig::new("my-secret")
    .provider(ProviderStrategy::None);

// Custom issuer
let config = JwtConfig::new("my-secret")
    .base_url("https://auth.example.com")
    .auth_path("/v2/token");
```

## Token generation

```rust
use axum_jwt_auth::{generate_jwt, JwtConfig};

let config = JwtConfig::new("my-secret");
let token = generate_jwt(1264, &config).unwrap();
```

## Token verification

```rust
use axum_jwt_auth::{verify_jwt, JwtConfig};

let config = JwtConfig::new("my-secret");
let claims = verify_jwt(&token, &config).unwrap();
assert_eq!(claims.user_id_u32(), Some(1264));
```

## Optional authentication

```rust
use axum_jwt_auth::OptionalAuthUser;

async fn handler(user: OptionalAuthUser) -> String {
    match user.into_inner() {
        Some(u) => format!("Hello, user {}!", u.user_id),
        None    => "Hello, anonymous!".into(),
    }
}
```

## CLI example

```bash
JWT_SECRET=my-secret cargo run --example token -- generate 42
JWT_SECRET=my-secret cargo run --example token -- verify eyJhbG...
```

## License

MIT