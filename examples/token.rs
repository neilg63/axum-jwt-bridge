//! Generate and verify JWTs from the command line.
//!
//! Loads `.env` automatically if present, otherwise reads from the environment.
//!
//! ```bash
//! cargo run --example token -- generate 42
//! cargo run --example token -- verify eyJhbG...
//! ```

use axum_jwt_auth::{generate_jwt, verify_jwt, JwtConfig};

fn main() {
    // Load .env if present; silently ignore if absent.
    dotenvy::dotenv().ok();

    let config = JwtConfig::from_env().expect("JWT_SECRET must be set");

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }

    match args[0].as_str() {
        "generate" => {
            let subject = args.get(1).unwrap_or_else(|| usage());
            match generate_jwt(subject, &config) {
                Ok(token) => println!("{token}"),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "verify" => {
            let token = args.get(1).unwrap_or_else(|| usage());
            match verify_jwt(token, &config) {
                Ok(c) => {
                    println!("Valid\n");
                    println!("  sub : {}", c.sub);
                    if let Some(iss) = &c.iss {
                        println!("  iss : {iss}");
                    }
                    if let Some(aud) = &c.aud {
                        println!("  aud : {}", aud.join(", "));
                    }
                    println!("  iat : {}", fmt(c.iat));
                    println!("  exp : {}", fmt(c.exp));
                    println!("  nbf : {}", fmt(c.nbf));
                    println!("  jti : {}", c.jti);
                    if let Some(prv) = &c.prv {
                        println!("  prv : {prv}");
                    }
                }
                Err(e) => {
                    eprintln!("Failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => usage(),
    }
}

fn fmt(ts: i64) -> String {
    ts.to_string()
}

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  cargo run --example token -- generate <user_id>");
    eprintln!("  cargo run --example token -- verify  <token>");
    std::process::exit(1);
}
