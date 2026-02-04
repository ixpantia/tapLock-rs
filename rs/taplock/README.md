# tapLock Rust Core

`taplock-rs` is the high-performance core library for the tapLock ecosystem. It provides a robust, asynchronous implementation of OAuth2 and OpenID Connect flows, specifically designed to be wrapped by other languages (like Python and R) or used directly in Rust web frameworks like Axum.

## Features

- **Multi-Provider Support**: Built-in configurations for Google, Microsoft Entra ID (Azure), and Keycloak.
- **Secure Token Handling**: Logic for exchanging codes, refreshing tokens, and validating JWTs using JWKS.
- **Environment-First Configuration**: Initialize clients directly from environment variables.
- **Axum Integration**: Optional `axum` feature providing middleware for seamless session management via secure cookies.
- **Dyn-Compatible Wrappers**: Designed to work well with FFI and language bindings.

## Installation

Add `taplock` to your `Cargo.toml`:

```toml
[dependencies]
taplock = { git = "https://github.com/ixpantia/tapLock-rs.git", subdirectory = "rs/taplock" }
```

### Features

- `axum`: Enables Axum-specific middleware and utilities for web applications.

## Usage

### 1. Initialize a Client from Environment

The simplest way to get started is using the `from_env` methods.

```rust
use taplock::auth::google::GoogleOAuth2Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Requires:
    // TAPLOCK_GOOGLE_CLIENT_ID
    // TAPLOCK_GOOGLE_CLIENT_SECRET
    // TAPLOCK_APP_URL
    let client = GoogleOAuth2Client::from_env().await?;
    
    let auth_url = client.get_authorization_url();
    println!("Redirect users to: {}", auth_url);
    
    Ok(())
}
```

### 2. Manual Initialization

```rust
use taplock::auth::entra_id::build_oauth2_state_azure_ad;

let client = build_oauth2_state_azure_ad(
    "client-id",
    "client-secret",
    "https://your-app.com",
    true, // use_refresh_token
    "tenant-id"
).await?;
```

### 3. Axum Middleware (Optional)

If the `axum` feature is enabled, you can protect your routes with the provided middleware.

```rust
use axum::{Router, routing::get, response::IntoResponse};
use taplock::auth::axum::TapLockRouterExt;
use taplock::auth::google::GoogleOAuth2Client;

async fn protected_handler() -> impl IntoResponse {
    "You are logged in!"
}

#[tokio::main]
async fn main() {
    let client = GoogleOAuth2Client::from_env().await.unwrap();
    
    let app = Router::new()
        .route("/dashboard", get(protected_handler))
        // Automatically adds callback routes and session middleware
        .taplock_auth::<GoogleOAuth2Client>(client);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## Environment Variables

| Provider | Method | Environment Variables |
|----------|--------|-----------------------|
| **Google** | `GoogleOAuth2Client::from_env()` | `TAPLOCK_GOOGLE_CLIENT_ID`, `TAPLOCK_GOOGLE_CLIENT_SECRET`, `TAPLOCK_APP_URL`, `TAPLOCK_GOOGLE_USE_REFRESH_TOKEN` (opt) |
| **Entra ID** | `AzureADOAuth2Client::from_env()` | `TAPLOCK_ENTRA_ID_CLIENT_ID`, `TAPLOCK_ENTRA_ID_CLIENT_SECRET`, `TAPLOCK_ENTRA_ID_TENANT_ID`, `TAPLOCK_APP_URL`, `TAPLOCK_ENTRA_ID_USE_REFRESH_TOKEN` (opt) |
| **Keycloak** | `KeycloakOAuth2Client::from_env()` | `TAPLOCK_KEYCLOAK_URL`, `TAPLOCK_KEYCLOAK_REALM`, `TAPLOCK_KEYCLOAK_CLIENT_ID`, `TAPLOCK_KEYCLOAK_CLIENT_SECRET`, `TAPLOCK_APP_URL`, `TAPLOCK_KEYCLOAK_USE_REFRESH_TOKEN` (opt) |

## License

Copyright (c) 2026 ixpantia, S.A.