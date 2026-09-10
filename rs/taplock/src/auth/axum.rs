use super::OAuth2Client;
use super::{ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME, TAPLOCK_CALLBACK_ENDPOINT};

use axum::{
    extract::{Extension, Query, Request, State},
    http::{header::AUTHORIZATION, header::SET_COOKIE, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
pub struct AuthQuery {
    pub code: Option<String>,
}

/// Strategy for determining when to redirect to login vs returning 401 Unauthorized.
#[derive(Clone, Debug, Default)]
pub enum RedirectStrategy {
    /// Always redirect to login on authentication failure.
    #[default]
    Always,
    /// Only redirect for paths that start with one of the given prefixes.
    Only(HashSet<String>),
    /// Redirect for all paths except those starting with one of the given prefixes.
    Except(HashSet<String>),
}

/// Configuration for TapLock authentication.
#[derive(Clone, Default)]
pub struct TapLockConfig {
    /// Strategy to use for redirection.
    pub redirect_strategy: RedirectStrategy,
    /// Domain to attach to the authentication cookies.
    ///
    /// If `None`, the value of the `TAPLOCK_COOKIE_DOMAIN` environment variable is used
    /// at build time; if that is also unset, the cookies are host-only (browser default).
    pub cookie_domain: Option<String>,
}

impl TapLockConfig {
    /// Returns a new builder for `TapLockConfig`.
    pub fn builder() -> TapLockConfigBuilder {
        TapLockConfigBuilder::default()
    }

    /// Determines if a given path should redirect based on the strategy.
    pub fn should_redirect(&self, path: &str) -> bool {
        match &self.redirect_strategy {
            RedirectStrategy::Always => true,
            RedirectStrategy::Only(prefixes) => {
                prefixes.iter().any(|prefix| path.starts_with(prefix))
            }
            RedirectStrategy::Except(prefixes) => {
                !prefixes.iter().any(|prefix| path.starts_with(prefix))
            }
        }
    }
}

/// Builder for [`TapLockConfig`].
#[derive(Default)]
pub struct TapLockConfigBuilder {
    strategy: RedirectStrategy,
    cookie_domain: Option<String>,
}

impl TapLockConfigBuilder {
    /// Configures the middleware to always redirect on authentication failure.
    pub fn redirect_always(mut self) -> Self {
        self.strategy = RedirectStrategy::Always;
        self
    }

    /// Configures the middleware to only redirect for paths starting with these prefixes.
    /// All other paths will return 401 Unauthorized.
    pub fn redirect_only<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let set = prefixes.into_iter().map(|s| s.into()).collect();
        self.strategy = RedirectStrategy::Only(set);
        self
    }

    /// Configures the middleware to redirect for all paths EXCEPT those starting with these prefixes.
    /// The excluded paths (e.g. "/api/") will return 401 Unauthorized.
    pub fn redirect_except<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let set = prefixes.into_iter().map(|s| s.into()).collect();
        self.strategy = RedirectStrategy::Except(set);
        self
    }

    /// Configures the cookie domain that authentication cookies are attached to.
    ///
    /// Takes precedence over the `TAPLOCK_COOKIE_DOMAIN` environment variable.
    pub fn cookie_domain(mut self, domain: impl Into<String>) -> Self {
        self.cookie_domain = Some(domain.into());
        self
    }

    /// Builds the `TapLockConfig`.
    ///
    /// If no cookie domain was set explicitly, falls back to the value of the
    /// `TAPLOCK_COOKIE_DOMAIN` environment variable, if present.
    pub fn build(self) -> TapLockConfig {
        let cookie_domain = if self.cookie_domain.is_some() {
            self.cookie_domain
        } else {
            std::env::var("TAPLOCK_COOKIE_DOMAIN")
                .ok()
                .filter(|d| !d.is_empty())
        };
        TapLockConfig {
            redirect_strategy: self.strategy,
            cookie_domain,
        }
    }
}

// Helper to create a cookie for setting
fn create_auth_cookie<'a>(name: &'a str, value: String, domain: Option<String>) -> Cookie<'a> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    // cookie.set_secure(true); // Enable this if running over HTTPS in production
    if let Some(domain) = domain {
        cookie.set_domain(domain);
    }
    cookie
}

// Helper to create a cookie for removal
fn remove_auth_cookie<'a>(name: &'a str, domain: Option<String>) -> Cookie<'a> {
    let mut cookie = Cookie::build(name).removal().path("/").build();
    if let Some(domain) = domain {
        cookie.set_domain(domain);
    }
    cookie
}

// Helper to extract bearer token from Authorization header.
// The scheme is case-insensitive per RFC 6750 ("Bearer", "bearer", "BEARER").
fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Axum middleware that handles OAuth2 authentication via cookies or Authorization header.
pub async fn auth_middleware<S, C>(
    State(state): State<S>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Response
where
    S: Send + Sync + 'static,
    C: OAuth2Client + axum::extract::FromRef<S> + 'static,
{
    let path = req.uri().path();

    // Skip authentication for the callback endpoint to avoid infinite redirect loops
    if path == TAPLOCK_CALLBACK_ENDPOINT {
        return next.run(req).await;
    }

    let client = C::from_ref(&state);

    let cookie_domain = req
        .extensions()
        .get::<TapLockConfig>()
        .and_then(|config| config.cookie_domain.clone());

    // Try to get access token from Authorization header first, then from cookie
    let access_token_header_val = extract_bearer_token(req.headers());
    let access_token_cookie_val = jar
        .get(ACCESS_TOKEN_COOKIE_NAME)
        .map(|c| c.value().to_string());
    let refresh_token_cookie_val = jar
        .get(REFRESH_TOKEN_COOKIE_NAME)
        .map(|c| c.value().to_string());

    // Prefer the Authorization header over the cookie (cookie is set by our
    // login flow); if one candidate fails validation, fall back to the other.
    let candidates = [access_token_header_val, access_token_cookie_val];

    // --- 1. Validate Access Token (from Authorization header or cookie) ---
    for access_token in candidates.into_iter().flatten() {
        match client.decode_access_token(access_token) {
            Ok(token_info) => {
                req.extensions_mut().insert(token_info);
                return next.run(req).await;
            }
            Err(e) => {
                tracing::warn!("Invalid access token: {:?}", e);
            }
        }
    }

    // --- 2. Access Token is missing or invalid, try to refresh ---
    if let Some(refresh_token) = refresh_token_cookie_val {
        tracing::debug!("Attempting to refresh tokens using refresh token.");
        match client.exchange_refresh_token(refresh_token).await {
            Ok(token_response) => {
                tracing::debug!("Successfully refreshed tokens.");
                req.extensions_mut().insert(token_response.clone());

                let mut response = next.run(req).await;

                let new_access_cookie = create_auth_cookie(
                    ACCESS_TOKEN_COOKIE_NAME,
                    token_response.access_token,
                    cookie_domain.clone(),
                );
                response.headers_mut().append(
                    SET_COOKIE,
                    HeaderValue::from_str(&new_access_cookie.to_string()).unwrap(),
                );

                if let Some(new_refresh_token) = token_response.refresh_token {
                    let new_refresh_cookie = create_auth_cookie(
                        REFRESH_TOKEN_COOKIE_NAME,
                        new_refresh_token,
                        cookie_domain.clone(),
                    );
                    response.headers_mut().append(
                        SET_COOKIE,
                        HeaderValue::from_str(&new_refresh_cookie.to_string()).unwrap(),
                    );
                } else {
                    let remove_old_refresh_cookie =
                        remove_auth_cookie(REFRESH_TOKEN_COOKIE_NAME, cookie_domain.clone());
                    response.headers_mut().append(
                        SET_COOKIE,
                        HeaderValue::from_str(&remove_old_refresh_cookie.to_string()).unwrap(),
                    );
                }
                return response;
            }
            Err(e) => {
                tracing::warn!("Failed to refresh tokens: {:?}.", e);
            }
        }
    }

    // --- 3. Authentication failed: Determine if we should redirect or return 401 ---
    let config = req.extensions().get::<TapLockConfig>();
    let should_redirect = match config {
        Some(cfg) => cfg.should_redirect(path),
        None => true, // Default to redirect if no config extension found
    };

    if should_redirect {
        tracing::debug!("Authentication failed. Redirecting to login handler.");
        let mut response = Redirect::to(TAPLOCK_CALLBACK_ENDPOINT).into_response();

        let remove_access_cookie =
            remove_auth_cookie(ACCESS_TOKEN_COOKIE_NAME, cookie_domain.clone());
        response.headers_mut().append(
            SET_COOKIE,
            HeaderValue::from_str(&remove_access_cookie.to_string()).unwrap(),
        );
        let remove_refresh_cookie =
            remove_auth_cookie(REFRESH_TOKEN_COOKIE_NAME, cookie_domain.clone());
        response.headers_mut().append(
            SET_COOKIE,
            HeaderValue::from_str(&remove_refresh_cookie.to_string()).unwrap(),
        );

        response
    } else {
        tracing::debug!("Authentication failed. Returning 401 Unauthorized.");
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

/// Handler for the authentication callback and login initiation.
pub async fn login_handler<S, C>(
    State(state): State<S>,
    jar: CookieJar,
    Query(query): Query<AuthQuery>,
    config: Option<Extension<TapLockConfig>>,
) -> Response
where
    S: Send + Sync + 'static,
    C: OAuth2Client + axum::extract::FromRef<S> + 'static,
{
    let client = C::from_ref(&state);
    let cookie_domain = config
        .as_ref()
        .and_then(|config| config.0.cookie_domain.clone());

    if let Some(code) = query.code {
        match client.exchange_code(code).await {
            Ok(token_response) => {
                let mut jar = jar;
                jar = jar.add(create_auth_cookie(
                    ACCESS_TOKEN_COOKIE_NAME,
                    token_response.access_token,
                    cookie_domain.clone(),
                ));

                if let Some(refresh_token) = token_response.refresh_token {
                    jar = jar.add(create_auth_cookie(
                        REFRESH_TOKEN_COOKIE_NAME,
                        refresh_token,
                        cookie_domain.clone(),
                    ));
                }

                (jar, Redirect::to("/")).into_response()
            }
            Err(e) => {
                tracing::error!("Failed to exchange code: {:?}", e);
                let mut jar = jar;
                let mut access_cookie = Cookie::build(ACCESS_TOKEN_COOKIE_NAME)
                    .removal()
                    .path("/")
                    .build();
                let mut refresh_cookie = Cookie::build(REFRESH_TOKEN_COOKIE_NAME)
                    .removal()
                    .path("/")
                    .build();
                if let Some(domain) = cookie_domain.clone() {
                    access_cookie.set_domain(domain.clone());
                    refresh_cookie.set_domain(domain);
                }
                jar = jar.remove(access_cookie);
                jar = jar.remove(refresh_cookie);
                (
                    jar,
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Authentication failed: {:?}", e),
                    ),
                )
                    .into_response()
            }
        }
    } else {
        let auth_url = client.get_authorization_url();
        Redirect::to(&auth_url).into_response()
    }
}

/// Extension trait for Axum routers to easily add TapLock authentication.
pub trait TapLockRouterExt<S> {
    /// Configures the router with TapLock authentication and a default configuration (Always redirect).
    fn taplock_auth<C>(self, state: S) -> Self
    where
        S: Clone + Send + Sync + 'static,
        C: OAuth2Client + axum::extract::FromRef<S> + 'static;

    /// Configures the router with TapLock authentication and a custom configuration.
    fn taplock_auth_with_config<C>(self, state: S, config: TapLockConfig) -> Self
    where
        S: Clone + Send + Sync + 'static,
        C: OAuth2Client + axum::extract::FromRef<S> + 'static;
}

impl<S> TapLockRouterExt<S> for axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn taplock_auth<C>(self, state: S) -> Self
    where
        C: OAuth2Client + axum::extract::FromRef<S> + 'static,
    {
        self.taplock_auth_with_config::<C>(state, TapLockConfig::builder().build())
    }

    fn taplock_auth_with_config<C>(self, state: S, config: TapLockConfig) -> Self
    where
        C: OAuth2Client + axum::extract::FromRef<S> + 'static,
    {
        self.route(
            TAPLOCK_CALLBACK_ENDPOINT,
            axum::routing::get(login_handler::<S, C>),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth_middleware::<S, C>,
        ))
        .layer(axum::Extension(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TapLockError;
    use crate::OAuth2Response;
    use axum::{body::Body, http::Request, routing::get, Router};
    use std::sync::Mutex;
    use tower::ServiceExt;

    // Env vars are process-global, so tests that mutate TAPLOCK_COOKIE_DOMAIN must not run in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn builder_sets_cookie_domain_explicitly() {
        let config = TapLockConfig::builder()
            .cookie_domain("example.com")
            .build();
        assert_eq!(config.cookie_domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn builder_falls_back_to_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: edition 2021, single-threaded test; we restore the value afterwards.
        let previous = std::env::var("TAPLOCK_COOKIE_DOMAIN").ok();
        std::env::set_var("TAPLOCK_COOKIE_DOMAIN", "example.org");

        let config = TapLockConfig::builder().build();
        assert_eq!(config.cookie_domain.as_deref(), Some("example.org"));

        match previous {
            Some(v) => std::env::set_var("TAPLOCK_COOKIE_DOMAIN", v),
            None => std::env::remove_var("TAPLOCK_COOKIE_DOMAIN"),
        }
    }

    #[test]
    fn builder_ignores_empty_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: edition 2021, single-threaded test; we restore the value afterwards.
        let previous = std::env::var("TAPLOCK_COOKIE_DOMAIN").ok();
        std::env::set_var("TAPLOCK_COOKIE_DOMAIN", "");

        let config = TapLockConfig::builder().build();
        assert_eq!(config.cookie_domain, None);

        match previous {
            Some(v) => std::env::set_var("TAPLOCK_COOKIE_DOMAIN", v),
            None => std::env::remove_var("TAPLOCK_COOKIE_DOMAIN"),
        }
    }

    #[test]
    fn explicit_config_takes_precedence_over_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: edition 2021, single-threaded test; we restore the value afterwards.
        let previous = std::env::var("TAPLOCK_COOKIE_DOMAIN").ok();
        std::env::set_var("TAPLOCK_COOKIE_DOMAIN", "env.example.com");

        let config = TapLockConfig::builder()
            .cookie_domain("config.example.com")
            .build();
        assert_eq!(config.cookie_domain.as_deref(), Some("config.example.com"));

        match previous {
            Some(v) => std::env::set_var("TAPLOCK_COOKIE_DOMAIN", v),
            None => std::env::remove_var("TAPLOCK_COOKIE_DOMAIN"),
        }
    }

    #[test]
    fn create_auth_cookie_includes_domain_when_set() {
        let cookie = create_auth_cookie(
            "taplock_access_token",
            "token".to_string(),
            Some("example.com".to_string()),
        );
        assert!(cookie.to_string().contains("Domain=example.com"));
    }

    #[test]
    fn create_auth_cookie_omits_domain_when_unset() {
        let cookie = create_auth_cookie("taplock_access_token", "token".to_string(), None);
        assert!(!cookie.to_string().to_lowercase().contains("domain="));
    }

    #[test]
    fn remove_auth_cookie_includes_domain_when_set() {
        let cookie = remove_auth_cookie("taplock_access_token", Some("example.com".to_string()));
        assert!(cookie.to_string().contains("Domain=example.com"));
    }

    #[test]
    fn remove_auth_cookie_omits_domain_when_unset() {
        let cookie = remove_auth_cookie("taplock_access_token", None);
        assert!(!cookie.to_string().to_lowercase().contains("domain="));
    }

    fn auth_headers(value: &'static str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn extract_bearer_token_accepts_standard_scheme() {
        assert_eq!(
            extract_bearer_token(&auth_headers("Bearer abc.def.ghi")).as_deref(),
            Some("abc.def.ghi")
        );
    }

    #[test]
    fn extract_bearer_token_scheme_is_case_insensitive() {
        assert_eq!(
            extract_bearer_token(&auth_headers("bearer abc.def.ghi")).as_deref(),
            Some("abc.def.ghi")
        );
        assert_eq!(
            extract_bearer_token(&auth_headers("BEARER abc.def.ghi")).as_deref(),
            Some("abc.def.ghi")
        );
    }

    #[test]
    fn extract_bearer_token_trims_whitespace_around_token() {
        assert_eq!(
            extract_bearer_token(&auth_headers("Bearer   abc.def.ghi  ")).as_deref(),
            Some("abc.def.ghi")
        );
    }

    #[test]
    fn extract_bearer_token_rejects_other_schemes() {
        assert_eq!(
            extract_bearer_token(&auth_headers("Basic abc.def.ghi")),
            None
        );
    }

    #[test]
    fn extract_bearer_token_rejects_missing_header() {
        assert_eq!(extract_bearer_token(&axum::http::HeaderMap::new()), None);
    }

    #[test]
    fn extract_bearer_token_rejects_missing_token() {
        assert_eq!(extract_bearer_token(&auth_headers("Bearer")), None);
        assert_eq!(extract_bearer_token(&auth_headers("Bearer ")), None);
    }

    const VALID_TOKEN: &str = "valid-jwt-token";

    #[derive(Clone, Debug)]
    struct MockClient {
        valid_token: String,
    }

    #[async_trait::async_trait]
    impl OAuth2Client for MockClient {
        async fn exchange_refresh_token(
            &self,
            _refresh_token: String,
        ) -> Result<OAuth2Response, TapLockError> {
            Err(TapLockError::new("refresh not supported by mock"))
        }

        async fn exchange_code(&self, _code: String) -> Result<OAuth2Response, TapLockError> {
            Err(TapLockError::new("code exchange not supported by mock"))
        }

        fn decode_access_token(
            &self,
            access_token: String,
        ) -> Result<OAuth2Response, TapLockError> {
            if access_token == self.valid_token {
                Ok(OAuth2Response {
                    access_token,
                    refresh_token: None,
                    fields: serde_json::json!({ "sub": "test-user" }),
                })
            } else {
                Err(TapLockError::new("invalid token"))
            }
        }

        fn get_authorization_url(&self) -> String {
            "https://example.com/auth".to_string()
        }
    }

    fn test_app(client: MockClient) -> Router {
        Router::new()
            .route("/protected", get(|| async { "ok" }))
            .taplock_auth_with_config::<MockClient>(
                client.clone(),
                TapLockConfig::builder()
                    .redirect_only(std::iter::empty::<String>())
                    .build(),
            )
            .with_state(client)
    }

    async fn send(app: Router, req: Request<Body>) -> axum::response::Response {
        app.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn authenticates_with_bearer_header() {
        let app = test_app(MockClient {
            valid_token: VALID_TOKEN.to_string(),
        });
        let response = send(
            app,
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, format!("Bearer {VALID_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_header_scheme_is_case_insensitive() {
        let app = test_app(MockClient {
            valid_token: VALID_TOKEN.to_string(),
        });
        let response = send(
            app,
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, format!("bearer {VALID_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authenticates_with_valid_cookie() {
        let app = test_app(MockClient {
            valid_token: VALID_TOKEN.to_string(),
        });
        let response = send(
            app,
            Request::builder()
                .uri("/protected")
                .header(
                    axum::http::header::COOKIE,
                    format!("{ACCESS_TOKEN_COOKIE_NAME}={VALID_TOKEN}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn header_takes_precedence_over_stale_cookie() {
        let app = test_app(MockClient {
            valid_token: VALID_TOKEN.to_string(),
        });
        let response = send(
            app,
            Request::builder()
                .uri("/protected")
                .header(
                    axum::http::header::COOKIE,
                    format!("{ACCESS_TOKEN_COOKIE_NAME}=stale-token"),
                )
                .header(AUTHORIZATION, format!("Bearer {VALID_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn falls_back_to_cookie_when_header_token_is_stale() {
        let app = test_app(MockClient {
            valid_token: VALID_TOKEN.to_string(),
        });
        let response = send(
            app,
            Request::builder()
                .uri("/protected")
                .header(
                    axum::http::header::COOKIE,
                    format!("{ACCESS_TOKEN_COOKIE_NAME}={VALID_TOKEN}"),
                )
                .header(AUTHORIZATION, "Bearer stale-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_credentials_return_unauthorized() {
        let app = test_app(MockClient {
            valid_token: VALID_TOKEN.to_string(),
        });
        let response = send(
            app,
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_credentials_return_unauthorized() {
        let app = test_app(MockClient {
            valid_token: VALID_TOKEN.to_string(),
        });
        let response = send(
            app,
            Request::builder()
                .uri("/protected")
                .header(
                    axum::http::header::COOKIE,
                    format!("{ACCESS_TOKEN_COOKIE_NAME}=stale-token"),
                )
                .header(AUTHORIZATION, "Bearer stale-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
