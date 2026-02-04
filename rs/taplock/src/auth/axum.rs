use super::OAuth2Client;
use super::{ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME, TAPLOCK_CALLBACK_ENDPOINT};

use axum::{
    extract::{Query, Request, State},
    http::{header::SET_COOKIE, HeaderValue, StatusCode},
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

    /// Builds the `TapLockConfig`.
    pub fn build(self) -> TapLockConfig {
        TapLockConfig {
            redirect_strategy: self.strategy,
        }
    }
}

// Helper to create a cookie for setting
fn create_auth_cookie<'a>(name: &'a str, value: String) -> Cookie<'a> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    // cookie.set_secure(true); // Enable this if running over HTTPS in production
    cookie
}

// Helper to create a cookie for removal
fn remove_auth_cookie<'a>(name: &'a str) -> Cookie<'a> {
    Cookie::build(name).removal().path("/").build()
}

/// Axum middleware that handles OAuth2 authentication via cookies.
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

    let access_token_cookie_val = jar
        .get(ACCESS_TOKEN_COOKIE_NAME)
        .map(|c| c.value().to_string());
    let refresh_token_cookie_val = jar
        .get(REFRESH_TOKEN_COOKIE_NAME)
        .map(|c| c.value().to_string());

    // --- 1. Validate Access Token ---
    if let Some(access_token) = access_token_cookie_val {
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

                let new_access_cookie =
                    create_auth_cookie(ACCESS_TOKEN_COOKIE_NAME, token_response.access_token);
                response.headers_mut().append(
                    SET_COOKIE,
                    HeaderValue::from_str(&new_access_cookie.to_string()).unwrap(),
                );

                if let Some(new_refresh_token) = token_response.refresh_token {
                    let new_refresh_cookie =
                        create_auth_cookie(REFRESH_TOKEN_COOKIE_NAME, new_refresh_token);
                    response.headers_mut().append(
                        SET_COOKIE,
                        HeaderValue::from_str(&new_refresh_cookie.to_string()).unwrap(),
                    );
                } else {
                    let remove_old_refresh_cookie = remove_auth_cookie(REFRESH_TOKEN_COOKIE_NAME);
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

        let remove_access_cookie = remove_auth_cookie(ACCESS_TOKEN_COOKIE_NAME);
        response.headers_mut().append(
            SET_COOKIE,
            HeaderValue::from_str(&remove_access_cookie.to_string()).unwrap(),
        );
        let remove_refresh_cookie = remove_auth_cookie(REFRESH_TOKEN_COOKIE_NAME);
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
) -> Response
where
    S: Send + Sync + 'static,
    C: OAuth2Client + axum::extract::FromRef<S> + 'static,
{
    let client = C::from_ref(&state);

    if let Some(code) = query.code {
        match client.exchange_code(code).await {
            Ok(token_response) => {
                let mut jar = jar;
                jar = jar.add(create_auth_cookie(
                    ACCESS_TOKEN_COOKIE_NAME,
                    token_response.access_token,
                ));

                if let Some(refresh_token) = token_response.refresh_token {
                    jar = jar.add(create_auth_cookie(REFRESH_TOKEN_COOKIE_NAME, refresh_token));
                }

                (jar, Redirect::to("/")).into_response()
            }
            Err(e) => {
                tracing::error!("Failed to exchange code: {:?}", e);
                let mut jar = jar;
                jar = jar.remove(Cookie::build(ACCESS_TOKEN_COOKIE_NAME));
                jar = jar.remove(Cookie::build(REFRESH_TOKEN_COOKIE_NAME));
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
        self.taplock_auth_with_config::<C>(state, TapLockConfig::default())
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
