use super::{ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME, TAPLOCK_CALLBACK_ENDPOINT};

use axum::{extract::Request, middleware::Next, response::Response};

use super::OAuth2Client;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};

use axum::http::header::{HeaderValue, SET_COOKIE};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite}; // Import for Set-Cookie header

use serde::Deserialize;

use std::sync::Arc;

pub trait AuthState: Clone + Send + Sync + 'static {
    type Client: OAuth2Client;
    fn oauth_client(&self) -> Arc<Self::Client>;
}

#[derive(Deserialize)]
pub struct AuthQuery {
    code: Option<String>,
}

// Helper to create a cookie for setting
fn create_auth_cookie<'a>(name: &'a str, value: String) -> Cookie<'a> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    // cookie.set_secure(true); // Enable this if running over HTTPS
    cookie
}

// Helper to create a cookie for removal
fn remove_auth_cookie<'a>(name: &'a str) -> Cookie<'a> {
    Cookie::build(name).removal().path("/").build()
}

pub async fn auth_middleware<S>(
    State(state): State<S>,
    jar: CookieJar, // Read-only view of cookies from the request
    request: Request,
    next: Next,
) -> Response
where
    S: AuthState,
{
    let access_token_cookie_val = jar
        .get(ACCESS_TOKEN_COOKIE_NAME)
        .map(|c| c.value().to_string());
    let refresh_token_cookie_val = jar
        .get(REFRESH_TOKEN_COOKIE_NAME)
        .map(|c| c.value().to_string());

    let mut response;

    // --- Validate Access Token ---
    if let Some(access_token) = access_token_cookie_val {
        match state.oauth_client().decode_access_token(access_token) {
            Ok(_) => {
                // Access token is valid, proceed with the request
                return next.run(request).await;
            }
            Err(e) => {
                tracing::warn!("Invalid access token: {:?}", e);
                // Access token is invalid, fall through to refresh or re-login logic
            }
        }
    } else {
        tracing::debug!("No access token found.");
    }

    // --- Access Token is invalid or missing, try to refresh ---
    if let Some(refresh_token) = refresh_token_cookie_val {
        tracing::debug!("Attempting to refresh tokens using refresh token.");
        match state
            .oauth_client()
            .exchange_refresh_token(refresh_token)
            .await
        {
            Ok(token_response) => {
                tracing::debug!("Successfully refreshed tokens.");
                // Successfully refreshed, run the next middleware/handler and then add new cookies
                response = next.run(request).await;

                // Set new access token cookie
                let new_access_cookie =
                    create_auth_cookie(ACCESS_TOKEN_COOKIE_NAME, token_response.access_token);
                response.headers_mut().append(
                    SET_COOKIE,
                    HeaderValue::from_str(&new_access_cookie.to_string()).unwrap(),
                );

                // Set new refresh token cookie or remove old one
                if let Some(new_refresh_token) = token_response.refresh_token {
                    let new_refresh_cookie =
                        create_auth_cookie(REFRESH_TOKEN_COOKIE_NAME, new_refresh_token);
                    response.headers_mut().append(
                        SET_COOKIE,
                        HeaderValue::from_str(&new_refresh_cookie.to_string()).unwrap(),
                    );
                } else {
                    // If no new refresh token returned, remove the old one (it might be one-time use or expired by the server)
                    let remove_old_refresh_cookie = remove_auth_cookie(REFRESH_TOKEN_COOKIE_NAME);
                    response.headers_mut().append(
                        SET_COOKIE,
                        HeaderValue::from_str(&remove_old_refresh_cookie.to_string()).unwrap(),
                    );
                }
                return response;
            }
            Err(e) => {
                tracing::warn!("Failed to refresh tokens: {:?}. Redirecting to login.", e);
                // Refresh failed, clear all auth cookies and redirect to login
                response = Redirect::to(TAPLOCK_CALLBACK_ENDPOINT).into_response();

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
                return response;
            }
        }
    } else {
        // No refresh token available, or access token was invalid and no refresh token
        tracing::debug!("No valid access token and no refresh token. Redirecting to login.");
        response = Redirect::to(TAPLOCK_CALLBACK_ENDPOINT).into_response();

        // Ensure invalid access token is removed if it existed
        let remove_access_cookie = remove_auth_cookie(ACCESS_TOKEN_COOKIE_NAME);
        response.headers_mut().append(
            SET_COOKIE,
            HeaderValue::from_str(&remove_access_cookie.to_string()).unwrap(),
        );
        return response;
    }
}

pub async fn login_handler<S>(
    State(state): State<S>,
    mut jar: CookieJar, // `jar` for modifications
    Query(query): Query<AuthQuery>,
) -> Response
where
    S: AuthState,
{
    if let Some(code) = query.code {
        // Handle callback from Keycloak
        match state.oauth_client().exchange_code(code).await {
            Ok(token_response) => {
                jar = jar.add(create_auth_cookie(
                    ACCESS_TOKEN_COOKIE_NAME,
                    token_response.access_token,
                ));

                if let Some(refresh_token) = token_response.refresh_token {
                    jar = jar.add(create_auth_cookie(REFRESH_TOKEN_COOKIE_NAME, refresh_token));
                } else {
                    // If no refresh token is provided on code exchange, ensure any old one is removed.
                    jar = jar.remove(Cookie::build(REFRESH_TOKEN_COOKIE_NAME));
                }

                (jar, Redirect::to("/")).into_response()
            }
            Err(e) => {
                tracing::error!("Failed to exchange code: {:?}", e);
                // On failure, clear any potentially bad cookies before showing error
                jar = jar.remove(Cookie::build(ACCESS_TOKEN_COOKIE_NAME));
                jar = jar.remove(Cookie::build(REFRESH_TOKEN_COOKIE_NAME));
                (
                    jar, // Pass the modified jar back with the error response
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Authentication failed: {:?}", e),
                    ),
                )
                    .into_response()
            }
        }
    } else {
        // Redirect to Keycloak login
        let auth_url = state.oauth_client().get_authorization_url();
        Redirect::to(&auth_url).into_response()
    }
}
