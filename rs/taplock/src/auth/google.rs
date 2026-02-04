use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use oauth2::TokenResponse;
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    StandardRevocableToken, StandardTokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

use super::jwks::JwksClient;
use super::{OAuth2Client, OAuth2Response, TAPLOCK_CALLBACK_ENDPOINT};
use crate::error::TapLockError;

const AUTH_BASE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

#[derive(Debug, Deserialize, Serialize, Clone)]
struct GoogleTokenResponseExtra {
    id_token: String,
}

impl oauth2::ExtraTokenFields for GoogleTokenResponseExtra {}

type GoogleClientFull = Client<
    BasicErrorResponse,
    StandardTokenResponse<GoogleTokenResponseExtra, BasicTokenType>,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

#[derive(Clone, Debug)]
pub struct GoogleOAuth2Client {
    reqwest_client: reqwest::Client,
    client: GoogleClientFull,
    client_id: String,
    jwks_client: JwksClient,
    use_refresh_token: bool,
}

impl GoogleOAuth2Client {
    fn get_jwk(&self, kid: &str) -> Option<jsonwebtoken::jwk::Jwk> {
        self.jwks_client.get_key(kid)
    }

    /// Initializes a Google client from environment variables
    ///
    /// - TAPLOCK_GOOGLE_CLIENT_ID (OAuth2 client ID)
    /// - TAPLOCK_GOOGLE_CLIENT_SECRET (OAuth2 client secret)
    /// - TAPLOCK_APP_URL (Base URL of this application for redirects)
    /// - TAPLOCK_GOOGLE_USE_REFRESH_TOKEN (Optional, "true" or "false", defaults to true)
    ///
    /// The error returns a vector of strings, either listing missing environment variables
    /// or describing an error during client initialization.
    pub async fn from_env() -> Result<Self, TapLockError> {
        let mut missing_env_vars = Vec::new();

        let get_env_var = |name: &str, missing: &mut Vec<String>| {
            std::env::var(name).unwrap_or_else(|_| {
                missing.push(name.to_string());
                String::new() // Return an empty string as a placeholder if not found
            })
        };

        let client_id = get_env_var("TAPLOCK_GOOGLE_CLIENT_ID", &mut missing_env_vars);
        let client_secret = get_env_var("TAPLOCK_GOOGLE_CLIENT_SECRET", &mut missing_env_vars);
        let app_url = get_env_var("TAPLOCK_APP_URL", &mut missing_env_vars);

        let use_refresh_token = match std::env::var("TAPLOCK_GOOGLE_USE_REFRESH_TOKEN") {
            Ok(s) => s.parse::<bool>().unwrap_or_else(|_| {
                eprintln!("Warning: TAPLOCK_GOOGLE_USE_REFRESH_TOKEN value '{}' is not a valid boolean. Defaulting to true.", s);
                true
            }),
            Err(_) => true,
        };

        if !missing_env_vars.is_empty() {
            return Err(TapLockError::MissingEnv(missing_env_vars));
        }

        build_oauth2_state_google(&client_id, &client_secret, &app_url, use_refresh_token).await
    }
}

fn decode_access_token(
    client: &GoogleOAuth2Client,
    access_token: String,
) -> Result<OAuth2Response, TapLockError> {
    let token_trim = access_token.trim_start_matches("Bearer").trim();
    let jwt_header = decode_header(token_trim)?;
    let kid = jwt_header.kid.ok_or(TapLockError::KidNotFound)?;
    let algo = jwt_header.alg;
    let decoding_key = client.get_jwk(&kid).ok_or(TapLockError::KidNotFound)?;
    let mut validation = Validation::new(algo);
    validation.set_audience(&[&client.client_id]);
    let val = decode::<serde_json::Value>(
        token_trim,
        &DecodingKey::from_jwk(&decoding_key)?,
        &validation,
    )?;

    Ok(OAuth2Response {
        access_token,
        refresh_token: None,
        fields: val.claims,
    })
}

async fn decode_token_and_maybe_refresh_jwks(
    client: &GoogleOAuth2Client,
    access_token: String,
) -> Result<OAuth2Response, TapLockError> {
    let token_trim = access_token.trim_start_matches("Bearer").trim();
    let jwt_header = decode_header(token_trim)?;
    let kid = jwt_header.kid.ok_or(TapLockError::KidNotFound)?;

    let decoding_key = client.jwks_client.get_key_with_refresh(&kid).await?;
    let algo = jwt_header.alg;
    let mut validation = Validation::new(algo);
    validation.set_audience(&[&client.client_id]);
    let val = decode::<serde_json::Value>(
        token_trim,
        &DecodingKey::from_jwk(&decoding_key)?,
        &validation,
    )?;

    Ok(OAuth2Response {
        access_token,
        refresh_token: None,
        fields: val.claims,
    })
}

pub async fn build_oauth2_state_google(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    use_refresh_token: bool,
) -> std::result::Result<GoogleOAuth2Client, TapLockError> {
    let app_url = app_url.trim_end_matches('/');
    let redirect_url = format!("{app_url}{TAPLOCK_CALLBACK_ENDPOINT}");

    let client = Client::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_auth_uri(AuthUrl::new(AUTH_BASE_URL.to_string())?)
        .set_token_uri(TokenUrl::new(TOKEN_URL.to_string())?)
        .set_redirect_uri(RedirectUrl::new(redirect_url)?);

    let reqwest_client = reqwest::Client::new();

    let jwks_client = JwksClient::new(JWKS_URL.to_string(), reqwest_client.clone()).await?;

    Ok(GoogleOAuth2Client {
        reqwest_client,
        client,
        jwks_client,
        client_id: client_id.to_string(),
        use_refresh_token,
    })
}

#[async_trait::async_trait]
impl OAuth2Client for GoogleOAuth2Client {
    async fn exchange_refresh_token(
        &self,
        refresh_token: String,
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        if !self.use_refresh_token {
            return Err(TapLockError::new("Refresh token is disabled"));
        }
        let token_result = self
            .client
            .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token.to_string()))
            .add_scopes(["openid", "email", "profile"].map(|s| Scope::new(s.into())))
            .request_async(&self.reqwest_client)
            .await?;

        let access_token = token_result.extra_fields().id_token.clone();
        let mut response = decode_token_and_maybe_refresh_jwks(self, access_token).await?;
        if self.use_refresh_token {
            response.refresh_token = Some(
                token_result
                    .refresh_token()
                    .map(|rt| rt.secret().clone())
                    .unwrap_or(refresh_token),
            );
        }
        Ok(response)
    }
    async fn exchange_code(
        &self,
        code: String,
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(&self.reqwest_client)
            .await?;

        let access_token = token_result.extra_fields().id_token.clone();
        let mut response = decode_token_and_maybe_refresh_jwks(self, access_token).await?;

        if self.use_refresh_token {
            response.refresh_token = token_result.refresh_token().map(|rt| rt.secret().clone());
        }

        Ok(response)
    }
    fn decode_access_token(
        &self,
        access_token: String,
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        let response = decode_access_token(self, access_token)?;
        Ok(response)
    }
    fn get_authorization_url(&self) -> String {
        let (auth_url, _csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_extra_param("access_type", "offline")
            .add_extra_param("prompt", "consent")
            .add_scopes(["openid", "email", "profile"].map(|s| Scope::new(s.into())))
            .url();
        auth_url.to_string()
    }
}
