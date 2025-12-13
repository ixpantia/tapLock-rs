#[cfg(feature = "axum")]
pub mod axum;

pub mod entra_id;
pub mod google;
pub mod jwks;
pub mod keycloak;

pub const ACCESS_TOKEN_COOKIE_NAME: &str = "taplock_access_token";
pub const REFRESH_TOKEN_COOKIE_NAME: &str = "taplock_refresh_token";
pub const TAPLOCK_CALLBACK_ENDPOINT: &str = "/.taplock/callback";

// TODO: Pasar todo esto a tapLock-rs distribuible

use crate::error::TapLockError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2Response {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub fields: serde_json::Value,
}

#[async_trait::async_trait]
pub trait OAuth2Client: Send + Sync {
    async fn exchange_refresh_token(
        &self,
        refresh_token: String,
    ) -> Result<OAuth2Response, TapLockError>;
    async fn exchange_code(&self, code: String) -> Result<OAuth2Response, TapLockError>;
    fn decode_access_token(&self, access_token: String) -> Result<OAuth2Response, TapLockError>;
    fn get_authorization_url(&self) -> String;
}
