pub mod auth;
pub mod error;

pub use auth::{
    keycloak, OAuth2Client, OAuth2Response, ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME,
    TAPLOCK_CALLBACK_ENDPOINT,
};
pub use error::TapLockError;

#[cfg(feature = "extendr-api")]
pub mod extendr;
