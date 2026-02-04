use extendr_api::prelude::*;
use std::sync::Arc;
use tokio::sync::oneshot::{self, error::TryRecvError};

use taplock_rs::{
    auth::{entra_id, google},
    keycloak, OAuth2Client, OAuth2Response, TapLockError, ACCESS_TOKEN_COOKIE_NAME,
    REFRESH_TOKEN_COOKIE_NAME, TAPLOCK_CALLBACK_ENDPOINT,
};

#[derive(Clone, Debug)]
enum ClientEnum {
    Google(google::GoogleOAuth2Client),
    EntraId(entra_id::AzureADOAuth2Client),
    Keycloak(keycloak::KeycloakOAuth2Client),
}

#[async_trait::async_trait]
impl OAuth2Client for ClientEnum {
    async fn exchange_refresh_token(
        &self,
        refresh_token: String,
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        match self {
            ClientEnum::Google(c) => c.exchange_refresh_token(refresh_token).await,
            ClientEnum::EntraId(c) => c.exchange_refresh_token(refresh_token).await,
            ClientEnum::Keycloak(c) => c.exchange_refresh_token(refresh_token).await,
        }
    }
    async fn exchange_code(
        &self,
        code: String,
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        match self {
            ClientEnum::Google(c) => c.exchange_code(code).await,
            ClientEnum::EntraId(c) => c.exchange_code(code).await,
            ClientEnum::Keycloak(c) => c.exchange_code(code).await,
        }
    }
    fn decode_access_token(
        &self,
        access_token: String,
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        match self {
            ClientEnum::Google(c) => c.decode_access_token(access_token),
            ClientEnum::EntraId(c) => c.decode_access_token(access_token),
            ClientEnum::Keycloak(c) => c.decode_access_token(access_token),
        }
    }
    fn get_authorization_url(&self) -> String {
        match self {
            ClientEnum::Google(c) => c.get_authorization_url(),
            ClientEnum::EntraId(c) => c.get_authorization_url(),
            ClientEnum::Keycloak(c) => c.get_authorization_url(),
        }
    }
}

#[extendr]
fn get_access_token_cookie_name() -> &'static str {
    ACCESS_TOKEN_COOKIE_NAME
}

#[extendr]
fn get_refresh_token_cookie_name() -> &'static str {
    REFRESH_TOKEN_COOKIE_NAME
}

#[extendr]
fn get_taplock_callback_endpoint() -> &'static str {
    TAPLOCK_CALLBACK_ENDPOINT
}

#[extendr]
fn parse_cookies(cookie_string: Option<&str>) -> List {
    let mut cookies: Vec<(String, Robj)> = Vec::new();

    if let Some(s) = cookie_string {
        for cookie_result in cookie::Cookie::split_parse(s) {
            match cookie_result {
                Ok(cookie) => cookies.push((cookie.name().to_string(), cookie.value().into_robj())),
                Err(_e) => {}
            }
        }
    }

    List::from_pairs(cookies)
}

#[extendr]
enum FutureResult {
    Error(Robj),
    Ready(Robj),
    Pending,
}

#[extendr]
impl FutureResult {
    fn is_error(&self) -> bool {
        matches!(self, Self::Error(..))
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(..))
    }

    fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    fn error(&self) -> Nullable<Robj> {
        match self {
            FutureResult::Error(e) => NotNull(e.clone()),
            _ => Null,
        }
    }

    fn value(&self) -> Nullable<Robj> {
        match self {
            FutureResult::Ready(v) => NotNull(v.clone()),
            _ => Null,
        }
    }
}

#[extendr]
struct AsyncFuture {
    rx: oneshot::Receiver<std::result::Result<OAuth2Response, TapLockError>>,
}

#[extendr]
impl AsyncFuture {
    fn poll(&mut self) -> FutureResult {
        match self.rx.try_recv() {
            Ok(Ok(robj)) => FutureResult::Ready(robj.into_robj()),
            Ok(Err(err)) => FutureResult::Error(err.into_robj()),
            Err(TryRecvError::Empty) => FutureResult::Pending,
            Err(e) => panic!("{e}"),
        }
    }
}

#[extendr]
struct OAuth2Runtime {
    runtime: tokio::runtime::Runtime,
    client: Arc<ClientEnum>,
    app_url: Robj,
}

#[extendr]
impl OAuth2Runtime {
    // Should return a AsyncFuture with a List containing the access_token
    // and the refresh token
    fn request_token(&self, authorization_code: String) -> AsyncFuture {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let client = Arc::clone(&self.client);
        self.runtime.spawn(async move {
            let response = client.exchange_code(authorization_code).await;
            let _ = tx.send(response);
        });
        AsyncFuture { rx }
    }

    // Should return a AsyncFuture with a List containing the new access_token
    // and the refresh token
    fn request_token_refresh(&self, refresh_token: String) -> AsyncFuture {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let client = Arc::clone(&self.client);
        self.runtime.spawn(async move {
            let response = client.exchange_refresh_token(refresh_token).await;
            let _ = tx.send(response);
        });
        AsyncFuture { rx }
    }

    // Should return a list with the deocoded token in the form of a list
    // or an error if the token is invalid
    fn decode_token(&self, token: String) -> Result<Robj> {
        let res = self
            .client
            .decode_access_token(token)
            .map_err(|_| Error::from("Hello".to_string()))?;
        Ok(res.into_robj())
    }

    fn get_authorization_url(&self) -> String {
        self.client.get_authorization_url()
    }

    fn get_app_url(&self) -> Robj {
        self.app_url.clone()
    }
}

#[extendr]
fn initialize_google_from_env_runtime() -> Result<OAuth2Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(TapLockError::Io)?;

    let client = runtime.block_on(google::GoogleOAuth2Client::from_env())?;

    let client = Arc::new(ClientEnum::Google(client));

    let app_url_str = std::env::var("TAPLOCK_APP_URL").unwrap_or_default();
    let app_url = Strings::from(app_url_str).into_robj();

    Ok(OAuth2Runtime {
        client,
        runtime,
        app_url,
    })
}

#[extendr]
fn initialize_google_runtime(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    use_refresh_token: bool,
) -> Result<OAuth2Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(TapLockError::Io)?;

    let client = runtime.block_on(google::build_oauth2_state_google(
        client_id,
        client_secret,
        app_url,
        use_refresh_token,
    ))?;

    let client = Arc::new(ClientEnum::Google(client));

    let app_url = Strings::from(app_url).into_robj();

    Ok(OAuth2Runtime {
        client,
        runtime,
        app_url,
    })
}

#[extendr]
fn initialize_entra_id_from_env_runtime() -> Result<OAuth2Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(TapLockError::Io)?;

    let client = runtime.block_on(entra_id::AzureADOAuth2Client::from_env())?;

    let client = Arc::new(ClientEnum::EntraId(client));

    let app_url_str = std::env::var("TAPLOCK_APP_URL").unwrap_or_default();
    let app_url = Strings::from(app_url_str).into_robj();

    Ok(OAuth2Runtime {
        client,
        runtime,
        app_url,
    })
}

#[extendr]
fn initialize_entra_id_runtime(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    tenant_id: &str,
    use_refresh_token: bool,
) -> Result<OAuth2Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(TapLockError::Io)?;

    let client = runtime.block_on(entra_id::build_oauth2_state_azure_ad(
        client_id,
        client_secret,
        app_url,
        use_refresh_token,
        tenant_id,
    ))?;

    let client = Arc::new(ClientEnum::EntraId(client));

    let app_url = Strings::from(app_url).into_robj();

    Ok(OAuth2Runtime {
        client,
        runtime,
        app_url,
    })
}

#[extendr]
fn initialize_keycloak_from_env_runtime() -> Result<OAuth2Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(TapLockError::Io)?;

    let client = runtime.block_on(keycloak::KeycloakOAuth2Client::from_env())?;

    let client = Arc::new(ClientEnum::Keycloak(client));

    let app_url_str = std::env::var("TAPLOCK_APP_URL").unwrap_or_default();
    let app_url = Strings::from(app_url_str).into_robj();

    Ok(OAuth2Runtime {
        client,
        runtime,
        app_url,
    })
}

#[extendr]
fn initialize_keycloak_runtime(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    base_url: &str,
    realm: &str,
    use_refresh_token: bool,
) -> Result<OAuth2Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(TapLockError::Io)?;

    let client = runtime.block_on(keycloak::build_oauth2_state_keycloak(
        client_id,
        client_secret,
        app_url,
        base_url,
        realm,
        use_refresh_token,
    ))?;

    let client = Arc::new(ClientEnum::Keycloak(client));

    let app_url = Strings::from(app_url).into_robj();

    Ok(OAuth2Runtime {
        client,
        runtime,
        app_url,
    })
}

// Macro to generate exports.
// This ensures exported functions are registered with R.
// See corresponding C code in `entrypoint.c`.
extendr_module! {
    mod tapLock;
    fn get_access_token_cookie_name;
    fn get_refresh_token_cookie_name;
    fn get_taplock_callback_endpoint;
    fn parse_cookies;
    fn initialize_google_runtime;
    fn initialize_google_from_env_runtime;
    fn initialize_entra_id_runtime;
    fn initialize_entra_id_from_env_runtime;
    fn initialize_keycloak_runtime;
    fn initialize_keycloak_from_env_runtime;
    impl AsyncFuture;
    impl FutureResult;
    impl OAuth2Runtime;
}
