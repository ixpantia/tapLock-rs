use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pythonize::pythonize;
use std::sync::Arc;
use taplock_rs::{
    auth::{entra_id, google, keycloak},
    OAuth2Client, OAuth2Response, TapLockError, ACCESS_TOKEN_COOKIE_NAME,
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

#[pyclass]
struct TapLockClient {
    client: Arc<ClientEnum>,
    #[pyo3(get)]
    app_url: String,
}

#[pymethods]
impl TapLockClient {
    #[pyo3(text_signature = "($self, code)")]
    fn exchange_code<'p>(&self, py: Python<'p>, code: String) -> PyResult<Bound<'p, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let response = client
                .exchange_code(code)
                .await
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

            Python::attach(|py| {
                let bound =
                    pythonize(py, &response).map_err(|e| PyValueError::new_err(e.to_string()))?;
                Ok(bound.unbind())
            })
        })
    }

    #[pyo3(text_signature = "($self, refresh_token)")]
    fn exchange_refresh_token<'p>(
        &self,
        py: Python<'p>,
        refresh_token: String,
    ) -> PyResult<Bound<'p, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let response = client
                .exchange_refresh_token(refresh_token)
                .await
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

            Python::attach(|py| {
                let bound =
                    pythonize(py, &response).map_err(|e| PyValueError::new_err(e.to_string()))?;
                Ok(bound.unbind())
            })
        })
    }

    fn decode_access_token<'p>(
        &self,
        py: Python<'p>,
        access_token: String,
    ) -> PyResult<Bound<'p, PyAny>> {
        let response = self
            .client
            .decode_access_token(access_token)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        pythonize(py, &response).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn get_authorization_url(&self) -> String {
        self.client.get_authorization_url()
    }
}

#[pyfunction]
fn initialize_google<'p>(
    py: Python<'p>,
    client_id: String,
    client_secret: String,
    app_url: String,
    use_refresh_token: bool,
) -> PyResult<Bound<'p, PyAny>> {
    let app_url_clone = app_url.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let client = google::build_oauth2_state_google(
            &client_id,
            &client_secret,
            &app_url_clone,
            use_refresh_token,
        )
        .await
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let taplock_client = TapLockClient {
            client: Arc::new(ClientEnum::Google(client)),
            app_url: app_url_clone,
        };

        Ok(taplock_client)
    })
}

#[pyfunction]
fn initialize_entra_id<'p>(
    py: Python<'p>,
    client_id: String,
    client_secret: String,
    app_url: String,
    tenant_id: String,
    use_refresh_token: bool,
) -> PyResult<Bound<'p, PyAny>> {
    let app_url_clone = app_url.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let client = entra_id::build_oauth2_state_azure_ad(
            &client_id,
            &client_secret,
            &app_url_clone,
            use_refresh_token,
            &tenant_id,
        )
        .await
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let taplock_client = TapLockClient {
            client: Arc::new(ClientEnum::EntraId(client)),
            app_url: app_url_clone,
        };

        Ok(taplock_client)
    })
}

#[pyfunction]
fn initialize_keycloak<'p>(
    py: Python<'p>,
    client_id: String,
    client_secret: String,
    app_url: String,
    base_url: String,
    realm: String,
    use_refresh_token: bool,
) -> PyResult<Bound<'p, PyAny>> {
    let app_url_clone = app_url.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let client = keycloak::build_oauth2_state_keycloak(
            &client_id,
            &client_secret,
            &app_url_clone,
            &base_url,
            &realm,
            use_refresh_token,
        )
        .await
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let taplock_client = TapLockClient {
            client: Arc::new(ClientEnum::Keycloak(client)),
            app_url: app_url_clone,
        };

        Ok(taplock_client)
    })
}

#[pyfunction]
fn initialize_google_from_env<'p>(py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let client = google::GoogleOAuth2Client::from_env()
            .await
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let app_url = std::env::var("TAPLOCK_APP_URL").unwrap_or_default();

        let taplock_client = TapLockClient {
            client: Arc::new(ClientEnum::Google(client)),
            app_url,
        };

        Ok(taplock_client)
    })
}

#[pyfunction]
fn initialize_entra_id_from_env<'p>(py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let client = entra_id::AzureADOAuth2Client::from_env()
            .await
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let app_url = std::env::var("TAPLOCK_APP_URL").unwrap_or_default();

        let taplock_client = TapLockClient {
            client: Arc::new(ClientEnum::EntraId(client)),
            app_url,
        };

        Ok(taplock_client)
    })
}

#[pyfunction]
fn initialize_keycloak_from_env<'p>(py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let client = keycloak::KeycloakOAuth2Client::from_env()
            .await
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let app_url = std::env::var("TAPLOCK_APP_URL").unwrap_or_default();

        let taplock_client = TapLockClient {
            client: Arc::new(ClientEnum::Keycloak(client)),
            app_url,
        };

        Ok(taplock_client)
    })
}

#[pyfunction]
fn get_access_token_cookie_name() -> &'static str {
    ACCESS_TOKEN_COOKIE_NAME
}

#[pyfunction]
fn get_refresh_token_cookie_name() -> &'static str {
    REFRESH_TOKEN_COOKIE_NAME
}

#[pyfunction]
fn get_taplock_callback_endpoint() -> &'static str {
    TAPLOCK_CALLBACK_ENDPOINT
}

#[pymodule]
mod taplock {

    #[pymodule_export]
    use super::get_access_token_cookie_name;
    #[pymodule_export]
    use super::get_refresh_token_cookie_name;
    #[pymodule_export]
    use super::get_taplock_callback_endpoint;
    #[pymodule_export]
    use super::initialize_entra_id;
    #[pymodule_export]
    use super::initialize_entra_id_from_env;
    #[pymodule_export]
    use super::initialize_google;
    #[pymodule_export]
    use super::initialize_google_from_env;
    #[pymodule_export]
    use super::initialize_keycloak;
    #[pymodule_export]
    use super::initialize_keycloak_from_env;
    #[pymodule_export]
    use super::TapLockClient;
}
