use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pythonize::pythonize;
use std::sync::Arc;
use taplock_rs::{
    auth::{entra_id, google, keycloak},
    OAuth2Client, ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME, TAPLOCK_CALLBACK_ENDPOINT,
};

#[pyclass]
struct TapLockClient {
    client: Arc<dyn OAuth2Client>,
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
            client: Arc::new(client),
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
            client: Arc::new(client),
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
            client: Arc::new(client),
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
            client: Arc::new(client),
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
            client: Arc::new(client),
            app_url,
        };

        Ok(taplock_client)
    })
}

#[pyfunction]
fn initialize_keycloak_from_env<'p>(py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let client = keycloak::KeycloakClient::from_env()
            .await
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let app_url = std::env::var("TAPLOCK_APP_URL").unwrap_or_default();

        let taplock_client = TapLockClient {
            client: Arc::new(client),
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
