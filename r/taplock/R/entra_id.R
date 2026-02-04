#' @title Create a new entra_id_config object
#' @description Creates a new entra_id_config object
#'
#' @param tenant_id The tenant ID for the app
#' @param client_id The client ID for the app
#' @param client_secret The client secret for the app
#' @param app_url The URL for the app
#' @param use_refresh_token Enable the use of refresh tokens
#'
#' @return An entra_id_config object
#' @export
new_entra_id_config <- function(
  tenant_id,
  client_id,
  client_secret,
  app_url,
  use_refresh_token = TRUE
) {
  runtime_result <- initialize_entra_id_runtime(
    client_id = client_id,
    client_secret = client_secret,
    tenant_id = tenant_id,
    app_url = app_url,
    use_refresh_token = use_refresh_token
  )
  if (is_error(runtime_result)) {
    rlang::abort(runtime_result$value)
  }
  return(runtime_result)
}

#' @title Create a new entra_id_config object from environment variables
#' @description Creates a new entra_id_config object using environment variables:
#' - TAPLOCK_ENTRA_ID_CLIENT_ID
#' - TAPLOCK_ENTRA_ID_CLIENT_SECRET
#' - TAPLOCK_ENTRA_ID_TENANT_ID
#' - TAPLOCK_APP_URL
#' - TAPLOCK_ENTRA_ID_USE_REFRESH_TOKEN (Optional)
#'
#' @return An entra_id_config object
#' @export
new_entra_id_config_from_env <- function() {
  runtime_result <- initialize_entra_id_from_env_runtime()
  if (is_error(runtime_result)) {
    rlang::abort(runtime_result$value)
  }
  return(runtime_result)
}
