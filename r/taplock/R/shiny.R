internal_add_auth_layers <- function(config, tower) {
  # Run functions to get endpoint and cookie names at the start
  login_endpoint <- get_taplock_login_endpoint()
  access_cookie_name <- get_access_token_cookie_name()
  refresh_cookie_name <- get_refresh_token_cookie_name()

  tower |>
    tower::add_get_route(login_endpoint, function(req) {
      query <- shiny::parseQueryString(req$QUERY_STRING)
      token <- request_token(config, query[["code"]])
      return(
        promises::then(
          token,
          onFulfilled = function(token) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = config$get_app_url(),
                "Set-Cookie" = build_cookie(
                  access_cookie_name,
                  add_bearer(token$access_token)
                ),
                "Set-Cookie" = build_cookie(
                  refresh_cookie_name,
                  token$refresh_token
                )
              )
            )
          },
          onRejected = function(e) {
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = config$get_app_url(),
                "Set-Cookie" = build_cookie(access_cookie_name, ""),
                "Set-Cookie" = build_cookie(refresh_cookie_name, "")
              )
            )
          }
        )
      )
    }) |>
    tower::add_get_route("/logout", function(req) {
      return(
        shiny::httpResponse(
          status = 302,
          headers = list(
            Location = config$get_app_url(),
            "Set-Cookie" = build_cookie(access_cookie_name, ""),
            "Set-Cookie" = build_cookie(refresh_cookie_name, "")
          )
        )
      )
    }) |>
    tower::add_http_layer(function(req) {
      # The cookie names are now extracted at the beginning of internal_add_auth_layers
      # and are available via lexical scoping.

      # Get the HTTP cookies from the request
      cookies <- parse_cookies(req$HTTP_COOKIE)
      req$PARSED_COOKIES <- cookies

      # If the user requests the root path, we'll check if they have
      # an access token. If they don't, we'll redirect them to the
      # login page.
      req$TOKEN <- access_token(config, cookies[[access_cookie_name]])

      if (
        is_error(req$TOKEN) && shiny::isTruthy(cookies[[refresh_cookie_name]])
      ) {
        # Ask for a new token using the refresh_token
        token <- request_token_refresh(config, cookies[[refresh_cookie_name]])
        return(
          promises::then(
            token,
            onFulfilled = function(token) {
              req$TOKEN <- token
              response <- req$NEXT(req)
              response$headers <- append(
                response$headers,
                list(
                  "Set-Cookie" = build_cookie(
                    access_cookie_name,
                    add_bearer(token$access_token)
                  ),
                  "Set-Cookie" = build_cookie(
                    refresh_cookie_name,
                    token$refresh_token
                  )
                )
              )
              return(response)
            },
            onRejected = function(e) {
              shiny::httpResponse(
                status = 302,
                headers = list(
                  Location = get_login_url(config),
                  "Set-Cookie" = build_cookie(
                    access_cookie_name,
                    ""
                  ),
                  "Set-Cookie" = build_cookie(
                    refresh_cookie_name,
                    ""
                  )
                )
              )
            }
          )
        )
      }
      print(req$TOKEN)
      if (is_error(req$TOKEN)) {
        if (req$PATH_INFO == "/") {
          return(
            shiny::httpResponse(
              status = 302,
              headers = list(
                Location = get_login_url(config)
              )
            )
          )
        } else {
          return(
            shiny::httpResponse(
              status = 403,
              content_type = "text/plain",
              content = "Forbidden"
            )
          )
        }
      }
      req$NEXT(req)
    }) |>
    tower::add_server_layer(function(input, output, session) {
      # The cookie name is now extracted at the beginning of internal_add_auth_layers
      # and is available via lexical scoping.

      cookies <- parse_cookies(session$request$HTTP_COOKIE)

      if (is.null(cookies[[access_cookie_name]])) {
        stop("No access token")
      }

      token_decode_result <- access_token(config, cookies[[access_cookie_name]])

      if (methods::is(token_decode_result, "error")) {
        rlang::abort(token_decode_result$value)
      }

      session$userData$token <- token_decode_result
    })
}
#' @title Add authentication middle ware to a 'tower' object
#' @description Attaches the necessary authentication layers
#'   to a 'tower' object. This will secure any layer added
#'   after.
#' @param tower A 'tower' object from the package 'tower'
#' @param config An 'openid_config' object
#' @return A modified 'tower' object with authentication layers
#' @export
add_auth_layers <- function(tower, config) {
  internal_add_auth_layers(config, tower)
}

#' @title Get the access token
#'
#' @description Gets the access token from the session to be used
#'   for internal logic.
#'
#' @param session A Shiny session
#'
#' @return An access_token object
#' @export
token <- function(session = shiny::getDefaultReactiveDomain()) {
  session$userData$token$fields
}
