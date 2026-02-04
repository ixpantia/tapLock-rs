
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.staticfiles import PathLike
from starlette.types import ASGIApp, HTTPExceptionHandler, Receive, Scope, Send

from .taplock import (
    TapLockClient,
    get_access_token_cookie_name,
    get_refresh_token_cookie_name,
    get_taplock_callback_endpoint,
    initialize_entra_id,
    initialize_entra_id_from_env,
    initialize_google,
    initialize_google_from_env,
    initialize_keycloak,
    initialize_keycloak_from_env,
)


class TapLock:
    def __init__(self):
        self.client = TapLockClient
        self.access_token_cookie = get_access_token_cookie_name()
        self.refresh_token_cookie = get_refresh_token_cookie_name()
        self.callback_endpoint = get_taplock_callback_endpoint()

        # Create a router that pre-wires the auth endpoints
        self.router = APIRouter()
        self._setup_routes()

    def _setup_routes(self):
        """Registers the standard OAuth2 routes."""
        # Route 1: Login (Redirects to Provider)
        # Using the variable from Rust to define the path
        self.router.add_api_route(
            path=self.callback_endpoint,
            endpoint=self.callback,
            methods=["GET"]
        )

    # --- Initialization Methods (Call these in Lifespan) ---

    async def init_google(self, client_id: str, client_secret: str, app_url: str, use_refresh_token: bool = True):
        self.client = await initialize_google(client_id, client_secret, app_url, use_refresh_token)

    async def init_entra_id(self, client_id: str, client_secret: str, app_url: str, tenant_id: str, use_refresh_token: bool = True):
        self.client = await initialize_entra_id(client_id, client_secret, app_url, tenant_id, use_refresh_token)

    async def init_keycloak(self, client_id: str, client_secret: str, app_url: str, base_url: str, realm: str, use_refresh_token: bool = True):
        self.client = await initialize_keycloak(client_id, client_secret, app_url, base_url, realm, use_refresh_token)

    async def init_google_from_env(self):
        self.client = await initialize_google_from_env()

    async def init_entra_id_from_env(self):
        self.client = await initialize_entra_id_from_env()

    async def init_keycloak_from_env(self):
        self.client = await initialize_keycloak_from_env()

    # --- Route Handlers ---
    async def login(self, return_to: str = "/") -> Response:
        self._check_init()
        auth_url = self.client.get_authorization_url()
        response = RedirectResponse(auth_url)
        # Store the destination URL in a temporary cookie
        response.set_cookie(
            key="taplock_return_to",
            value=return_to,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=300 # 5 minutes is plenty for a login flow
        )
        return response

    # Logic headers without content length
    async def login_headers(self, return_to: str = "/") -> Dict[str, str]:
        response = await self.login(return_to)
        headers = response.headers
        headers.__delitem__("content-length")
        return dict(headers)

    async def callback(self, request: Request) -> RedirectResponse:
        self._check_init()
        code = request.query_params.get("code")
        if not code:
            raise HTTPException(status_code=400, detail="Authorization code not found")

        try:
            token_data = await self.client.exchange_code(code)
        except Exception as e:
             raise HTTPException(status_code=400, detail=f"Failed to exchange code: {str(e)}")

        # Retrieve the return URL from the cookie, default to "/"
        return_to = request.cookies.get("taplock_return_to", "/")

        # Create the redirect response
        redirect_response = RedirectResponse(url=return_to)

        # Set the authentication cookies on the new response
        self._set_cookies(redirect_response, token_data)

        # Clear the temporary return_to cookie
        redirect_response.delete_cookie("taplock_return_to")

        return redirect_response

    async def logout(self, response: Response):
        """Clears the authentication cookies."""
        response.delete_cookie(self.access_token_cookie)
        response.delete_cookie(self.refresh_token_cookie)
        return {"message": "Logged out"}

    # --- Dependency ---
    async def _handle_request(
        self,
        request: Request,
        redirect_on_fail: bool,
        return_to: Optional[str] = None
    ) -> Dict[str, Any]:
        self._check_init()
        access_token = request.cookies.get(self.access_token_cookie)

        if access_token:
            try:
                token_data = self.client.decode_access_token(access_token)
                return token_data
            except Exception:
                pass # Token invalid, try refresh

        refresh_token = request.cookies.get(self.refresh_token_cookie)
        if not refresh_token:
            if redirect_on_fail:
                # Capture current URL if no specific return_to is provided
                target = return_to or str(request.url)
                login_headers = await self.login_headers(return_to=target)
                raise HTTPException(status_code=307, headers=login_headers)
            raise HTTPException(status_code=401, detail="Not authenticated")

        try:
            token_data = await self.client.exchange_refresh_token(refresh_token)
            return token_data
        except Exception:
            if redirect_on_fail:
                target = return_to or str(request.url)
                login_headers = await self.login_headers(return_to=target)
                raise HTTPException(status_code=307, headers=login_headers)
            raise HTTPException(status_code=401, detail="Session expired")

    async def _secure_impl(
        self,
        request: Request,
        response: Response,
        redirect_on_fail: bool,
        return_to: Optional[str] = None
    ):
        # We already handle exceptions in _handle_request
        token_data = await self._handle_request(
            request=request,
            redirect_on_fail=redirect_on_fail,
            return_to=return_to
        )
        self._set_cookies(response, token_data)
        return token_data.get("fields", token_data)

    def secure(self, redirect_on_fail: bool = False, return_to: Optional[str] = None):
        """
        Returns a dependency that enforces authentication.

        :param redirect_on_fail: If True, redirect to login on failure.
                                 If False, raise 401 HTTPException.
        :param return_to: The URL to redirect to after successful login.
                          If None, it will redirect back to the current request URL.
        """
        async def dependency(request: Request, response: Response) -> Dict[str, Any]:
            return await self._secure_impl(request, response, redirect_on_fail, return_to)
        return dependency

    # Allows using `Depends(auth)` directly for default behavior (no redirect).
    async def __call__(self, request: Request, response: Response) -> Dict[str, Any]:
        return await self._secure_impl(request, response, redirect_on_fail=False)

    # --- Helpers ---

    def _check_init(self):
        if not self.client:
            raise RuntimeError("TapLock client not initialized. Please call init_* method in your FastAPI lifespan.")

    def _set_cookies(self, response: Response, token_data: Dict[str, Any]):
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        if access_token:
            response.set_cookie(
                key=self.access_token_cookie,
                value=access_token,
                httponly=True,
                secure=True,
                samesite="lax"
            )

        if refresh_token:
            response.set_cookie(
                key=self.refresh_token_cookie,
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite="lax"
            )

class TapLockMiddleware(BaseHTTPMiddleware):
    auth: TapLock
    redirect_on_fail: bool
    return_to: Optional[str] = None
    def __init__(self, app: ASGIApp, auth: TapLock, *, redirect_on_fail: bool = False, return_to: Optional[str] = None):
        super().__init__(app)
        self.auth = auth
        self.redirect_on_fail = redirect_on_fail
        self.return_to = return_to

    async def dispatch(self, request, call_next) -> Response:
        if request.url.path == self.auth.callback_endpoint:
            response = await self.auth.callback(request)
            return response

        try:
            token_data = await self.auth._handle_request(request, redirect_on_fail=self.redirect_on_fail, return_to=self.return_to)
        except HTTPException as http_exception:
            return JSONResponse(
                content= {"detail": http_exception.detail} if http_exception.detail  else {"detail": "unauthorized"},
                status_code=http_exception.status_code,
                headers=http_exception.headers,
            )

        response = await call_next(request)
        self.auth._set_cookies(response, token_data)
        return response
