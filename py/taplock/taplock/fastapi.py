
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from .taplock import (
    get_access_token_cookie_name,
    get_refresh_token_cookie_name,
    get_taplock_callback_endpoint,
    initialize_entra_id,
    initialize_google,
    initialize_keycloak,
)


class TapLock:
    def __init__(self):
        self.client = None
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

    # --- Route Handlers ---

    async def login(self) -> RedirectResponse:
        self._check_init()
        return RedirectResponse(self.client.get_authorization_url())

    async def callback(self, request: Request, response: Response) -> Dict[str, Any]:
        self._check_init()
        code = request.query_params.get("code")
        if not code:
            raise HTTPException(status_code=400, detail="Authorization code not found")

        try:
            token_data = await self.client.exchange_code(code)
        except Exception as e:
             raise HTTPException(status_code=400, detail=f"Failed to exchange code: {str(e)}")

        self._set_cookies(response, token_data)
        return token_data

    async def logout(self, response: Response):
        """Clears the authentication cookies."""
        response.delete_cookie(self.access_token_cookie)
        response.delete_cookie(self.refresh_token_cookie)
        return {"message": "Logged out"}

    # --- Dependency ---

    async def _secure_impl(self, request: Request, response: Response, redirect_on_fail: bool):
        self._check_init()
        access_token = request.cookies.get(self.access_token_cookie)

        if access_token:
            try:
                user_data = self.client.decode_access_token(access_token)
                return user_data.get("fields", user_data)
            except Exception:
                pass # Token invalid, try refresh

        refresh_token = request.cookies.get(self.refresh_token_cookie)
        if not refresh_token:
            if redirect_on_fail:
                login_response = await self.login()
                raise HTTPException(status_code=307, headers={"Location": login_response.headers["location"]})
            raise HTTPException(status_code=401, detail="Not authenticated")

        try:
            token_data = await self.client.exchange_refresh_token(refresh_token)
            self._set_cookies(response, token_data)
            return token_data.get("fields", token_data)
        except Exception:
            if redirect_on_fail:
                login_response = await self.login()
                raise HTTPException(status_code=307, headers={"Location": login_response.headers["location"]})
            raise HTTPException(status_code=401, detail="Session expired")

    def secure(self, redirect_on_fail: bool = False):
        """
        Returns a dependency that enforces authentication.

        :param redirect_on_fail: If True, redirect to login on failure.
                                 If False, raise 401 HTTPException.
        """
        async def dependency(request: Request, response: Response) -> Dict[str, Any]:
            return await self._secure_impl(request, response, redirect_on_fail)
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
