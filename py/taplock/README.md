# tapLock Python

`taplock` is a high-performance authentication library for FastAPI applications, powered by a Rust core. It simplifies the integration of OAuth2 providers like Google, Entra ID (Azure), and Keycloak, handling token exchange, validation, and session management via secure cookies.

## Installation

We recommend using [uv](https://github.com/astral-sh/uv) to manage your dependencies. Add `taplock` to your `pyproject.toml` by pointing to the repository:

```toml
[tool.uv.sources]
taplock = { git = "https://github.com/ixpantia/tapLock-rs.git", subdirectory = "py/taplock" }
```

Then install it:

```bash
uv add taplock
```

## Quick Start

### 1. Initialize TapLock

Instantiate `TapLock` and configure it within your FastAPI lifespan.

```python
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from taplock import TapLock

# 1. Instantiate globally
auth = TapLock()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 2. Configure in Lifespan (Async)
    # You can initialize with explicit credentials:
    # await auth.init_google(
    #     client_id=os.getenv("GOOGLE_CLIENT_ID"),
    #     client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    #     app_url="http://localhost:8000/" 
    # )
    
    # Or initialize directly from environment variables:
    await auth.init_google_from_env()
    yield

app = FastAPI(lifespan=lifespan)

# 3. Add Authentication Routes (Callback handling)
app.include_router(auth.router, tags=["Auth"])
```

### 2. Protect Endpoints using `Depends`

You can protect specific routes using FastAPI's dependency injection.

```python
from fastapi import Depends

@app.get("/dashboard")
async def dashboard(user: dict = Depends(auth)):
    """Returns 401 JSON error if not authenticated."""
    return {"message": f"Hello, {user.get('preferred_username')}"}

@app.get("/secure-page")
async def secure_page(user: dict = Depends(auth.secure(redirect_on_fail=True))):
    """Redirects to login page if not authenticated."""
    return {"message": "Welcome to the secure page"}
```

### 3. Global Protection using Middleware

If you want to protect your entire application (or sub-mounted apps), use the `TapLockMiddleware`. Note that when using the middleware, there is no need to mount the router (`app.include_router(auth.router)`).

```python
from taplock import TapLockMiddleware

# Protect everything and redirect to login if session is missing
# No need to include auth.router when using middleware
app.add_middleware(TapLockMiddleware, auth=auth, redirect_on_fail=True)
```

## Configuration Methods

`taplock` supports several providers out of the box. You can initialize them manually or from environment variables.

### Environment Variable Initialization

For ease of use, you can call `init_*_from_env()` which will look for the following variables:

| Provider | Method | Environment Variables |
|----------|--------|-----------------------|
| **Google** | `init_google_from_env()` | `TAPLOCK_GOOGLE_CLIENT_ID`, `TAPLOCK_GOOGLE_CLIENT_SECRET`, `TAPLOCK_APP_URL`, `TAPLOCK_GOOGLE_USE_REFRESH_TOKEN` (opt) |
| **Entra ID** | `init_entra_id_from_env()` | `TAPLOCK_ENTRA_ID_CLIENT_ID`, `TAPLOCK_ENTRA_ID_CLIENT_SECRET`, `TAPLOCK_ENTRA_ID_TENANT_ID`, `TAPLOCK_APP_URL`, `TAPLOCK_ENTRA_ID_USE_REFRESH_TOKEN` (opt) |
| **Keycloak** | `init_keycloak_from_env()` | `TAPLOCK_KEYCLOAK_URL`, `TAPLOCK_KEYCLOAK_REALM`, `TAPLOCK_KEYCLOAK_CLIENT_ID`, `TAPLOCK_KEYCLOAK_CLIENT_SECRET`, `TAPLOCK_APP_URL`, `TAPLOCK_KEYCLOAK_USE_REFRESH_TOKEN` (opt) |

### Manual Initialization

- **Google**: `await auth.init_google(client_id, client_secret, app_url)`
- **Entra ID**: `await auth.init_entra_id(client_id, client_secret, app_url, tenant_id)`
- **Keycloak**: `await auth.init_keycloak(client_id, client_secret, app_url, base_url, realm)`

## Features

- **Rust Core**: Token validation and cryptographic operations are handled by a high-performance Rust backend.
- **Secure Cookies**: Automatically manages `access_token` and `refresh_token` in `HttpOnly`, `Secure` cookies.
- **Automatic Refresh**: Transparently handles token refresh when the access token expires.
- **FastAPI Native**: Designed to work seamlessly with FastAPI dependencies and middleware.

## Examples

For more detailed implementations, check the [examples directory](../../examples/py-examples):
- `using_depends.py`: Fine-grained control over route protection.
- `using_middleware.py`: Global application protection.