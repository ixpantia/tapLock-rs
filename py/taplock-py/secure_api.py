
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI

from taplock import TapLock

load_dotenv()

# 1. Instantiate globally (Sync)
auth = TapLock()

# 2. Configure in Lifespan (Async)
@asynccontextmanager
async def lifespan(app: FastAPI):
    await auth.init_google(
        client_id=os.getenv("CLIENT_ID"),
        client_secret=os.getenv("CLIENT_SECRET"),
        app_url="http://localhost:3000/" # Note the /auth prefix if you mount it there
    )
    yield

app = FastAPI(lifespan=lifespan)

# 3. Add Routes (Login, Callback, Logout are now live at /auth/...)
app.include_router(auth.router, tags=["Auth"])

# 4. Protect Endpoints
@app.get("/dashboard-json-error")
async def dashboard_json_error(user: dict = Depends(auth)):
    """This endpoint will return a 401 JSON error if not authenticated."""
    return {"message": f"Welcome back!", "user": user}


@app.get("/dashboard-redirect")
async def dashboard_redirect(user: dict = Depends(auth.secure(redirect_on_fail=True))):
    """This endpoint will redirect to the login page if not authenticated."""
    return {"message": f"Welcome back!", "user": user}
