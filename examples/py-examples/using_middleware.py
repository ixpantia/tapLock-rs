import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from starlette.staticfiles import StaticFiles

from taplock import TapLock, TapLockMiddleware

load_dotenv()

# 1. Instantiate globally (Sync)
auth = TapLock()

# 2. Configure in Lifespan (Async)
@asynccontextmanager
async def lifespan(app: FastAPI):
    await auth.init_google(
        client_id=os.getenv("CLIENT_ID"),
        client_secret=os.getenv("CLIENT_SECRET"),
        app_url="http://localhost:8000/" # Note the /auth prefix if you mount it there
    )
    yield

app = FastAPI(lifespan=lifespan)

# 3. Mount any endpoints or sub applications
app.mount("/", StaticFiles(directory = "./static"))

# 4. Add global middleware.
#
# The main difference between using `Depends` and the middleware is that the
# middleware applies to all endpoints and sub applications.
app.add_middleware(TapLockMiddleware, auth = auth, redirect_on_fail = True)
