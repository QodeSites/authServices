# from cron.schedular import start_scheduler
from db.redis import shutdown, startup
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time
import logging

from config.settings import settings
# from app.core.middleware import setup_middlewares

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def lifespan(app: FastAPI):
    # Validate required environment variables at startup. We name each
    # missing variable explicitly so operators know exactly which secret
    # to set in their .env / secret manager.
    required_env_vars = [
        "DATABASE_URL",
        "JWT_PRIVATE_KEY",
        "JWT_PUBLIC_KEY",
        "TWO_FACTOR_API_KEY",
        "ADMIN_AUTH_ID",
    ]
    missing_vars = [var for var in required_env_vars if not getattr(settings, var, None)]

    # Symmetric JWT_SECRET (or legacy SECRET_KEY) is also required and must
    # come from the environment — never the previous random default.
    if not settings.JWT_SECRET and not settings.SECRET_KEY:
        missing_vars.append("JWT_SECRET (or SECRET_KEY)")

    if missing_vars:
        error_msg = (
            "Auth service startup aborted — missing required environment "
            f"variables: {', '.join(missing_vars)}. Set them in the service "
            ".env or secret manager and restart."
        )
        logger.error(error_msg)
        raise ValueError(error_msg)

    # Call redis startup
    startup()
    # Start scheduler here to ensure it starts when the app comes up
    # start_scheduler()
    logger.info("Qode Auth Services API starting up...")
    yield
    shutdown()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    lifespan=lifespan
)

# Add CORS middleware. Origins are pulled from settings.CORS_ORIGINS so the
# allowlist is configured per-environment via .env (CORS_ORIGINS=...).
# Previously this was a hardcoded list that overrode the env-driven config.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware for production
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "*.qodeinvest.com"]
    )

# Add request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

from api.v1 import auth_router, profile_router, admin_router

app.include_router(auth_router.router,
    prefix=f"{settings.API_V1_PREFIX}/auth", tags=["auth"])
app.include_router(profile_router.router,
    prefix=f"{settings.API_V1_PREFIX}/profile", tags=["profile"])
app.include_router(admin_router.router,
    prefix=f"{settings.API_V1_PREFIX}/admin", tags=["admin"])

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": settings.VERSION}

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Qode Auth Services API",
        "version": settings.VERSION,
        "docs": f"{settings.API_V1_PREFIX}/docs"
    }

# Exception handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "Endpoint not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# The events have been moved to the lifespan function above.

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=settings.DEBUG
    )