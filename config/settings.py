from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    # API Settings
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False
    PROJECT_NAME: str = "Qode Auth Services"
    VERSION: str = "1.0.0"
    DATABASE_ECHO: bool = False

    DATABASE_URL: str
    DB_URL_QODEINVEST: str
    DB_URL_QODEPORTFOLIO: str
    DATABASE_ASYNC_URL: Optional[str] = None

    # SECURITY: SECRET_KEY / JWT_SECRET MUST be supplied by the environment.
    # Previous code defaulted to `secrets.token_urlsafe(32)` which regenerated
    # a new key on every process start, invalidating every signed token after
    # each deploy/restart. Read JWT_SECRET (preferred) or SECRET_KEY from env;
    # the application will fail loudly at startup (see lifespan in main.py)
    # if neither is supplied, rather than silently using an ephemeral key.
    JWT_SECRET: Optional[str] = None
    SECRET_KEY: Optional[str] = None

    # Asymmetric JWT keypair (RS256). Required.
    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str
    ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    REDIS_URL: str = "redis://localhost:6379"

    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    DEFAULT_ADMIN_EMAIL: str = "admin@qode360.com"
    # SECURITY: removed hardcoded "admin123" default. Required from env.
    DEFAULT_ADMIN_PASSWORD: Optional[str] = None

    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100

    MICROSOFT_CLIENT_ID: Optional[str] = None
    MICROSOFT_CLIENT_SECRET: Optional[str] = None
    MICROSOFT_TENANT_ID: Optional[str] = None

    RESEND_API_KEY: Optional[str] = None
    FUNDAMENTAL_SQLITE_DATA: Optional[str] = None
    SHARE_PRICE_SQLITE_DATA: Optional[str] = None
    INDICATOR_SQLITE_DATA: Optional[str] = None

    TWO_FACTOR_API_KEY: Optional[str] = None
    # Base URL for the 2Factor.in OTP gateway (per-environment).
    TWO_FACTOR_API_URL: str = "https://2factor.in/API/V1"

    # ── App-store reviewer OTP bypass (Strategy B from LAUNCH_CHECKLIST.md §6) ──
    # When BOTH env vars are set, the OTP service short-circuits for the
    # configured phone: send_otp returns success without dispatching an SMS,
    # and verify_otp accepts the static REVIEWER_OTP without hitting 2Factor.
    # Disable post-review by clearing the env vars — this is a static backdoor.
    # REVIEWER_PHONE is the full digits-only E.164 (e.g. "919999999999").
    REVIEWER_PHONE: Optional[str] = None
    REVIEWER_OTP: Optional[str] = None

    # Finsense/Finvu AA API
    AA_BASE_URL_UAT: Optional[str] = None
    AA_BASE_URL_PROD: Optional[str] = None
    AA_USER_ID: Optional[str] = None
    AA_PASSWORD: Optional[str] = None
    AA_FIU_ID: Optional[str] = None
    AA_CHANNEL_ID: Optional[str] = None
    AA_ENVIRONMENT: Optional[str] = None

    # Consent approval: URL to call for actual approval (runs in background). Leave None to only simulate.
    CONSENT_APPROVAL_URL: Optional[str] = None
    CONSENT_APPROVAL_TIMEOUT_SECONDS: int = 300
    CONSENT_JOB_TTL_SECONDS: int = 3600
    ADMIN_AUTH_ID: str

    class Config:
        env_file = ".env"
        extra = "ignore"

    def model_post_init(self, __context) -> None:
        """Resolve the symmetric secret used for non-JWT signing helpers.

        Order of precedence:
          1. JWT_SECRET  (canonical name across services)
          2. SECRET_KEY  (legacy name retained for backwards compat)
        Either must be provided in the environment. We never fall back to
        a randomly generated value, because that would silently invalidate
        every existing token on every restart.
        """
        if not self.JWT_SECRET and not self.SECRET_KEY:
            # Defer raising to the FastAPI lifespan so the standard
            # "missing required env var" error path produces a clean message
            # — leaving SECRET_KEY as None here is fine; main.py validates.
            return
        # Mirror the value so legacy code paths reading SECRET_KEY keep working.
        if self.JWT_SECRET and not self.SECRET_KEY:
            object.__setattr__(self, "SECRET_KEY", self.JWT_SECRET)
        if self.SECRET_KEY and not self.JWT_SECRET:
            object.__setattr__(self, "JWT_SECRET", self.SECRET_KEY)


settings = Settings()