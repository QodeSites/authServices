from pydantic_settings import BaseSettings
from typing import List, Optional
import secrets

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

    SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_SECRET_KEY: str = SECRET_KEY  
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    REDIS_URL: str = "redis://localhost:6379"

    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    DEFAULT_ADMIN_EMAIL: str = "admin@qode360.com"
    DEFAULT_ADMIN_PASSWORD: str = "admin123"

    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100

    MICROSOFT_CLIENT_ID: Optional[str] = None
    MICROSOFT_CLIENT_SECRET: Optional[str] = None
    MICROSOFT_TENANT_ID: Optional[str] = None

    RESEND_API_KEY: Optional[str] = None
    FUNDAMENTAL_SQLITE_DATA: Optional[str] = None
    SHARE_PRICE_SQLITE_DATA: Optional[str] = None
    INDICATOR_SQLITE_DATA: Optional[str] = None

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()