from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional
import logging

from db.session import get_db
from services.jwt_service import JWTService
from services.auth_service import AuthService
from models.models import User, Application
from config.settings import settings

logger = logging.getLogger(__name__)
security = HTTPBearer()


def get_auth_service(db: Session = Depends(get_db)) -> AuthService:
    """Dependency to get auth service"""
    return AuthService(db)


def get_jwt_service(db: Session = Depends(get_db)) -> JWTService:
    """Dependency to get JWT service"""
    return JWTService(db)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Dependency to get current authenticated user from access token"""
    token = credentials.credentials
    jwt_service = JWTService(db)
    
    payload = jwt_service.verify_token(token, token_type="access")
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    user_id = int(payload.get("sub"))
    auth_service = AuthService(db)
    user = auth_service.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Dependency to get current user but return None if not authenticated"""
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None

async def verify_admin(
    x_admin_auth_id: Optional[str] = Header(None, alias="x-admin-auth-id"),
) -> str:
    """Dependency to verify admin credentials from headers."""
    if not x_admin_auth_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-Admin-Auth-Id header")
    if x_admin_auth_id != settings.ADMIN_AUTH_ID:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-Admin-Auth-Id header")
    return True
    
async def verify_application(
    x_client_id: Optional[str] = Header(None, alias="x-client-id"),
    request: Request = None,
    db: Session = Depends(get_db)
) -> Application:
    """
    Dependency to verify application credentials from headers.

    Accepts x-client-id header with case-insensitive lookup.
    """
    client_id = x_client_id

    # Fallback to request headers with case-insensitive lookup if not found
    if not client_id and request:
        client_id = request.headers.get("x-client-id") or request.headers.get("X-Client-Id")

    if not client_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Client-Id header",
        )

    auth_service = AuthService(db)
    application = auth_service.verify_application_credentials(client_id)

    if not application:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid application credentials"
        )

    return application


async def verify_service_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> dict:
    """Dependency to verify service-to-service token"""
    token = credentials.credentials
    jwt_service = JWTService(db)
    
    payload = jwt_service.verify_token(token, token_type="service")
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired service token"
        )
    
    return payload