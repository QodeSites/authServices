from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional

from db.session import get_db
from services.jwt_service import JWTService
from services.auth_service import AuthService
from models.models import User, Application

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

async def verify_application(
    x_client_id: Optional[str] = Header(None, alias="x-client-id"),
    db: Session = Depends(get_db)
) -> Application:
    """
    Dependency to verify application credentials from headers.

    Accepts x-client-id header with any casing or client spelling.
    """
    # Try various common header names if not found
    header_names = [
        "x-client-id", "X-Client-Id", "X-CLIENT-ID",
        "X_CLIENT_ID", "x_client_id", "X-Client-ID", "x_clientid", "client_id"
    ]
    print(x_client_id,"===============================x_client_id")
    client_id = x_client_id

    if not client_id:
        # Try to extract from lowercased/misc spellings
        from fastapi import Request
        import inspect

        current_frame = inspect.currentframe()
        caller = None
        try:
            for frame_info in inspect.stack():
                local_vars = frame_info.frame.f_locals
                if "request" in local_vars:
                    caller = local_vars["request"]
                    break
            if caller and isinstance(caller, Request):
                req_headers = caller.headers
            else:
                req_headers = None
        except Exception:
            req_headers = None

        if req_headers:
            # Now check all possible spelling/casings
            for h in header_names:
                value = req_headers.get(h)
                if value:
                    client_id = value
                    break

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