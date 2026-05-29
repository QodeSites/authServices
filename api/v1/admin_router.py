from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    Path,
    Body,
    Header,
    Request
)
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
import logging

from db.session import get_db
from models.schemas import (
    AdminUserLoginRequest,
    TokenResponse,
    UserResponse
)
from services.auth_service import AuthService
from services.jwt_service import JWTService
from utils.dependencies import (

    verify_application,
    verify_admin,
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)
router = APIRouter()




@router.post(
    "/admin-login/",
    response_model=TokenResponse,
    summary="Authenticate and login a user"
)
async def admin_login(
    data: AdminUserLoginRequest = Body(...),
    db: Session = Depends(get_db),
    application=Depends(verify_application),
    verify_admin=Depends(verify_admin),
    request: Request = None
):
    """
    Authenticate admin with email and password.
    """
    client_ip = request.client.host if request else None

    # Check if ADMIN_AUTH_ID is configured
    from config.settings import settings
    if not settings.ADMIN_AUTH_ID or settings.ADMIN_AUTH_ID.strip() == "":
        logger.error(f"Admin bypass login attempted from {client_ip} but ADMIN_AUTH_ID not configured")
        raise HTTPException(
            status_code=503,
            detail="Admin bypass not configured"
        )

    # Check IP allowlist - only allow localhost/internal IPs
    allowed_ips = ["127.0.0.1", "localhost", "::1"]  # IPv4 and IPv6 loopback
    if client_ip not in allowed_ips:
        logger.warning(f"Admin bypass login attempted from non-allowed IP: {client_ip}")
        raise HTTPException(
            status_code=403,
            detail="Admin access restricted to localhost"
        )

    # Log admin bypass attempt
    logger.info(f"Admin bypass login attempt for email={data.email} from IP={client_ip}")

    if not data.email:
        raise HTTPException(
            status_code=400,
            detail="Email is required for password login. Use OTP or OAuth for other identifiers.",
        )
    auth_service = AuthService(db)
    jwt_service = JWTService(db)
    user, user_application, _tokens, error = auth_service.admin_by_pass_login(
        email=data.email,
        application_id=application.id,
    )
    if error:
        logger.warning(f"Admin bypass login failed for email={data.email}: {error}")
        raise HTTPException(status_code=400, detail=error)

    # Log successful admin bypass login
    logger.info(f"Admin bypass login successful for user_id={user.id}, email={data.email}, IP={client_ip}")

    access_token = jwt_service.create_access_token(
        user_id=user.id,
        application_id=application.id,
        user_application_id=user_application.id
    )
    refresh_token = jwt_service.create_refresh_token(
        user_id=user.id,
        ip_address=client_ip,
        user_agent=(request.headers.get("user-agent") if request else None)
    )
    user_dict = {**user.__dict__}
    user_dict["uuid"] = str(user.uuid)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user_dict).dict()
    )
