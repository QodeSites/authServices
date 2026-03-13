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
        raise HTTPException(status_code=400, detail=error)
        
    access_token = jwt_service.create_access_token(
        user_id=user.id,
        application_id=application.id,
        user_application_id=user_application.id
    )
    refresh_token = jwt_service.create_refresh_token(
        user_id=user.id,
        ip_address=(request.client.host if request else None),
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
