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
    ResponseModel,
    UserRegisterRequest,
    UserLoginRequest,
    ChangePasswordRequest,
    UnlockAccountRequest,
    TokenResponse,
    RefreshTokenRequest,
    LogoutRequest,
    OAuthLoginRequest,
    UserResponse,
    UserUpdateRequest
)
from services.auth_service import AuthService
from services.jwt_service import JWTService
from services.user_service import UserService
from utils.dependencies import (
    get_auth_service,
    get_jwt_service,
    get_current_user,
    get_current_user_optional,
    verify_application,
    verify_service_token,
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter()


@router.post(
    "/update/",
    response_model=ResponseModel,
    summary="Register a new user"
)
@router.post(
    "/update/",
    response_model=ResponseModel,
    summary="Update user profile"
)
async def update_profile(
    data: UserUpdateRequest = Body(...),
    db: Session = Depends(get_db),
    application=Depends(verify_application)
):
    """
    Update user
    """
    data_dict = data.model_dump()
    print(data_dict, "==========data")

    user_service = UserService(db)
    user, user_application, error = user_service.update_profile(data_dict, application.id)
    print(user, "============user")
    if error:
        raise HTTPException(status_code=400, detail=error)

    # Prepare user response model
    user_dict = {**user.__dict__}
    user_dict["uuid"] = str(user.uuid)
    from models.schemas import UserResponse
    user_response = UserResponse.model_validate(user_dict)

    return ResponseModel(
        success=True,
        data={
            "user": user_response
        },
        message="User updated successfully"
    )
