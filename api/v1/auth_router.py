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

# --- New Route: OAuth Login ---
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
    OAuthLoginRequest
)
from services.auth_service import AuthService
from services.jwt_service import JWTService
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
    "/register",
    response_model=ResponseModel,
    summary="Register a new user"
)
async def register_user(
    data: UserRegisterRequest = Body(...),
    db: Session = Depends(get_db),
    application=Depends(verify_application)
):
    """
    Register a new user for the application.
    """
    auth_service = AuthService(db)
    user, user_application, error = auth_service.register_user(
        email=data.email,
        username=data.username,
        password=data.password,
        full_name=data.full_name,
        application_id=application.id
    )
    if error:
        raise HTTPException(status_code=400, detail=error)
    return ResponseModel(
        success=True,
        data={
            "user_id": user.id,
            "user_application_id": user_application.id,
        },
        message="Registration successful"
    )

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and login a user"
)
async def login_user(
    data: UserLoginRequest = Body(...),
    db: Session = Depends(get_db),
    application=Depends(verify_application),
    request: Request = None
):
    """
    Authenticate user with email and password.
    """
    auth_service = AuthService(db)
    jwt_service = JWTService(db)
    user, user_application, error = auth_service.authenticate_user(
        email=data.email,
        password=data.password,
        application_id=application.id
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
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@router.post(
    "/oauth-login",
    response_model=TokenResponse,
    summary="OAuth login or register a user"
)
async def oauth_login(
    data: OAuthLoginRequest = Body(...),
    db: Session = Depends(get_db),
    application=Depends(verify_application),
    request: Request = None,
):
    """
    OAuth login or sign up a user.
    """
    print(application,"===============================application")
    auth_service = AuthService(db)
    user, user_application, tokens, error = auth_service.auth_login(
        provider=data.provider,
        provider_user_id=data.provider_user_id,
        email=data.email,
        username=data.username,
        full_name=data.full_name,
        application_id=application.id,
        oauth_payload=data.oauth_payload,
    )
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    from models.schemas import UserResponse

    # Ensure the uuid is converted to string before passing to the schema
    user_dict = {**user.__dict__}
    user_dict["uuid"] = str(user.uuid)

    return TokenResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens.get("refresh_token"),
        token_type="bearer",
        user=UserResponse.model_validate(user_dict).dict()
    )

@router.post(
    "/change-password",
    response_model=ResponseModel,
    summary="Change password"
)
async def change_password(
    data: ChangePasswordRequest = Body(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    application=Depends(verify_application)
):
    """
    Change user password.
    """
    auth_service = AuthService(db)
    success, error = auth_service.change_password(
        user_id=user.id,
        application_id=application.id,
        old_password=data.old_password,
        new_password=data.new_password
    )
    if not success:
        raise HTTPException(status_code=400, detail=error)
    return ResponseModel(success=True, data={}, message="Password changed successfully")


@router.post(
    "/unlock-account",
    response_model=ResponseModel,
    summary="Unlock user account"
)
async def unlock_account(
    data: UnlockAccountRequest = Body(...),
    db: Session = Depends(get_db),
    application=Depends(verify_application)
):
    """
    Unlock a locked user account (admin/support endpoint).
    """
    auth_service = AuthService(db)
    success, error = auth_service.unlock_user_account(
        user_id=data.user_id,
        application_id=application.id
    )
    if not success:
        raise HTTPException(status_code=400, detail=error)
    return ResponseModel(success=True, data={}, message="User account unlocked")


@router.post(
    "/refresh-token",
    response_model=TokenResponse,
    summary="Refresh access token using refresh token"
)
async def refresh_token(
    data: RefreshTokenRequest = Body(...),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Request a new access token via refresh token.
    """
    jwt_service = JWTService(db)
    payload = jwt_service.verify_token(data.refresh_token, token_type="refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user_id = int(payload.get("sub"))
    access_token = jwt_service.create_access_token(user_id=user_id)
    return TokenResponse(
        access_token=access_token,
        refresh_token=data.refresh_token,
        token_type="bearer"
    )


@router.post(
    "/logout",
    response_model=ResponseModel,
    summary="Revoke the given refresh token (logout)"
)
async def logout(
    data: LogoutRequest = Body(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    """
    Logout user and revoke refresh token.
    """
    jwt_service = JWTService(db)
    revoked = jwt_service.revoke_refresh_token(data.refresh_token)
    if not revoked:
        raise HTTPException(status_code=400, detail="Failed to revoke session")
    return ResponseModel(success=True, data={}, message="Logged out successfully")


@router.post(
    "/logout-all",
    response_model=ResponseModel,
    summary="Log out from all sessions (revoke all active tokens)"
)
async def logout_all(
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    jwt_service = JWTService(db)
    count = jwt_service.revoke_all_user_sessions(user_id=user.id)
    return ResponseModel(
        success=True,
        data={"revoked_sessions": count},
        message="Logged out from all sessions"
    )


@router.get(
    "/me",
    response_model=ResponseModel,
    summary="Get current user info"
)
async def get_profile(user=Depends(get_current_user)):
    from models.schemas import UserSchema
    return ResponseModel(
        success=True,
        data=UserSchema.from_orm(user),
        message="Fetched current user"
    )


@router.get(
    "/sessions",
    response_model=ResponseModel,
    summary="Get active sessions for current user"
)
async def get_sessions(
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    jwt_service = JWTService(db)
    sessions = jwt_service.get_user_active_sessions(user_id=user.id)
    return ResponseModel(
        success=True,
        data=sessions,
        message="Fetched active user sessions"
    )


# @router.post(
#     "/service-token",
#     response_model=TokenResponse,
#     summary="Create token for service-to-service authentication"
# )
# async def create_service_token(
#     service_account_id: int = Body(...),
#     service_name: str = Body(...),
#     db: Session = Depends(get_db),
#     credentials: dict = Depends(verify_service_token)
# ):
#     """
#     Issue a service-to-service authentication token.
#     """
#     jwt_service = JWTService(db)
#     token = jwt_service.create_service_token(
#         service_account_id=service_account_id,
#         service_name=service_name
#     )
#     return TokenResponse(
#         access_token=token,
#         refresh_token=None,
#         token_type="service"
#     )


