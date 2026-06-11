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
import re

from db.session import get_db

logger = logging.getLogger(__name__)
from models.schemas import (
    ResponseModel,
    UserRegisterRequest,
    UserLoginRequest,
    ChangePasswordRequest,
    SetPasswordRequest,
    UnlockAccountRequest,
    TokenResponse,
    RefreshTokenRequest,
    LogoutRequest,
    OAuthLoginRequest,
    UserResponse
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


def _normalize_phone_code(phone_code: str) -> str:
    """Canonicalise phone_code: strip whitespace and any leading '+'.

    Historically rows have been written with both '+91' and '91' depending on
    which frontend created them, which broke exact-match lookups in
    otp_auth_verify (P0-3). Single canonical form going forward is the
    digits-only string.
    """
    return (phone_code or "").strip().lstrip("+")


@router.post(
    "/register/",
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
    "/login/",
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
    if not data.email:
        raise HTTPException(
            status_code=400,
            detail="Email is required for password login. Use OTP or OAuth for other identifiers.",
        )
    auth_service = AuthService(db)
    jwt_service = JWTService(db)
    user, user_application, error = auth_service.authenticate_user(
        email=data.email,
        password=data.password,
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

@router.post(
    "/oauth-login/",
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
    "/otp/send/",
    response_model=ResponseModel,
    summary="Send OTP for phone authentication"
)
async def send_otp(
    phone_code : str = Body(..., embed=True),
    phone_number: str = Body(..., embed=True),
    application=Depends(verify_application),
    db: Session = Depends(get_db)
):
    """
    Send an OTP to the given phone number for authentication (login/register).
    """
    # Validate phone_number: must be a 10-digit Indian mobile number starting with 6-9.
    # Defence in depth — matches the FE validator (lib/validation.ts:validatePhone).
    if not re.match(r"^\d{10}$", phone_number):
        raise HTTPException(status_code=422, detail="Invalid phone number. Must be 10 digits.")
    if not re.match(r"^[6-9]\d{9}$", phone_number):
        raise HTTPException(status_code=422, detail="Mobile number must start with 6-9")

    # Validate phone_code: must be 1-4 digits with optional leading +
    if not re.match(r"^\+?\d{1,4}$", phone_code):
        raise HTTPException(status_code=422, detail="Invalid phone code. Must be 1-4 digits with optional leading +.")

    # Canonicalise — see _normalize_phone_code docstring (P0-3 fix).
    phone_code = _normalize_phone_code(phone_code)

    auth_service = AuthService(db)
    user, user_application, error = auth_service.otp_auth_send(
        phone_code=phone_code,
        phonenumber=phone_number,
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
        message="OTP sent successfully"
    )

@router.post(
    "/otp/verify/",
    response_model=TokenResponse,
    summary="Verify OTP and login by phone"
)
async def verify_otp(
    phone_code : str = Body(..., embed=True),
    phone_number: str = Body(..., embed=True),
    application=Depends(verify_application),
    otp: str = Body(..., embed=True),
    db: Session = Depends(get_db)
):
    """
    Verify the provided OTP for the phone number and application,
    login/register user and return access/refresh tokens.
    """
    # Validate phone_number: must be a 10-digit Indian mobile number starting with 6-9.
    # Defence in depth — matches the FE validator (lib/validation.ts:validatePhone).
    if not re.match(r"^\d{10}$", phone_number):
        raise HTTPException(status_code=422, detail="Invalid phone number. Must be 10 digits.")
    if not re.match(r"^[6-9]\d{9}$", phone_number):
        raise HTTPException(status_code=422, detail="Mobile number must start with 6-9")

    # Validate phone_code: must be 1-4 digits with optional leading +
    if not re.match(r"^\+?\d{1,4}$", phone_code):
        raise HTTPException(status_code=422, detail="Invalid phone code. Must be 1-4 digits with optional leading +.")

    # Canonicalise — see _normalize_phone_code docstring (P0-3 fix).
    phone_code = _normalize_phone_code(phone_code)

    auth_service = AuthService(db)
    user, user_application, tokens, error = auth_service.otp_auth_verify(
        phone_code=phone_code,
        phonenumber=phone_number,
        application_id=application.id,
        otp=otp
    )
    if error:
        raise HTTPException(status_code=400, detail=error)
    # Prepare user response
    from models.schemas import UserResponse
    user_dict = {**user.__dict__}
    user_dict["uuid"] = str(user.uuid)
    return TokenResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens.get("refresh_token"),
        token_type=tokens.get("token_type", "bearer"),
        user=UserResponse.model_validate(user_dict).dict()
    )

@router.post(
    "/change-password/",
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
    Change user password (requires current password).
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
    "/set-password/",
    response_model=ResponseModel,
    summary="Set or reset password (first-time setup or OTP/token-verified reset)"
)
async def set_password(
    data: SetPasswordRequest = Body(...),
    db: Session = Depends(get_db),
    application=Depends(verify_application)
):
    """
    Set or reset password. Used after OTP or token verification.
    Creates user and credential in auth service if they do not exist.
    """
    auth_service = AuthService(db)
    success, error = auth_service.set_password(
        email=data.email.strip().lower(),
        new_password=data.new_password,
        application_id=application.id
    )
    if not success:
        raise HTTPException(status_code=400, detail=error)
    return ResponseModel(success=True, data={}, message="Password set successfully")


@router.post(
    "/unlock-account/",
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
    "/refresh-token/",
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
    # Issue a new refresh token (token rotation)
    new_refresh_token = jwt_service.create_refresh_token(user_id=user_id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )


@router.post(
    "/logout/",
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
    "/logout-all/",
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
    "/me/",
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

