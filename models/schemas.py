from pydantic import BaseModel, EmailStr, Field, validator, ConfigDict
from pydantic.generics import GenericModel
from typing import Generic, TypeVar, Optional, List, Dict, Any
from datetime import datetime
from models.models import AuthProviderEnum

T = TypeVar("T")    

# ==================== Generalized Response Model ====================

class ResponseModel(GenericModel, Generic[T]):
    message: str
    data: Optional[T] = None
    errors: Optional[Any] = None

    class Config:
        from_attributes = True

# ==================== Auth Schemas ====================

class UserRegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = Field(None, max_length=100)
    client_id: str
    client_secret: str

    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric (underscores and hyphens allowed)')
        return v

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str
    client_id: str
    client_secret: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    user: Dict[str, Any]

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8)
    client_id: str
    client_secret: str

class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None

# ==================== User Schemas ====================

class UserResponse(BaseModel):
    id: int
    uuid: str  # keep as str in schema for serialization

    email: str
    username: str
    full_name: Optional[str]
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UserProfileResponse(BaseModel):
    id: int
    uuid: str
    email: str
    username: str
    full_name: Optional[str]
    is_active: bool
    is_verified: bool
    created_at: datetime
    applications: List[Dict[str, Any]]

    model_config = ConfigDict(from_attributes=True)

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(None, max_length=100)
    username: Optional[str] = Field(None, min_length=3, max_length=50)

    @validator('username')
    def username_alphanumeric(cls, v):
        if v and not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric (underscores and hyphens allowed)')
        return v

# ==================== Session Schemas ====================

class SessionResponse(BaseModel):
    id: int
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: str
    expires_at: str

class SessionsListResponse(BaseModel):
    sessions: List[SessionResponse]
    total: int

class RevokeSessionRequest(BaseModel):
    session_id: int

# ==================== Service Schemas ====================

class ServiceTokenRequest(BaseModel):
    client_id: str
    client_secret: str

class ServiceTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    service_name: str
    allowed_services: List[str]

# ==================== Admin Schemas ====================

class UnlockAccountRequest(BaseModel):
    user_id: int
    application_id: int

class CreateApplicationRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)

class ApplicationResponse(BaseModel):
    id: int
    name: str
    client_id: str
    client_secret: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class CreateServiceRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)

class ServiceResponse(BaseModel):
    id: int
    name: str
    service_key: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# ==================== General Schemas ====================

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None


class OAuthLoginRequest(BaseModel):
    provider: AuthProviderEnum
    provider_user_id: str
    email: str
    username: str
    full_name: Optional[str] = None
    oauth_payload: Optional[Dict[str, Any]] = None
