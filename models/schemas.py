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


    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric (underscores and hyphens allowed)')
        return v

from pydantic import field_validator

class UserLoginRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone_code: Optional[str] = None
    phone_number: Optional[str] = None
    username: Optional[str] = None
    password: str

    @field_validator("email", "phone_number", "username", mode="after")
    @classmethod
    def at_least_one_identifier(cls, v, values):
        # Only run once after all fields are parsed (mode="after")
        # Validate that at least one of email, phone_number, username is provided
        if not (values.get("email") or values.get("phone_number") or values.get("username")):
            raise ValueError("At least one of email, phone_number, or username must be provided.")
        return v

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    user: Optional[Dict[str, Any]] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8)


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None

# ==================== User Schemas ====================

from pydantic import field_validator
from uuid import UUID

class UserSchema(BaseModel):
    id: int
    uuid: str
    email: str
    username: str
    full_name: Optional[str]
    phone_code: Optional[str]
    phonenumber: Optional[str]
    pancard: Optional[str]
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator('uuid', mode='before')
    @classmethod
    def uuid_to_str(cls, v):
        if isinstance(v, UUID):
            return str(v)
        return v

class UserUpdateRequest(BaseModel):
    id: Optional[int] = None
    uuid: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    phone_code: Optional[str] = None
    phonenumber: Optional[str] = None
    pancard: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator('uuid', mode='before')
    @classmethod
    def uuid_to_str(cls, v):
        if isinstance(v, UUID):
            return str(v)
        return v

class UserResponse(BaseModel):
    id: int
    uuid: str  # keep as str in schema for serialization

    email: Optional[str]
    username: Optional[str] 
    full_name: Optional[str]
    phone_code: Optional[str]
    phonenumber: Optional[str]
    pancard:Optional[str]
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
