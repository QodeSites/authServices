from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator,ValidationInfo, UUID4
from pydantic.generics import GenericModel
from typing import Generic, TypeVar, Optional, List, Dict, Any, Union
from datetime import datetime
from decimal import Decimal
from enum import Enum
from uuid import UUID

T = TypeVar("T")


# Auth Schemas
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    email: str
    password: str

class TokenData(BaseModel):
    email: Optional[str] = None

class ResponseModel(GenericModel, Generic[T]):
    message: str
    data: Optional[T] = None
    errors: Optional[T] = None

    class Config:
        from_attributes = True
