from enum import Enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Text, Float,
    Index, CheckConstraint, UniqueConstraint, ForeignKey
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import func
from sqlalchemy import Enum as SAEnum

from config.database import Base


# helpers
def now_tz():
    return datetime.now(timezone.utc)


class PermissionRequestStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_superuser = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


    # relationships
    departments = relationship("UserDepartment", back_populates="user", cascade="all, delete-orphan")
    permissions_created = relationship("Permission", back_populates="created_by_user", foreign_keys="Permission.created_by_id")
    permissions = relationship("Permission", back_populates="user_obj", foreign_keys="Permission.user_id")
    permission_requests = relationship("PermissionRequest", back_populates="user_obj", foreign_keys="PermissionRequest.user_id")

    __table_args__ = (
        Index('idx_users_email_active', 'email', 'is_active'),
        Index('idx_users_created_at', 'created_at'),
        CheckConstraint(
            "email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'",
            name='valid_email'
        ),
    )

    @validates('email')
    def validate_email(self, key, address):
        if not address or '@' not in address:
            raise ValueError("Invalid email address")
        return address.lower().strip()
