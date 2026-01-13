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

#######################################
# OAUTH PROVIDER
#######################################
class AuthProviderEnum(str, Enum):
    LOCAL = "local"
    GOOGLE = "google"
    GITHUB = "github"
    FACEBOOK = "facebook"


# helpers
def now_tz():
    return datetime.now(timezone.utc)

#######################################
# USER (Account identity shared across all applications)
#######################################
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    uuid = Column(PG_UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name = Column(String(100))

    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user_applications = relationship(
        "UserApplication", back_populates="user", cascade="all, delete-orphan"
    )
    sessions = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )


#######################################
# USER APPLICATION (User scoped to a frontend Application)
#######################################
class UserApplication(Base):
    __tablename__ = "user_applications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    application_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", back_populates="user_applications")
    application = relationship("Application", back_populates="user_applications")
    auth_methods = relationship("AuthMethod", back_populates="user_application", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("user_id", "application_id", name="uq_user_application"),
        Index('ix_userapplications_uid_app', 'user_id', 'application_id'),
    )


#######################################
# AUTH METHOD (one per provider/user_application)
#######################################
class AuthMethod(Base):
    __tablename__ = "auth_methods"

    id = Column(Integer, primary_key=True)
    user_application_id = Column(Integer, ForeignKey("user_applications.id", ondelete="CASCADE"), nullable=False)

    provider = Column(
        SAEnum(AuthProviderEnum, name="auth_provider_enum"),
        nullable=False
    )

    provider_user_id = Column(String(255))  # OAuth only
    is_primary = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user_application = relationship("UserApplication", back_populates="auth_methods")
    credential = relationship(
        "UserCredential", uselist=False, back_populates="auth_method", cascade="all, delete-orphan"
    )
    oauth_account = relationship(
        "OAuthAccount", uselist=False, back_populates="auth_method", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("user_application_id", "provider", name="uq_userapp_provider"),
        UniqueConstraint("provider", "provider_user_id", name="uq_provider_user_id"),
        Index('ix_authmethod_provider', 'provider'),
    )


#######################################
# USER CREDENTIAL (Store per-auth-method password hash)
#######################################
class UserCredential(Base):
    __tablename__ = "user_credentials"

    id = Column(Integer, primary_key=True)
    auth_method_id = Column(
        Integer, ForeignKey("auth_methods.id", ondelete="CASCADE"),
        unique=True, nullable=False
    )

    password_hash = Column(String(255), nullable=False)
    password_algo = Column(String(50), default="bcrypt")

    failed_attempts = Column(Integer, default=0)
    is_locked = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    auth_method = relationship("AuthMethod", back_populates="credential")


#######################################
# OAUTH ACCOUNT (Store OAuth tokens)
#######################################
class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"

    id = Column(Integer, primary_key=True)
    auth_method_id = Column(
        Integer, ForeignKey("auth_methods.id", ondelete="CASCADE"),
        unique=True, nullable=False
    )

    access_token = Column(Text)
    refresh_token = Column(Text)
    expires_at = Column(DateTime(timezone=True))
    provider_payload = Column(JSONB)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    auth_method = relationship("AuthMethod", back_populates="oauth_account")


#######################################
# SERVICE (Backend service key)
#######################################
class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True)

    name = Column(String(100), unique=True, nullable=False)
    service_key = Column(String(64), unique=True, nullable=False)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    application_services = relationship(
        "ApplicationService",
        back_populates="service",
        cascade="all, delete-orphan"
    )
    service_account_permissions = relationship(
        "ServiceAccountPermission",
        back_populates="service",
        cascade="all, delete-orphan"
    )


#######################################
# APPLICATION (Frontend service key)
#######################################
class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True)

    name = Column(String(100), unique=True, nullable=False)
    client_id = Column(String(64), unique=True, nullable=False)
    client_secret = Column(String(128), nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    allowed_services = relationship(
        "ApplicationService",
        cascade="all, delete-orphan",
        back_populates="application"
    )
    user_applications = relationship(
        "UserApplication",
        cascade="all, delete-orphan",
        back_populates="application"
    )


#######################################
# APPLICATION SERVICE (Relation of frontend and backend services)
#######################################
class ApplicationService(Base):
    __tablename__ = "application_services"

    application_id = Column(
        Integer, ForeignKey("applications.id", ondelete="CASCADE"),
        primary_key=True
    )
    service_id = Column(
        Integer, ForeignKey("services.id", ondelete="CASCADE"),
        primary_key=True
    )

    granted_at = Column(DateTime(timezone=True), server_default=func.now())

    application = relationship("Application", back_populates="allowed_services")
    service = relationship("Service", back_populates="application_services")


#######################################
# USER SESSION (User session data)
#######################################
class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    refresh_token_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    ip_address = Column(String(45))
    user_agent = Column(Text)

    is_revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index('ix_user_sessions_user_id', 'user_id'),
        Index('ix_user_sessions_expires_at', 'expires_at'),
    )


#######################################
# JWT BLACKLIST (JWT blacklisted tokens)
#######################################
class JWTBlacklist(Base):
    __tablename__ = "jwt_blacklist"

    jti = Column(PG_UUID(as_uuid=True), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))

    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index('ix_jwt_blacklist_expires_at', 'expires_at'),
    )


#######################################
# SERVICE ACCOUNT (For backend service-to-service communication)
#######################################
class ServiceAccount(Base):
    __tablename__ = "service_accounts"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)

    client_id = Column(String(64), unique=True, nullable=False)
    client_secret = Column(String(128), nullable=False)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    allowed_services = relationship(
        "ServiceAccountPermission",
        back_populates="service_account",
        cascade="all, delete-orphan"
    )


#######################################
# SERVICE ACCOUNT PERMISSION (Proper join table instead of JSONB)
#######################################
class ServiceAccountPermission(Base):
    __tablename__ = "service_account_permissions"

    service_account_id = Column(
        Integer, ForeignKey("service_accounts.id", ondelete="CASCADE"),
        primary_key=True
    )
    service_id = Column(
        Integer, ForeignKey("services.id", ondelete="CASCADE"),
        primary_key=True
    )

    granted_at = Column(DateTime(timezone=True), server_default=func.now())

    service_account = relationship("ServiceAccount", back_populates="allowed_services")
    service = relationship("Service", back_populates="service_account_permissions")