import jwt  # PyJWT
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any, List
from sqlalchemy.orm import Session

from config.settings import settings
from models.models import User, JWTBlacklist, UserSession


class JWTService:
    """Handles JWT token creation, validation, and revocation"""

    def __init__(self, db: Session):
        self.db = db
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.ALGORITHM
        self.access_token_expire = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire = settings.REFRESH_TOKEN_EXPIRE_DAYS

    def create_access_token(
        self,
        user_id: int,
        application_id: Optional[int] = None,
        user_application_id: Optional[int] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create an access token"""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=self.access_token_expire)

        payload = {
            "sub": str(user_id),
            "type": "access",
            "jti": str(uuid.uuid4()),
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }

        if application_id:
            payload["app_id"] = application_id

        if user_application_id:
            payload["user_app_id"] = user_application_id

        if additional_claims:
            payload.update(additional_claims)

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        # PyJWT returns bytes in v1.x, str in v2.x: ensure string
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token

    def create_refresh_token(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """Create a refresh token and store session"""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=self.refresh_token_expire)

        payload = {
            "sub": str(user_id),
            "type": "refresh",
            "jti": str(uuid.uuid4()),
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        # Hash the token for storage
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Store session
        session = UserSession(
            user_id=user_id,
            refresh_token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            is_revoked=False
        )
        self.db.add(session)
        self.db.commit()

        return token

    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify and decode a token"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )

            # Verify token type
            if payload.get("type") != token_type:
                return None

            # Check if token is blacklisted (only for access tokens)
            if token_type == "access":
                jti = payload.get("jti")
                if jti:
                    is_blacklisted = self.db.query(JWTBlacklist).filter(
                        JWTBlacklist.jti == uuid.UUID(jti)
                    ).first()

                    if is_blacklisted:
                        return None

            # Check if refresh token session is valid
            if token_type == "refresh":
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                session = self.db.query(UserSession).filter(
                    UserSession.refresh_token_hash == token_hash,
                    UserSession.is_revoked == False,
                    UserSession.expires_at > datetime.now(timezone.utc)
                ).first()

                if not session:
                    return None

            return payload

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None

    def revoke_access_token(self, token: str, user_id: Optional[int] = None) -> bool:
        """Revoke an access token by adding it to blacklist"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False}
            )

            jti = payload.get("jti")
            exp = payload.get("exp")

            if not jti or not exp:
                return False

            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)

            blacklist_entry = JWTBlacklist(
                jti=uuid.UUID(jti),
                user_id=user_id or int(payload.get("sub")),
                expires_at=expires_at
            )

            self.db.add(blacklist_entry)
            self.db.commit()

            return True

        except Exception:
            self.db.rollback()
            return False

    def revoke_refresh_token(self, token: str) -> bool:
        """Revoke a refresh token by marking session as revoked"""
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            session = self.db.query(UserSession).filter(
                UserSession.refresh_token_hash == token_hash,
                UserSession.is_revoked == False
            ).first()

            if session:
                session.is_revoked = True
                session.revoked_at = datetime.now(timezone.utc)
                self.db.commit()
                return True

            return False
        except Exception:
            self.db.rollback()
            return False

    def revoke_all_user_sessions(self, user_id: int) -> int:
        """Revoke all active sessions for a user"""
        try:
            sessions = self.db.query(UserSession).filter(
                UserSession.user_id == user_id,
                UserSession.is_revoked == False
            ).all()

            count = 0
            now = datetime.now(timezone.utc)
            for session in sessions:
                session.is_revoked = True
                session.revoked_at = now
                count += 1

            self.db.commit()
            return count
        except Exception:
            self.db.rollback()
            return 0

    # def create_service_token(
    #     self,
    #     service_account_id: int,
    #     allowed_services: List[str]
    # ) -> str:
    #     """Create a token for service-to-service communication"""
    #     now = datetime.now(timezone.utc)
    #     expires_at = now + timedelta(hours=1)

    #     payload = {
    #         "sub": f"service:{service_account_id}",
    #         "type": "service",
    #         "service_name": service_name,
    #         "allowed_services": allowed_services,
    #         "jti": str(uuid.uuid4()),
    #         "iat": int(now.timestamp()),
    #         "exp": int(expires_at.timestamp()),
    #     }

    #     token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    #     return token

    def get_user_active_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all active sessions for a user"""
        sessions = self.db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_revoked == False,
            UserSession.expires_at > datetime.now(timezone.utc)
        ).order_by(UserSession.created_at.desc()).all()

        return [
            {
                "id": session.id,
                "ip_address": session.ip_address,
                "user_agent": session.user_agent,
                "created_at": session.created_at.isoformat(),
                "expires_at": session.expires_at.isoformat()
            }
            for session in sessions
        ]

    def cleanup_expired_tokens(self) -> Dict[str, int]:
        """Clean up expired tokens from blacklist"""
        try:
            now = datetime.now(timezone.utc)

            # Delete expired blacklist entries
            blacklist_deleted = self.db.query(JWTBlacklist).filter(
                JWTBlacklist.expires_at < now
            ).delete()

            # Delete expired sessions
            sessions_deleted = self.db.query(UserSession).filter(
                UserSession.expires_at < now
            ).delete()

            self.db.commit()

            return {
                "blacklist_deleted": blacklist_deleted,
                "sessions_deleted": sessions_deleted
            }
        except Exception:
            self.db.rollback()
            return {"blacklist_deleted": 0, "sessions_deleted": 0}