from typing import Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from models.models import (
    User, Application, Service, UserApplication,
    AuthMethod, UserCredential, AuthProviderEnum,
    ApplicationService, ServiceAccount, ServiceAccountPermission
)
from services.password_service import PasswordService
from services.jwt_service import JWTService

class AuthService:
    """Handles authentication logic and user verification"""
    
    def __init__(self, db: Session):
        self.db = db
        self.password_service = PasswordService()
        self.jwt_service = JWTService(db)

    def auth_login(
        self,
        provider: AuthProviderEnum,
        provider_user_id: str,
        email: str,
        username: str,
        full_name: Optional[str],
        application_id: int,
        oauth_payload: Optional[dict] = None
    ) -> Tuple[Optional[User], Optional[UserApplication], Optional[Dict[str, str]], Optional[str]]:
        """
        Login or signup a user using OAuth.
        If user does not exist, create it; otherwise, verify and return tokens.
        
        Returns: (User, UserApplication, tokens_dict, error_message)
        """
        try:
            # Step 1: Check if application exists and is active
            application = self.db.query(Application).filter(
                Application.id == application_id,
                Application.is_active == True
            ).first()
            if not application:
                return None, None, None, "Application not found or inactive"
            
            # Step 2: Try to find a user with this email
            user = self.db.query(User).filter(
                User.email == email
            ).first()

            is_new_user = False

            if not user:
                # If not found by email, try by username (rare for oauth but prevent dup)
                user = self.db.query(User).filter(
                    User.username == username
                ).first()

            if not user:
                # No user exists. Create one.
                user = User(
                    email=email,
                    username=username,
                    full_name=full_name,
                    is_active=True,
                    is_verified=True  # Oauth assumed verified
                )
                self.db.add(user)
                self.db.flush()
                is_new_user = True

            # Step 3: See if user is registered for the application
            user_application = self.db.query(UserApplication).filter(
                UserApplication.user_id == user.id,
                UserApplication.application_id == application_id
            ).first()

            if not user_application:
                # Register user to application
                user_application = UserApplication(
                    user_id=user.id,
                    application_id=application_id
                )
                self.db.add(user_application)
                self.db.flush()

            # Step 4: Find or create AuthMethod for the provider
            auth_method = self.db.query(AuthMethod).filter(
                AuthMethod.user_application_id == user_application.id,
                AuthMethod.provider == provider
            ).first()

            if not auth_method:
                # Create auth_method for this provider
                auth_method = AuthMethod(
                    user_application_id=user_application.id,
                    provider=provider,
                    provider_user_id=provider_user_id,
                    is_primary=is_new_user  # Make primary if first login
                )
                self.db.add(auth_method)
                self.db.flush()
            else:
                # Update provider_user_id if changed
                if (provider_user_id and auth_method.provider_user_id != provider_user_id):
                    auth_method.provider_user_id = provider_user_id
                
            # Step 5: Create/update OAuthAccount (if applicable)
            if oauth_payload is not None:
                from models.models import OAuthAccount
                oauth_account = self.db.query(OAuthAccount).filter(
                    OAuthAccount.auth_method_id == auth_method.id
                ).first()
                if not oauth_account:
                    oauth_account = OAuthAccount(
                        auth_method_id=auth_method.id,
                        provider_payload=oauth_payload,
                        updated_at=datetime.now(timezone.utc)
                    )
                    self.db.add(oauth_account)
                else:
                    oauth_account.provider_payload = oauth_payload
                    oauth_account.updated_at = datetime.now(timezone.utc)

            self.db.commit()
            self.db.refresh(user)
            self.db.refresh(user_application)

            access_token = self.jwt_service.create_access_token(
                user_id=user.id,
                application_id=user_application.application_id,
                user_application_id=user_application.id
            )
            refresh_token = self.jwt_service.create_refresh_token(
                user_id=user.id
            )
            tokens = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer"
            }

            return user, user_application, tokens, None
        except Exception as e:
            self.db.rollback()
            return None, None, None, f"OAuth authentication failed: {str(e)}"

    def register_user(
        self,
        email: str,
        username: str,
        password: str,
        full_name: Optional[str],
        application_id: int
    ) -> Tuple[Optional[User], Optional[UserApplication], Optional[str]]:
        """
        Register a new user
        Returns: (User, UserApplication, error_message)
        """
        try:
            # Validate password strength
            is_valid, error_msg = self.password_service.validate_password_strength(password)
            if not is_valid:
                return None, None, error_msg
            
            # Check if application exists
            application = self.db.query(Application).filter(
                Application.id == application_id,
                Application.is_active == True
            ).first()
            
            if not application:
                return None, None, "Application not found or inactive"
            
            # Check if user with email already exists
            existing_user = self.db.query(User).filter(
                User.email == email
            ).first()
            
            if existing_user:
                # Check if user already registered for this application
                existing_user_app = self.db.query(UserApplication).filter(
                    UserApplication.user_id == existing_user.id,
                    UserApplication.application_id == application_id
                ).first()
                
                if existing_user_app:
                    return None, None, "User already registered for this application"
                
                # Create UserApplication for existing user
                user = existing_user
            else:
                # Check if username is taken
                existing_username = self.db.query(User).filter(
                    User.username == username
                ).first()
                
                if existing_username:
                    return None, None, "Username already taken"
                
                # Create new user
                user = User(
                    email=email,
                    username=username,
                    full_name=full_name,
                    is_active=True,
                    is_verified=False
                )
                self.db.add(user)
                self.db.flush()
            
            # Create UserApplication
            user_application = UserApplication(
                user_id=user.id,
                application_id=application_id
            )
            self.db.add(user_application)
            self.db.flush()
            
            # Create AuthMethod for local provider
            auth_method = AuthMethod(
                user_application_id=user_application.id,
                provider=AuthProviderEnum.LOCAL,
                is_primary=True
            )
            self.db.add(auth_method)
            self.db.flush()
            
            # Hash password and create credential
            password_hash, algo = self.password_service.hash_password(password)
            credential = UserCredential(
                auth_method_id=auth_method.id,
                password_hash=password_hash,
                password_algo=algo
            )
            self.db.add(credential)
            
            self.db.commit()
            self.db.refresh(user)
            self.db.refresh(user_application)
            
            return user, user_application, None
            
        except Exception as e:
            self.db.rollback()
            return None, None, f"Registration failed: {str(e)}"
    
    def authenticate_user(
        self,
        email: str,
        password: str,
        application_id: int
    ) -> Tuple[Optional[User], Optional[UserApplication], Optional[str]]:
        """
        Authenticate a user with email and password
        Returns: (User, UserApplication, error_message)
        """
        try:
            # Find user
            user = self.db.query(User).filter(
                User.email == email,
                User.is_active == True
            ).first()
            
            if not user:
                return None, None, "Invalid credentials"
            
            # Find user application
            user_application = self.db.query(UserApplication).filter(
                UserApplication.user_id == user.id,
                UserApplication.application_id == application_id
            ).first()
            
            if not user_application:
                return None, None, "User not registered for this application"
            
            # Find auth method
            auth_method = self.db.query(AuthMethod).filter(
                AuthMethod.user_application_id == user_application.id,
                AuthMethod.provider == AuthProviderEnum.LOCAL
            ).first()
            
            if not auth_method:
                return None, None, "Authentication method not found"
            
            # Get credential
            credential = self.db.query(UserCredential).filter(
                UserCredential.auth_method_id == auth_method.id
            ).first()
            
            if not credential:
                return None, None, "Credentials not found"
            
            # Check if account is locked
            if credential.is_locked:
                return None, None, "Account is locked due to too many failed attempts. Please contact support."
            
            # Verify password
            if not self.password_service.verify_password(password, credential.password_hash):
                # Increment failed attempts
                credential.failed_attempts += 1
                if credential.failed_attempts >= 5:
                    credential.is_locked = True
                self.db.commit()
                
                remaining = 5 - credential.failed_attempts
                if remaining > 0:
                    return None, None, f"Invalid credentials. {remaining} attempts remaining."
                else:
                    return None, None, "Account locked due to too many failed attempts."
            
            # Reset failed attempts on successful login
            credential.failed_attempts = 0
            self.db.commit()
            
            return user, user_application, None
            
        except Exception as e:
            self.db.rollback()
            return None, None, f"Authentication failed: {str(e)}"
    
    def verify_application_credentials(
        self,
        client_id: str,
    ) -> Optional[Application]:
        """Verify application credentials"""
        application = self.db.query(Application).filter(
            Application.client_id == client_id,
            Application.is_active == True
        ).first()
        
        return application
    
    def verify_service_credentials(
        self,
        client_id: str,
        client_secret: str
    ) -> Optional[Tuple[ServiceAccount, list]]:
        """
        Verify service account credentials
        Returns: (ServiceAccount, allowed_services)
        """
        service_account = self.db.query(ServiceAccount).filter(
            ServiceAccount.client_id == client_id,
            ServiceAccount.client_secret == client_secret,
            ServiceAccount.is_active == True
        ).first()
        
        if not service_account:
            return None
        
        # Get allowed services
        permissions = self.db.query(ServiceAccountPermission).filter(
            ServiceAccountPermission.service_account_id == service_account.id
        ).all()
        
        allowed_services = []
        for p in permissions:
            service = self.db.query(Service).get(p.service_id)
            if service:
                allowed_services.append(service.service_key)
        
        return service_account, allowed_services
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        return self.db.query(User).filter(
            User.id == user_id,
            User.is_active == True
        ).first()
    
    def change_password(
        self,
        user_id: int,
        application_id: int,
        old_password: str,
        new_password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Change user password
        Returns: (success, error_message)
        """
        try:
            # Validate new password strength
            is_valid, error_msg = self.password_service.validate_password_strength(new_password)
            if not is_valid:
                return False, error_msg
            
            # Find user application
            user_application = self.db.query(UserApplication).filter(
                UserApplication.user_id == user_id,
                UserApplication.application_id == application_id
            ).first()
            
            if not user_application:
                return False, "User application not found"
            
            # Find auth method
            auth_method = self.db.query(AuthMethod).filter(
                AuthMethod.user_application_id == user_application.id,
                AuthMethod.provider == AuthProviderEnum.LOCAL
            ).first()
            
            if not auth_method:
                return False, "Authentication method not found"
            
            # Get credential
            credential = self.db.query(UserCredential).filter(
                UserCredential.auth_method_id == auth_method.id
            ).first()
            
            if not credential:
                return False, "Credentials not found"
            
            # Verify old password
            if not self.password_service.verify_password(old_password, credential.password_hash):
                return False, "Invalid old password"
            
            # Hash new password
            new_hash, algo = self.password_service.hash_password(new_password)
            
            # Update credential
            credential.password_hash = new_hash
            credential.password_algo = algo
            credential.failed_attempts = 0
            credential.is_locked = False
            credential.updated_at = datetime.now(timezone.utc)
            
            self.db.commit()
            
            return True, None
            
        except Exception as e:
            self.db.rollback()
            return False, f"Password change failed: {str(e)}"
    
    def unlock_user_account(
        self,
        user_id: int,
        application_id: int
    ) -> Tuple[bool, Optional[str]]:
        """
        Unlock a user account
        Returns: (success, error_message)
        """
        try:
            user_application = self.db.query(UserApplication).filter(
                UserApplication.user_id == user_id,
                UserApplication.application_id == application_id
            ).first()
            
            if not user_application:
                return False, "User application not found"
            
            auth_method = self.db.query(AuthMethod).filter(
                AuthMethod.user_application_id == user_application.id,
                AuthMethod.provider == AuthProviderEnum.LOCAL
            ).first()
            
            if not auth_method:
                return False, "Authentication method not found"
            
            credential = self.db.query(UserCredential).filter(
                UserCredential.auth_method_id == auth_method.id
            ).first()
            
            if not credential:
                return False, "Credentials not found"
            
            credential.is_locked = False
            credential.failed_attempts = 0
            self.db.commit()
            
            return True, None
            
        except Exception as e:
            self.db.rollback()
            return False, f"Unlock failed: {str(e)}"
    
    def verify_service_access(
        self,
        application_id: int,
        service_key: str
    ) -> bool:
        """Verify if an application has access to a service"""
        service = self.db.query(Service).filter(
            Service.service_key == service_key,
            Service.is_active == True
        ).first()
        
        if not service:
            return False
        
        app_service = self.db.query(ApplicationService).filter(
            ApplicationService.application_id == application_id,
            ApplicationService.service_id == service.id
        ).first()
        
        return app_service is not None
    
    def get_user_applications(self, user_id: int) -> list:
        """Get all applications a user is registered for"""
        user_apps = self.db.query(UserApplication).filter(
            UserApplication.user_id == user_id
        ).all()
        
        result = []
        for user_app in user_apps:
            app = self.db.query(Application).get(user_app.application_id)
            if app:
                result.append({
                    "user_application_id": user_app.id,
                    "application_id": app.id,
                    "application_name": app.name,
                    "registered_at": user_app.created_at.isoformat()
                })
        
        return result