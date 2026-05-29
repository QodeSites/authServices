from typing import Dict
from sqlalchemy.orm import Session
import logging

from models.models import Application, User, UserApplication

logger = logging.getLogger(__name__)

class UserService:

    def __init__(self, db: Session):
        self.db = db


    def update_profile(self, data: Dict, application_id: int):
        """
        Updates the user profile for the specified application.
        Returns: (User, Application, message)
        """
        # 1. Validate and fetch application
        application = self.db.query(Application).filter(
            Application.id == application_id,
            Application.is_active == True
        ).first()
        if not application:
            return None, None, "Application not found or inactive"

        # 2. Attempt to find user using any available identifier (try all)
        user = None
        user_query = self.db.query(User)
        filters = []
        identifier_fields = ["id", "email", "username", "phonenumber", "pancard"]
        for field in identifier_fields:
            value = data.get(field)
            if value is not None:
                filters.append(getattr(User, field) == value)

        if filters:
            # Try to find a user with ANY identifier (OR), not AND
            from sqlalchemy import or_
            user = user_query.filter(or_(*filters)).first()

        if user is None:
            return None, None, "User not found"

        # Only update fields that exist on the user and ignore protected fields
        exclude_fields = {"id", "uuid", "created_at"}
        for key, value in data.items():
            if key in exclude_fields or value is None:
                continue
            if hasattr(user, key):
                setattr(user, key, value)

        self.db.commit()
        self.db.refresh(user)
        return user, application, None