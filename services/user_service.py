from typing import Dict
from sqlalchemy.orm import Session

from models.models import Application, User, UserApplication

class UserService:

    def __init__(self, db: Session):
        self.db = db


    def update_profile(self, data: Dict, application_id: int):
        """
        Updates the user profile for the specified application.
        Returns: (User, Application, message)
        """
        print(data,"==========data")

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
        identifier_fields = ["id", "uuid", "email", "username", "phone_code", "phonenumber", "pancard"]
        for field in identifier_fields:
            value = data.get(field)
            if value is not None:
                filters.append(getattr(User, field) == value)

        if filters:
            # Try to find a user with ANY identifier (OR), not AND
            from sqlalchemy import or_
            user = user_query.filter(or_(*filters)).first()

        # If not found, attempt to find by less strict fields (name etc)
        if user is None and (data.get("full_name") or data.get("phonenumber") or data.get("pancard")):
            user_application_query = self.db.query(UserApplication).join(User).filter(
                UserApplication.application_id == application_id
            )
            if data.get("phonenumber"):
                user_application_query = user_application_query.filter(User.phonenumber == data["phonenumber"])
            elif data.get("pancard"):
                user_application_query = user_application_query.filter(User.pancard == data["pancard"])
            else:
                return None, None, "User not found for given profile fields"
            user_application = user_application_query.first()
            if user_application:
                user = self.db.query(User).filter(User.id == user_application.user_id).first()
            else:
                return None, None, "User not found for given profile fields"

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