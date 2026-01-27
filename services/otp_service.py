
import os
import re
import logging
import requests

from db.redis import get_redis_client
from config.settings import settings

logger = logging.getLogger(__name__)

TWO_FACTOR_API_KEY = settings.TWO_FACTOR_API_KEY
OTP_EXPIRY_SECONDS = 300  # 5 minutes
RATE_LIMIT_ATTEMPTS = 3
RATE_LIMIT_WINDOW = 36000 # 1 hour
PHONE_VERIFIED_EXPIRY = 600  # 10 minutes

class OtpService:
    """
    OTP Service for sending and verifying OTP using 2Factor.in and Redis.
    """

    def __init__(self, phone_code: int, phone_number: int) -> None:
        self.phone_code = phone_code
        self.phone_number = phone_number
        # Combine code and number, or store internationally compliant
        self.cleaned_phone = f"{self.phone_code}{self.phone_number}"
        self.cleaned_phone = re.sub(r"\D", "", self.cleaned_phone)
        self.redis = get_redis_client()

    def send_otp(self):
        """
        Send an OTP to the user's phone.
        """
        if not TWO_FACTOR_API_KEY:
            logger.error("[OTP Service] TWO_FACTOR_API_KEY not set in environment.")
            return {"success": False, "message": "Internal server error"}

        phone = self.cleaned_phone
        rate_limit_key = f"otp:ratelimit:{phone}"

        try:
            # Rate limiting (max 3 in 1 hour)
            attempts = self.redis.get(rate_limit_key)
            if attempts and int(attempts) >= RATE_LIMIT_ATTEMPTS:
                logger.warning(f"[OTP Service] Rate limit exceeded for {phone}")
                return {
                    "success": False,
                    "message": "Too many OTP requests. Please try again after 1 hour."
                }

            url = f"https://2factor.in/API/V1/{TWO_FACTOR_API_KEY}/SMS/{phone}/AUTOGEN"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            logger.info(f"[OTP Service] 2Factor response: {data}")

            if data.get("Status") == "Success" and data.get("Details"):
                session_id = data["Details"]
                self.redis.setex(f"otp:session:{phone}", OTP_EXPIRY_SECONDS, session_id)
                current_attempts = int(attempts or 0)
                self.redis.setex(rate_limit_key, RATE_LIMIT_WINDOW, str(current_attempts + 1))
                logger.info(f"[OTP Service] OTP sent successfully to {phone}, session: {session_id}")
                return {
                    "success": True,
                    "session_id": session_id,
                    "message": "OTP sent successfully"
                }
            else:
                logger.error(f"[OTP Service] Failed to send OTP: {data}")
                return {
                    "success": False,
                    "message": data.get("Details") or "Failed to send OTP"
                }

        except Exception as error:
            logger.error(f"[OTP Service] Error sending OTP: {str(error)}")
            return {
                "success": False,
                "message": str(error) or "Internal server error"
            }

    def verify_otp(self, otp:str):
        """
        Verify user-submitted OTP.
        """
        if not TWO_FACTOR_API_KEY:
            logger.error("[OTP Service] TWO_FACTOR_API_KEY not set in environment.")
            return {"success": False, "verified": False, "message": "Internal server error"}

        phone = self.cleaned_phone
        session_id = self.redis.get(f"otp:session:{phone}")
        if not session_id:
            logger.warning(f"[OTP Service] No OTP session found for {phone}")
            return {
                "success": False,
                "verified": False,
                "message": "OTP expired or invalid. Please request a new OTP."
            }
        try:
            url = f"https://2factor.in/API/V1/{TWO_FACTOR_API_KEY}/SMS/VERIFY/{session_id}/{otp}"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            logger.info(f"[OTP Service] 2Factor verify response: {data}")

            if data.get("Status") == "Success" and data.get("Details") == "OTP Matched":
                self.redis.setex(f"phone:verified:{phone}", PHONE_VERIFIED_EXPIRY, "true")
                self.redis.delete(f"otp:session:{phone}")
                logger.info(f"[OTP Service] OTP verified successfully for {phone}")
                return {
                    "success": True,
                    "verified": True,
                    "message": "Phone number verified successfully"
                }
            else:
                logger.warning(f"[OTP Service] OTP verification failed for {phone}")
                return {
                    "success": False,
                    "verified": False,
                    "message": "Invalid OTP. Please try again."
                }
        except Exception as error:
            logger.error(f"[OTP Service] Error verifying OTP: {str(error)}")
            return {
                "success": False,
                "verified": False,
                "message": str(error) or "Internal server error"
            }

    def is_phone_verified(self):
        """
        Check if the phone number is verified within the recent window.
        """
        verified = self.redis.get(f"phone:verified:{self.cleaned_phone}")
        return verified == "true"

    def clear_phone_verification(self):
        """
        Clear/expire the phone verification status.
        """
        self.redis.delete(f"phone:verified:{self.cleaned_phone}")
