
import os
import re
import logging
import requests
from fastapi import HTTPException

from db.redis import get_redis_client
from config.settings import settings

logger = logging.getLogger(__name__)

TWO_FACTOR_API_KEY = settings.TWO_FACTOR_API_KEY
# Base URL for the 2Factor.in OTP gateway. Overridable via env so we don't
# bake third-party hostnames into source. Strip any trailing slash so the
# downstream f-strings remain consistent.
TWO_FACTOR_API_URL = (settings.TWO_FACTOR_API_URL or "https://2factor.in/API/V1").rstrip("/")
OTP_EXPIRY_SECONDS = 180  # 3 minutes
RATE_LIMIT_ATTEMPTS = 3
RATE_LIMIT_WINDOW = 3600  # 1 hour
PHONE_VERIFIED_EXPIRY = 120  # 2 minutes

# ── App-store reviewer bypass (Strategy B from LAUNCH_CHECKLIST.md §6) ──
# Normalised once at import time: digits-only, no leading +. Module-scoped
# so per-request work stays cheap. When unset (production after launch),
# `_is_reviewer_phone` always returns False — fully off.
_REVIEWER_PHONE = re.sub(r"\D", "", settings.REVIEWER_PHONE or "")
_REVIEWER_OTP = (settings.REVIEWER_OTP or "").strip()

def _is_reviewer_phone(phone: str) -> bool:
    """True when both reviewer env vars are set AND the cleaned phone matches."""
    return bool(_REVIEWER_PHONE) and bool(_REVIEWER_OTP) and phone == _REVIEWER_PHONE

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
        phone = self.cleaned_phone

        # Reviewer bypass: skip 2Factor entirely + skip rate-limiting so the
        # App Store / Play Store reviewer can hammer the OTP screen during
        # the review run. Logged so we can audit how often it fires (should
        # be ~zero outside review windows). Disable by clearing the env vars.
        if _is_reviewer_phone(phone):
            logger.warning(f"[OTP Service] REVIEWER BYPASS — send_otp for {phone[:4]}***")
            self.redis.setex(
                f"otp:session:{phone}", OTP_EXPIRY_SECONDS, "reviewer-bypass"
            )
            return {
                "success": True,
                "session_id": "reviewer-bypass",
                "message": "OTP sent successfully",
            }

        if not TWO_FACTOR_API_KEY:
            logger.error("[OTP Service] TWO_FACTOR_API_KEY not set in environment.")
            return {"success": False, "message": "Internal server error"}

        rate_limit_key = f"otp:ratelimit:{phone}"

        try:
            # Check rate limiting: max 3 OTP send attempts per phone per hour
            attempts = self.redis.get(rate_limit_key)
            if attempts is not None:
                attempts = int(attempts)
                if attempts >= RATE_LIMIT_ATTEMPTS:
                    logger.warning(f"[OTP Service] Rate limit exceeded for {phone}")
                    raise HTTPException(status_code=429, detail="Too many OTP requests. Try again in an hour.")

            # Increment rate limit counter with 3600s TTL
            self.redis.incr(rate_limit_key)
            self.redis.expire(rate_limit_key, RATE_LIMIT_WINDOW)

            url = f"{TWO_FACTOR_API_URL}/{TWO_FACTOR_API_KEY}/SMS/{phone}/AUTOGEN"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            logger.info(f"[OTP Service] 2Factor response status received")

            if data.get("Status") == "Success" and data.get("Details"):
                session_id = data["Details"]
                self.redis.setex(f"otp:session:{phone}", OTP_EXPIRY_SECONDS, session_id)
                logger.info(f"[OTP Service] OTP sent successfully to phone")
                return {
                    "success": True,
                    "session_id": session_id,
                    "message": "OTP sent successfully"
                }
            else:
                logger.error(f"[OTP Service] Failed to send OTP")
                return {
                    "success": False,
                    "message": data.get("Details") or "Failed to send OTP"
                }

        except HTTPException:
            raise
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
        phone = self.cleaned_phone

        # Reviewer bypass — match the static OTP, mark the phone verified.
        # Same constant-time-ish compare style as the live path uses (string
        # equality is fine here; the OTP is non-secret to the reviewer).
        if _is_reviewer_phone(phone):
            if (otp or "").strip() == _REVIEWER_OTP:
                logger.warning(
                    f"[OTP Service] REVIEWER BYPASS — verify_otp OK for {phone[:4]}***"
                )
                self.redis.setex(
                    f"phone:verified:{phone}", PHONE_VERIFIED_EXPIRY, "true"
                )
                self.redis.delete(f"otp:session:{phone}")
                return {
                    "success": True,
                    "verified": True,
                    "message": "Phone number verified successfully",
                }
            logger.warning(
                f"[OTP Service] REVIEWER BYPASS — wrong static OTP for {phone[:4]}***"
            )
            return {
                "success": False,
                "verified": False,
                "message": "Invalid OTP. Please try again.",
            }

        if not TWO_FACTOR_API_KEY:
            logger.error("[OTP Service] TWO_FACTOR_API_KEY not set in environment.")
            return {"success": False, "verified": False, "message": "Internal server error"}

        session_id = self.redis.get(f"otp:session:{phone}")
        if not session_id:
            logger.warning(f"[OTP Service] No OTP session found for {phone}")
            return {
                "success": False,
                "verified": False,
                "message": "OTP expired or invalid. Please request a new OTP."
            }
        try:
            url = f"{TWO_FACTOR_API_URL}/{TWO_FACTOR_API_KEY}/SMS/VERIFY/{session_id}/{otp}"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            logger.info(f"[OTP Service] 2Factor verify response: {data}")

            if data.get("Status") == "Success" and data.get("Details") == "OTP Matched":
                self.redis.setex(f"phone:verified:{phone}", PHONE_VERIFIED_EXPIRY, "true")
                self.redis.delete(f"otp:session:{phone}")
                # Clear rate limit key after successful OTP verification
                rate_limit_key = f"otp:ratelimit:{phone}"
                self.redis.delete(rate_limit_key)
                logger.info(f"[OTP Service] OTP verified successfully")
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
