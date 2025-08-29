from .models import UserOTP
from django.core.mail import send_mail
from django.conf import settings
from django.utils.crypto import get_random_string
from datetime import timedelta
from django.utils import timezone
from django.db import transaction
import logging
import re
import random
from typing import Optional, Literal

logger = logging.getLogger(__name__)

Channel = Literal["phone", "email"]
Purpose = Literal["registration", "login"]

OTP_TTL_MIN = 5          # 5 minutes
COOLDOWN_SEC = 60        # 1 minute between sends
if getattr(settings, "DEBUG", False):
    COOLDOWN_SEC = 0


def _normalize_phone(raw: str) -> str:
    s = (raw or "").strip()
    return re.sub(r"[ \-]", "", s)

def _generate_otp() -> str:
    # keep your previous generator if you prefer
    return get_random_string(length=6, allowed_chars='0123456789')
    # or:
    # return f"{random.randint(100000, 999999)}"

def _send_sms(to: str, msg: str) -> None:
    # TODO: integrate SMS provider (Twilio/SNS/Gateway)
    logger.info(f"[DEV] SMS to {to}: {msg}")
    print(f"[DEV] SMS to {to}: {msg}")

def _send_email(to: str, subject: str, body: str) -> None:
    send_mail(
        subject=subject,
        message=body,
        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@example.com'),
        recipient_list=[to],
        fail_silently=bool(getattr(settings, 'DEBUG', False)),
    )

@transaction.atomic
def send_otp_for(*, user, channel: Optional[Channel] = None, purpose: Purpose = "registration"):
    """
    Core sender with rate-limit, invalidate, expiry & delivery.
    Returns dict: {otp_sent, temp_token, expires_in_seconds, [debug_otp]}
    """
    if not user.email and not user.phone_number:
        raise ValueError("User has no contact info")

    # Auto-select channel if not provided
    if channel is None:
        channel = "phone" if user.phone_number else "email"

    now = timezone.now()

    # Cooldown: block if another OTP was created very recently
    recent = UserOTP.objects.filter(
        user=user,
        otp_type=channel,
        is_used=False,
        created_at__gte=now - timedelta(seconds=COOLDOWN_SEC),
    ).order_by("-created_at").first()
    if recent:
        return {
            "otp_sent": False,
            "temp_token": str(recent.temp_token),
            "expires_in_seconds": max(0, int((recent.expires_at - now).total_seconds())) if recent.expires_at else OTP_TTL_MIN*60,
            "message": "Please wait before requesting another OTP.",
        }

    # Invalidate older unused OTPs for same channel
    UserOTP.objects.filter(user=user, otp_type=channel, is_used=False).update(is_used=True)

    # Create new OTP
    otp = _generate_otp()
    otp_obj = UserOTP.objects.create(
        user=user,
        otp=otp,
        otp_type=channel,
        expires_at=now + timedelta(minutes=OTP_TTL_MIN),
    )

    # Best-effort delivery
    try:
        if channel == "phone" and user.phone_number:
            _send_sms(_normalize_phone(user.phone_number), f"Your {purpose} OTP is {otp}")
        elif channel == "email" and user.email:
            _send_email(user.email, "Your OTP Code", f"Use this OTP to {purpose}: {otp}")
        else:
            logger.warning("No valid route for OTP delivery.")
    except Exception as e:
        logger.exception(f"Failed to deliver OTP for user {user.id}: {e}")

    payload = {
        "otp_sent": True,
        "temp_token": str(otp_obj.temp_token),
        "expires_in_seconds": OTP_TTL_MIN * 60,
    }
    if getattr(settings, "DEBUG", False):
        payload["debug_otp"] = otp
    return payload

def verify_otp(*, temp_token: str, otp: str, channel: Optional[Channel] = None):
    """
    Verify OTP by temp_token (+ optional channel).
    Returns dict: {ok, user, message}
    """
    from django.contrib.auth import get_user_model
    User = get_user_model()

    qs = UserOTP.objects.select_related("user").filter(temp_token=temp_token)
    if channel:
        qs = qs.filter(otp_type=channel)

    try:
        rec = qs.get()
    except UserOTP.DoesNotExist:
        return {"ok": False, "user": None, "message": "Invalid token."}

    now = timezone.now()
    if rec.is_used or not rec.expires_at or rec.expires_at < now:
        return {"ok": False, "user": None, "message": "OTP expired."}

    if rec.otp != otp:
        return {"ok": False, "user": None, "message": "Incorrect OTP."}

    rec.is_used = True
    rec.save(update_fields=["is_used"])

    return {"ok": True, "user": rec.user, "message": "Verified."}

# ---- Backwards compatible wrapper (keeps your old name/signature) ----
def send_otp(user):
    """
    Backward-compatible thin wrapper over send_otp_for().
    Auto-selects channel: phone if available else email. Purpose defaults to 'registration'.
    """
    return send_otp_for(user=user, channel=None, purpose="registration")
