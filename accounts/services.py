from .models import UserOTP
from django.core.mail import send_mail
from django.conf import settings
from django.utils.crypto import get_random_string
from datetime import timedelta
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

def _generate_otp():
    return get_random_string(length=6, allowed_chars='0123456789')

def send_otp(user):
    """
    Generate & persist OTP (UserOTP), then try to deliver via email/phone.
    Never raise if delivery fails; log the error and return the temp_token so
    the client can proceed to verification.
    """
    if not user.email and not user.phone_number:
        raise ValueError("User has no contact info")

    otp = _generate_otp()
    otp_obj = UserOTP.objects.create(
        user=user,
        otp=otp,
        otp_type='phone' if user.phone_number else 'email',
        expires_at=timezone.now() + timedelta(minutes=5),
    )

    # Try delivery but do not raise on failure
    try:
        if otp_obj.otp_type == 'phone' and user.phone_number:
            # TODO: integrate SMS provider here (Twilio, etc.)
            # For now, dev-log:
            logger.info(f"[DEV] Send OTP {otp} to phone {user.phone_number}")
        elif user.email:
            send_mail(
                subject='Your OTP Code',
                message=f'Use this OTP to verify your account: {otp}',
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@example.com'),
                recipient_list=[user.email],
                fail_silently=bool(getattr(settings, 'DEBUG', False)),  # don’t raise in DEBUG
            )
        else:
            logger.warning("No valid contact route for OTP.")
    except Exception as e:
        # Do not break registration response
        logger.exception(f"Failed to deliver OTP for user {user.id}: {e}")

    return otp_obj  # caller can read otp_obj.temp_token
