# auth_service/utils/captcha.py
import requests
from django.conf import settings

def verify_captcha(token: str) -> bool:
    """
    Verify captcha token with Google reCAPTCHA.
    Returns True if valid, False otherwise.
    """
    secret = getattr(settings, "RECAPTCHA_SECRET_KEY", None)
    if not secret:
        # Fail-safe: in DEBUG mode skip captcha
        if getattr(settings, "DEBUG", False):
            return True
        return False

    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {"secret": secret, "response": token}

    try:
        resp = requests.post(url, data=data, timeout=5)
        result = resp.json()
        return result.get("success", False)
    except Exception:
        return False
