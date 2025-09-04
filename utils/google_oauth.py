# auth_service/utils/google_oauth.py
from django.conf import settings
from google.oauth2 import id_token
from google.auth.transport import requests as g_requests

class GoogleTokenError(Exception):
    pass

def verify_google_id_token(token: str) -> dict:
    """
    Verify a Google ID token issued to your frontend app.
    Returns the decoded payload dict on success, raises GoogleTokenError on failure.
    """
    client_id = getattr(settings, "GOOGLE_CLIENT_ID", None)
    if not client_id:
        raise GoogleTokenError("Server misconfigured: GOOGLE_CLIENT_ID missing.")

    try:
        payload = id_token.verify_oauth2_token(
            token, g_requests.Request(), audience=client_id
        )
        # Expected fields: sub, email, email_verified, name, picture, given_name, family_name
        if not payload.get("email"):
            raise GoogleTokenError("Google token has no email.")
        if payload.get("aud") != client_id:
            raise GoogleTokenError("Token audience mismatch.")
        return payload
    except Exception as e:
        raise GoogleTokenError(f"Invalid Google ID token: {e}")
