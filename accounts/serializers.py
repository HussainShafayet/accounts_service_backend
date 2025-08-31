from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from .models import PhoneOTP, UserOTP
import random
import uuid
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.validators import UniqueValidator
from django.db.models import Q
from .services import send_otp_for, verify_otp, issue_password_reset_token, verify_password_reset_token
from django.db import transaction


User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        validators=[validate_password]
    )

    email = serializers.EmailField(
        required=False,
        allow_blank=True,
        validators=[UniqueValidator(
            queryset=User.objects.all(),
            message="This email is already registered."
        )]
    )
    phone_number = serializers.CharField(
        required=False,
        allow_blank=True,
        validators=[UniqueValidator(
            queryset=User.objects.all(),
            message="This phone number is already registered."
        )]
    )

    class Meta:
        model = User
        fields = [
            'username', 'email', 'phone_number',
            'first_name', 'last_name', 'address', 'password'
        ]

    def validate(self, attrs):
        errors = {}

        # normalize blank → None
        email = attrs.get('email') or None
        phone = attrs.get('phone_number') or None

        if not email and not phone:
            errors['email'] = "Email is required if phone number is not provided."
            errors['phone_number'] = "Phone number is required if email is not provided."

        for field in ['first_name', 'last_name', 'address']:
            if not attrs.get(field):
                errors[field] = f"{field.replace('_', ' ').capitalize()} is required."

        if errors:
            raise serializers.ValidationError(errors)

        attrs['email'] = email
        attrs['phone_number'] = phone
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.is_active = False  # inactive until OTP verification
        user.save()
        return user

    
class RegistrationOTPVerifySerializer(serializers.Serializer):
    otp = serializers.CharField()
    temp_token = serializers.UUIDField()

    def validate(self, data):
        otp = (data.get("otp") or "").strip()
        if not otp.isdigit() or len(otp) != 6:
            raise serializers.ValidationError("Invalid OTP format.")

        # Use service – channel auto-detected from the token record
        res = verify_otp(
            temp_token=str(data["temp_token"]),
            otp=otp,
            channel=None,   # auto: use the otp_type stored with this token
        )
        if not res.get("ok"):
            # e.g. "Invalid token." / "OTP expired." / "Incorrect OTP."
            raise serializers.ValidationError(res.get("message") or "OTP verification failed.")

        user = res.get("user")
        if user is None:
            raise serializers.ValidationError("Invalid user for this OTP.")

        # Activate & verify user atomically
        with transaction.atomic():
            # mark user verified/active (idempotent)
            user.is_active = True
            if hasattr(user, "is_verified"):
                user.is_verified = True
            user.save(update_fields=["is_active"] + (["is_verified"] if hasattr(user, "is_verified") else []))

            # (Optional hardening) Invalidate any other unused registration OTPs for this user
            # UserOTP.objects.filter(user=user, is_used=False).update(is_used=True)

        return {"message": "User verified successfully"}

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number']
        read_only_fields = ['id']


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Login with either email or username via a single field: `login`.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove parent's email/username field so it doesn't complain
        self.fields.pop(self.username_field, None)
        # Replace with our unified login field
        self.fields['login'] = serializers.CharField(write_only=True)
        self.fields['password'].required = True
        self.fields['password'].trim_whitespace = False

    def validate(self, attrs):
        login = (attrs.get('login') or '').strip()
        password = attrs.get('password') or ''

        if not login:
            raise serializers.ValidationError({'login': 'Login (email or username) is required.'})

        # Try case-insensitive match
        user = User.objects.filter(Q(email__iexact=login) | Q(username__iexact=login)).first()
        if not user:
            raise serializers.ValidationError({'login': 'No user found with this email or username.'})

        if not user.is_active:
            raise serializers.ValidationError({'login': 'Account is not active. Please verify.'})

        # Authenticate against Django’s backend
        user_auth = authenticate(
            request=self.context.get('request'),
            username=user.email,  # canonical
            password=password
        )
        if user_auth is None:
            raise serializers.ValidationError({'password': 'Incorrect credentials.'})

        # Delegate to parent with canonical identifier
        data = super().validate({self.username_field: user.email, 'password': password})

        data['user'] = {
            'id': user.id,
            'email': user.email,
            'username': user.username,
        }
        return data

class SendOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField()

    def validate_phone_number(self, value):
        qs = User.objects.filter(phone_number=value)
        if not qs.exists():
            raise serializers.ValidationError("User with this phone number does not exist.")
        return value

    def create(self, validated_data):
        user = User.objects.get(phone_number=validated_data["phone_number"])
        result = send_otp_for(user=user, channel="phone", purpose="login")
        if not result["otp_sent"]:
            raise serializers.ValidationError({"detail": result.get("message", "Failed to send OTP")})
        data = {
            "otp_sent": True,
            "temp_token": result["temp_token"],
            "expires_in_seconds": result["expires_in_seconds"]
        }
        if result["debug_otp"]:
            data["debug_otp"] = result["debug_otp"]
        return data

class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField()
    temp_token = serializers.UUIDField()

    def validate(self, data):
        # Optional: basic OTP shape guard
        otp = (data.get('otp') or '').strip()
        if not otp.isdigit() or len(otp) != 6:
            raise serializers.ValidationError("Invalid OTP format.")

        # Use the unified service; this is phone-login, so channel='phone'
        res = verify_otp(
            temp_token=str(data['temp_token']),
            otp=otp,
            channel="phone",
        )
        if not res.get("ok"):
            # service returns: {"ok": False, "user": None, "message": "..."}
            raise serializers.ValidationError(res.get("message") or "OTP verification failed.")

        user = res.get("user")
        refresh = RefreshToken.for_user(user)

        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }

class ResendOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    temp_token = serializers.UUIDField(required=False)

    def validate(self, attrs):
        phone   = (attrs.get("phone_number") or "").strip()
        email   = (attrs.get("email") or "").strip()
        temp_token = attrs.get("temp_token")

        user = None
        channel = None
        purpose = "login"  # ✅ auto default

        if phone or email:
            q = Q()
            if phone: q |= Q(phone_number=phone)
            if email: q |= Q(email__iexact=email)
            user = User.objects.filter(q).first()
            if not user:
                raise serializers.ValidationError("No user found for given identifier.")
            channel = "phone" if phone else "email"

        elif temp_token:
            try:
                rec = UserOTP.objects.select_related("user").get(temp_token=temp_token)
            except UserOTP.DoesNotExist:
                raise serializers.ValidationError("Invalid temp_token.")
            user = rec.user
            channel = rec.otp_type

        else:
            raise serializers.ValidationError("Provide phone_number, email or temp_token.")

        attrs["user"] = user
        attrs["channel"] = channel
        attrs["purpose"] = purpose
        return attrs

    def create(self, validated_data):
        result = send_otp_for(
            user=validated_data["user"],
            channel=validated_data["channel"],
            purpose=validated_data["purpose"],
            force=True,  # ✅ always resend
        )

        if not result.get("otp_sent", False):
            raise serializers.ValidationError({"detail": result.get("message", "Failed to resend OTP")})

        data = {
            "otp_sent": True,
            "temp_token": result["temp_token"],
            "expires_in_seconds": result["expires_in_seconds"],
        }
        if result.get("debug_otp"):
            data["debug_otp"] = result["debug_otp"]
        return data


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate_new_password(self, value):
        validate_password(value)  # Django validators (length, common, numeric etc.)
        return value

    def validate(self, attrs):
        user = self.context["request"].user
        if not user.check_password(attrs["old_password"]):
            raise serializers.ValidationError({"old_password": "Old password is incorrect."})
        if attrs["old_password"] == attrs["new_password"]:
            raise serializers.ValidationError({"new_password": "New password must be different."})
        return attrs

    def save(self, **kwargs):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save(update_fields=["password"])
        return {"detail": "Password changed successfully."}
class PasswordResetStartSerializer(serializers.Serializer):
    phone_number = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)

    def validate(self, attrs):
        phone = (attrs.get("phone_number") or "").strip()
        email = (attrs.get("email") or "").strip()
        if not phone and not email:
            raise serializers.ValidationError("Provide phone_number or email.")

        q = Q()
        if phone: q |= Q(phone_number=phone)
        if email: q |= Q(email__iexact=email)
        user = User.objects.filter(q).first()
        if not user:
            raise serializers.ValidationError("User not found.")

        attrs["user"] = user
        attrs["channel"] = "phone" if phone else "email"
        return attrs

    def create(self, validated_data):
        result = send_otp_for(
            user=validated_data["user"],
            channel=validated_data["channel"],
            purpose="reset",
            force=False
        )
        if not result.get("otp_sent"):
            raise serializers.ValidationError({"detail": result.get("message", "Please wait before requesting another OTP.")})

        resp = {
            "otp_sent": True,
            "temp_token": result["temp_token"],
            "expires_in_seconds": result["expires_in_seconds"],
        }
        if result.get("debug_otp"):
            resp["debug_otp"] = result["debug_otp"]
        return resp
class PasswordResetVerifySerializer(serializers.Serializer):
    temp_token = serializers.UUIDField()
    otp = serializers.CharField()

    def validate(self, data):
        otp = (data.get("otp") or "").strip()
        if not otp.isdigit() or len(otp) != 6:
            raise serializers.ValidationError({"otp": "Invalid OTP format."})
        return data

    def create(self, validated_data):
        # ✅ Cast UUID -> str before passing along
        temp_token = str(validated_data["temp_token"])
        otp = validated_data["otp"]

        res = verify_otp(temp_token=temp_token, otp=otp, channel=None)
        if not res.get("ok"):
            # Ensure message is a plain string
            msg = res.get("message") or "OTP verification failed."
            raise serializers.ValidationError({"otp": msg})

        # ✅ issue_password_reset_token should already return str
        reset_token = issue_password_reset_token(res["user"], minutes=10)

        # ✅ Return only strings/ints
        return {"reset_token": reset_token, "expires_in_seconds": 600}
class PasswordResetSetSerializer(serializers.Serializer):
    reset_token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate(self, attrs):
        token = attrs.get("reset_token")
        res = verify_password_reset_token(token, max_age=600)
        if not res.get("ok"):
            raise serializers.ValidationError(res.get("message") or "Invalid reset token.")
        attrs["user"] = res["user"]
        return attrs

    def create(self, validated_data):
        user = validated_data["user"]
        user.set_password(validated_data["new_password"])
        user.save(update_fields=["password"])
        return {"detail": "Password has been reset successfully."}

#class LoginOTPVerifySerializer(serializers.Serializer):
#    otp = serializers.CharField()
#    temp_token = serializers.UUIDField()

#    def validate(self, data):
#        try:
#            otp_obj = UserOTP.objects.get(temp_token=data['temp_token'], is_used=False)
#        except UserOTP.DoesNotExist:
#            raise serializers.ValidationError("Invalid or expired OTP session.")

#        if otp_obj.otp != data['otp']:
#            raise serializers.ValidationError("Invalid OTP.")

#        if timezone.now() > otp_obj.expires_at:
#            raise serializers.ValidationError("OTP expired.")

#        otp_obj.is_used = True
#        otp_obj.save()

#        user = otp_obj.user

#        refresh = RefreshToken.for_user(user)
#        return {
#            "access": str(refresh.access_token),
#            "refresh": str(refresh)
#        }

