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


User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        validators=[validate_password]
    )

    class Meta:
        model = User
        fields = [
            'username', 'email', 'phone_number',
            'first_name', 'last_name', 'address', 'password'
        ]

    def validate(self, attrs):
        errors = {}

        email = attrs.get('email')
        phone = attrs.get('phone_number')

        # Ensure at least one of email or phone_number
        if not email and not phone:
            # Mark missing fields individually
            errors['email'] = "Email is required if phone number is not provided."
            errors['phone_number'] = "Phone number is required if email is not provided."

        # Check other required fields dynamically
        for field in ['first_name', 'last_name', 'address']:
            if not attrs.get(field):
                errors[field] = f"{field.replace('_', ' ').capitalize()} is required."

        if errors:
            raise serializers.ValidationError(errors)

        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.is_active = False  # inactive until OTP verification
        user.save()

        # Send OTP (phone priority)
        from .services import send_otp
        send_otp(user)

        # Return only temp_token for verification
        return user
    
class RegistrationOTPVerifySerializer(serializers.Serializer):
    otp = serializers.CharField()
    temp_token = serializers.UUIDField()

    def validate(self, data):
        try:
            otp_obj = UserOTP.objects.get(temp_token=data['temp_token'], is_used=False)
        except UserOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired OTP session.")

        if otp_obj.otp != data['otp']:
            raise serializers.ValidationError("Invalid OTP.")

        if timezone.now() > otp_obj.expires_at:
            raise serializers.ValidationError("OTP expired.")

        # Activate user
        user = otp_obj.user
        user.is_active = True
        user.is_verified = True
        user.save()

        # Mark OTP used
        otp_obj.is_used = True
        otp_obj.save()

        return {"message": "User verified successfully"}

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number']
        read_only_fields = ['id']


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        # Allow login with either email or username
        login = attrs.get('email') or attrs.get('username')
        password = attrs.get('password')

        # Try to fetch user by email or username
        try:
            user = User.objects.get(email=login)
        except User.DoesNotExist:
            try:
                user = User.objects.get(username=login)
            except User.DoesNotExist:
                raise serializers.ValidationError('No user found with this email or username.')

        # Authenticate user
        if not user.check_password(password):
            raise serializers.ValidationError('Incorrect password.')

        # Use super() to generate JWT tokens
        data = super().validate({'email': user.email, 'password': password})
        data['user'] = {
            'id': user.id,
            'email': user.email,
            'username': user.username,
        }
        return data

class SendOTPSerializer(serializers.Serializer):
   phone_number = serializers.CharField()

   def validate_phone_number(self, value):
        if not User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("User with this phone number does not exist.")
        return value

   def create(self, validated_data):
        user = User.objects.get(phone_number=validated_data['phone_number'])

        # Invalidate old OTPs
        PhoneOTP.objects.filter(user=user, is_used=False).update(is_used=True)

        # Generate new OTP + temp_token
        otp_code = str(random.randint(100000, 999999))
        otp_obj = PhoneOTP.objects.create(user=user, otp=otp_code)
        # TODO: send SMS here
        print(f"Send OTP {otp_code} to {user.phone_number}")
        return {"otp_sent": True,"otp":otp_code, "temp_token": otp_obj.temp_token}

class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField()
    temp_token = serializers.UUIDField()

    def validate(self, data):
        try:
            otp_obj = PhoneOTP.objects.get(temp_token=data['temp_token'], is_used=False);
        except PhoneOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired OTP session.")

        if otp_obj.otp != data['otp']:
            raise serializers.ValidationError("Invalid OTP.")
        if timezone.now() > otp_obj.created_at + timedelta(minutes=5):
            raise serializers.ValidationError("OTP expired.")

        otp_obj.is_used = True
        otp_obj.save()

        refresh = RefreshToken.for_user(otp_obj.user)
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }

class ResendOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField()

    def validate_phone_number(self, value):
        if not User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("User with this phone number does not exist.")
        return value

    def create(self, validated_data):
        user = User.objects.get(phone_number=validated_data['phone_number'])

        # Invalidate old OTPs (optional)
        PhoneOTP.objects.filter(user=user, is_used=False).update(is_used=True)

        # Generate new OTP + temp_token
        otp_code = str(random.randint(100000, 999999))
        otp_obj = PhoneOTP.objects.create(user=user, otp=otp_code)

        # TODO: send SMS here
        print(f"Resent OTP {otp_code} to {user.phone_number}")

        return {
            "otp_sent": True,
            "temp_token": str(otp_obj.temp_token)
        }

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

