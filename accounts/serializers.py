from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from .models import PhoneOTP
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
        # Make username optional if your model allows blank=True
        fields = ['username', 'email', 'password', 'phone_number']

    def create(self, validated_data):
        # Use get with default None for optional fields
        username = validated_data.get('username', None)
        email = validated_data.get('email')
        phone_number = validated_data.get('phone_number', None)
        password = validated_data['password']

        # Create user using set_password to hash the password
        user = User(
            username=username,
            email=email,
            phone_number=phone_number
        )
        user.set_password(password)
        user.save()
        return user

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
        otp_code = str(random.randint(100000, 999999))
        temp_token = str(uuid.uuid4())
        PhoneOTP.objects.create(user=user, otp=otp_code, is_used=False)
        # TODO: send SMS here
        print(f"Send OTP {otp_code} to {user.phone_number}")
        return {"otp_sent": True,"otp":otp_code, "temp_token": temp_token}

class VerifyOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    otp = serializers.CharField()
    temp_token = serializers.CharField()

    def validate(self, data):
        try:
            user = User.objects.get(phone_number=data['phone_number'])
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid phone number.")

        try:
            otp_obj = PhoneOTP.objects.filter(user=user, is_used=False).latest('created_at')
        except PhoneOTP.DoesNotExist:
            raise serializers.ValidationError("No OTP found. Request a new one.")

        if otp_obj.otp != data['otp']:
            raise serializers.ValidationError("Invalid OTP.")
        if timezone.now() > otp_obj.created_at + timedelta(minutes=5):
            raise serializers.ValidationError("OTP expired.")

        otp_obj.is_used = True
        otp_obj.save()

        refresh = RefreshToken.for_user(user)
        return {
            "user": {
                'id': user.id,
                'email': user.email,
                'username': user.username,
            },
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }

