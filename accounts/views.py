# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, throttling, serializers
from .serializers import UserRegistrationSerializer, UserSerializer, SendOTPSerializer, VerifyOTPSerializer, ResendOTPSerializer, RegistrationOTPVerifySerializer, ChangePasswordSerializer, PasswordResetStartSerializer, PasswordResetVerifySerializer, PasswordResetSetSerializer
from .models import CustomUser, UserOTP
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from uuid import UUID

from django.conf import settings

from .services import send_otp
import logging

logger = logging.getLogger(__name__)

#login
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer

class RegisterUserAPIView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        
        from .services import send_otp_for
        result = send_otp_for(user=user, purpose="registration", force=True)

        if not result.get("otp_sent"):
            return Response(
                {"error": result.get("message", "Registered, but failed to send OTP.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        payload = {
            "temp_token": result["temp_token"],
            "pending": True,
            "expires_in_seconds": result["expires_in_seconds"]
        }
        if result.get("debug_otp"):
            payload["debug_otp"] = result["debug_otp"]

        return Response(payload, status=status.HTTP_201_CREATED)

    
class VerifyRegistrationOTPAPIView(APIView):
    # Optional: basic throttle
    throttle_classes = [throttling.AnonRateThrottle]

    def post(self, request):
        serializer = RegistrationOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)



class UserListAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        users = CustomUser.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        access_token = data['access']
        refresh_token = data['refresh']

        response = Response(
            {
                "access": access_token,
                "user": data['user']
            },
            status=status.HTTP_200_OK
        )

        # If your frontend runs on a different origin, you need SameSite=None and Secure=True (in prod)
        same_site = 'None' if not settings.DEBUG else 'Lax'
        secure_flag = not settings.DEBUG

        # Optionally set Max-Age to your refresh lifetime in seconds
        max_age = None
        try:
            lifetime = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
            # timedelta -> seconds
            max_age = int(lifetime.total_seconds())
        except Exception:
            pass

        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=secure_flag,
            samesite=same_site,
            path='/',               # cookie available site-wide; change to '/api/token/refresh/' if you want to scope it
            max_age=max_age,        # optional but recommended
        )

        return response


class CustomTokenRefreshView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response({"detail": "No refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
        except Exception:
            return Response({"detail": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        # Always return a proper Response
        return Response({"access": access_token}, status=status.HTTP_200_OK)



class SendOTPAPIView(APIView):
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.save(), status=status.HTTP_200_OK)

class VerifyOTPAPIView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data  # contains access + refresh

        access_token = data["access"]
        refresh_token = data["refresh"]

        response = Response({"access": access_token}, status=status.HTTP_200_OK)


        same_site = 'None' if not settings.DEBUG else 'Lax'
        secure_flag = not settings.DEBUG

        # Optional: cookie lifetime == refresh lifetime
        max_age = None
        try:
            max_age = int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds())
        except Exception:
            pass

        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=secure_flag,
            samesite=same_site,
            path='/',
            max_age=max_age,   # optional but recommended
        )

        return response

class ResendOTPAPIView(APIView):
    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.save(), status=status.HTTP_200_OK)

class LogoutView(APIView):
    def post(self, request):
        response = Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        
        # Delete refresh token cookie
        response.delete_cookie(
            key="refresh_token",
            path="/",  # Must match the path used when setting the cookie
        )

        return response

# 1) Change password (authenticated)
class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        s = ChangePasswordSerializer(data=request.data, context={"request": request})
        s.is_valid(raise_exception=True)
        return Response(s.save(), status=status.HTTP_200_OK)

# 2) Reset start (send OTP via UserOTP)
class PasswordResetStartAPIView(APIView):
    throttle_classes = [throttling.AnonRateThrottle]
    def post(self, request):
        s = PasswordResetStartSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        return Response(s.save(), status=status.HTTP_200_OK)

class PasswordResetVerifyAPIView(APIView):
    def post(self, request):
        s = PasswordResetVerifySerializer(data=request.data)
        s.is_valid(raise_exception=True)
        return Response(s.save(), status=status.HTTP_200_OK)


class PasswordResetSetAPIView(APIView):
    throttle_classes = [throttling.AnonRateThrottle]
    def post(self, request):
        s = PasswordResetSetSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        return Response(s.save(), status=status.HTTP_200_OK)




