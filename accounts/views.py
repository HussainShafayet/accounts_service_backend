# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserRegistrationSerializer, UserSerializer, SendOTPSerializer, VerifyOTPSerializer, ResendOTPSerializer, RegistrationOTPVerifySerializer
from .models import CustomUser, UserOTP
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from django.conf import settings

#login
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer

class RegisterUserAPIView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                otp_obj = user.otps.latest('created_at')  # Assuming OTP always exists
                temp_token = otp_obj.temp_token

                return Response(
                    {
                        'message': 'User registered successfully. OTP pending.',
                        'temp_token': str(temp_token),
                        # 'otp': otp_value,  # REMOVE in production
                    },
                    status=status.HTTP_201_CREATED
                )
            except UserOTP.DoesNotExist:
                return Response(
                    {'error': 'OTP generation failed.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            except Exception as e:
                return Response(
                    {'error': 'Something went wrong.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
class VerifyRegistrationOTPAPIView(APIView):
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

        # data['access'] is the access token returned by the serializer
        access_token = data['access']
        refresh_token = data['refresh']  # get refresh token

        # Prepare response
        response = Response(
            {
                "access": access_token,
                "user": data['user']
            },
            status=status.HTTP_200_OK
        )

        # Set refresh token as HttpOnly cookie
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=not settings.DEBUG,  # set True in production (HTTPS)
            samesite='Strict',  # or 'Lax' if needed
            path='/'  # only send cookie to refresh endpoint
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
        data = serializer.validated_data

        # data['access'] is the access token returned by the serializer
        access_token = data['access']
        refresh_token = data['refresh']  # get refresh token

        # Prepare response
        response = Response(
            {
                "access": access_token,
            },
            status=status.HTTP_200_OK
        )

        # Set refresh token as HttpOnly cookie
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=not settings.DEBUG,  # set True in production (HTTPS)
            samesite='Strict',  # or 'Lax' if needed
            path='/'
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
    



