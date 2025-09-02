from django.urls import path
from .views import RegisterUserAPIView,  UserListAPIView, CustomTokenObtainPairView, SendOTPAPIView, VerifyOTPAPIView, ResendOTPAPIView, CustomTokenRefreshView, LogoutView, VerifyRegistrationOTPAPIView, ChangePasswordAPIView, PasswordResetStartAPIView, PasswordResetVerifyAPIView, PasswordResetSetAPIView, MeAPIView

urlpatterns = [
    path('register/', RegisterUserAPIView.as_view()),
    path('verify-registration-otp/', VerifyRegistrationOTPAPIView.as_view(), name='verify-registration-otp'),
    path('users/', UserListAPIView.as_view()),
    #username or email
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    #only phone_number login with otp
    path('send-otp/', SendOTPAPIView.as_view(), name='send-otp'),
    path('verify-otp/', VerifyOTPAPIView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPAPIView.as_view(), name='resend-otp'),
    
    
    path('change-password/', ChangePasswordAPIView.as_view(), name='change-password'),
    # accounts/urls.py
    path('password-reset/start/', PasswordResetStartAPIView.as_view(), name='password-reset-start'),
    path('password-reset/verify/', PasswordResetVerifyAPIView.as_view(), name='password-reset-verify'),
    path('password-reset/set/', PasswordResetSetAPIView.as_view(), name='password-reset-set'),

    path("logout/", LogoutView.as_view(), name="logout"),
    
    path('me/', MeAPIView.as_view(), name='me'),
]
