from django.urls import path
from .views import RegisterUserAPIView,  UserListAPIView, CustomTokenObtainPairView, SendOTPAPIView, VerifyOTPAPIView, ResendOTPAPIView, CustomTokenRefreshView

urlpatterns = [
    path('register/', RegisterUserAPIView.as_view()),
    path('users/', UserListAPIView.as_view()),
    #username or email
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    #only phone_number with otp
    #path('login/', SendOTPAPIView.as_view(), name='send-otp'),
    #path('verify-otp/', VerifyOTPAPIView.as_view(), name='verify-otp'),
    #path('resend-otp/', ResendOTPAPIView.as_view(), name='resend-otp'),
]
