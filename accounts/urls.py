from django.urls import path
from .views import RegisterUserAPIView,  UserListAPIView, CustomTokenObtainPairView, SendOTPAPIView, VerifyOTPAPIView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterUserAPIView.as_view()),
    path('users/', UserListAPIView.as_view()),
    #path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login/', SendOTPAPIView.as_view(), name='send-otp'),
    path('verify-otp/', VerifyOTPAPIView.as_view(), name='verify-otp'),
]
