# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserRegistrationSerializer

class RegisterUserAPIView(APIView):
    """
    API endpoint to register a new user.
    """
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#class UserView(APIView):
#    permission_classes = [permissions.IsAuthenticated]
#    def get(self, request):
#        serializer = UserSerializer(request.user)
#        return Response(serializer.data)
