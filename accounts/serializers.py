from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate

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