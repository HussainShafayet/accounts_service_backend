#from django.contrib.auth.models import AbstractUser
#from django.db import models
#from django.contrib import admin

#class CustomUser(AbstractUser):
#    email = models.EmailField(unique=True)
#    phone_number = models.CharField(max_length=20, blank=True)

#    USERNAME_FIELD = 'email'
#    REQUIRED_FIELDS = ['username']

#admin.site.register(CustomUser)


from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
import uuid
from django.contrib.auth import get_user_model
from datetime import timedelta


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with an email and password"""
        if not email:
            raise ValueError("The Email field is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True, blank=True, null=True)
    username = models.CharField(max_length=50, blank=True, null=True, unique=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True, unique=True)

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    address = models.TextField(default="Temporary Address")

    profile_picture = models.URLField(blank=True, null=True)

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email or self.phone_number or str(self.id)




User = get_user_model();
class PhoneOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    temp_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(default=timezone.now)
    is_used = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        # ensure unique temp_token
        if not self.temp_token:
            while True:
                token = uuid.uuid4()
                if not PhoneOTP.objects.filter(temp_token=token).exists():
                    self.temp_token = token
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.phone_number} - {self.otp}"
class UserOTP(models.Model):
    OTP_TYPE_CHOICES = (
        ('email', 'Email'),
        ('phone', 'Phone'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    otp = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=10, choices=OTP_TYPE_CHOICES)
    temp_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_used = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # set expires_at if not already set
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        # ensure unique temp_token
        if not self.temp_token:
            while True:
                token = uuid.uuid4()
                if not UserOTP.objects.filter(temp_token=token).exists():
                    self.temp_token = token
                    break
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() <= self.expires_at and not self.is_used

    def __str__(self):
        return f"{self.user.email or self.user.phone_number} - {self.otp_type} - {self.otp}"



