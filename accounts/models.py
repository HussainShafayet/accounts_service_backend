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
    # Core identity
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    username = models.CharField(max_length=50, blank=True, null=True, unique=True)

    # Contact
    phone_number = models.CharField(max_length=20, blank=True, null=True, unique=True)

    # Profile
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    profile_picture = models.URLField(blank=True, null=True)

    # Status
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)  # email/phone verification
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)

    # Metadata
    date_joined = models.DateTimeField(default=timezone.now)

    # Manager
    objects = CustomUserManager()

    # Login identifier
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # username optional for superuser

    def __str__(self):
        return self.email or str(self.id)




class PhoneOTP(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=timezone.now)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.phone_number} - {self.otp}"
