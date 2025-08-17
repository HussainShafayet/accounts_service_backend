from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib import admin

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

admin.site.register(CustomUser)