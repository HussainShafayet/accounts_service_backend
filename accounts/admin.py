from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, UserOTP

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ("email", "username", "first_name", "last_name", "phone_number", "is_active", "is_staff", "is_verified")
    list_filter = ("is_staff", "is_verified", "is_active")
    search_fields = ("email", "username", "phone_number", "first_name", "last_name", "address")
    ordering = ("-date_joined",)

    fieldsets = (
    (None, {"fields": ("email", "password")}),
    ("Personal info", {"fields": ("username", "first_name", "last_name", "phone_number", "profile_picture", "address")}),
    ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "is_verified", "groups", "user_permissions")}),
    ("Important dates", {"fields": ("last_login", "date_joined")}),
)


    add_fieldsets = (
    (None, {
        "classes": ("wide",),
        "fields": ("email", "password1", "password2", "first_name", "last_name", "phone_number", "address", "is_active", "is_staff", "is_superuser"),
    }),
)


@admin.register(UserOTP)
class UserOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'temp_token', 'created_at', 'is_used')
    list_filter = ('is_used', 'created_at')
    search_fields = ('user__phone_number', 'otp', 'temp_token')
    readonly_fields = ('created_at',)


