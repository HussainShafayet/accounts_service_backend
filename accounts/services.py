from .models import UserOTP
from django.core.mail import send_mail
import random

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(user):
    """
    Send OTP to user after registration.
    Priority: phone > email
    """
    otp = generate_otp()

    if user.phone_number:
        otp_type = 'phone'
        # Save OTP in DB
        UserOTP.objects.create(user=user, otp=otp, otp_type=otp_type)
        # Send SMS (replace with your SMS service)
        print(f"Send OTP {otp} to phone {user.phone_number}")

    elif user.email:
        otp_type = 'email'
        UserOTP.objects.create(user=user, otp=otp, otp_type=otp_type)
        # Send email
        send_mail(
            'Your OTP Code',
            f'Use this OTP to activate your account: {otp}',
            'shafayetsec09@gmail.com',
            [user.email],
            fail_silently=False,
        )
    else:
        # Should never happen if validation ensures at least email/phone
        raise ValueError("User has no contact info")
