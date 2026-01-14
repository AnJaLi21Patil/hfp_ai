from django.shortcuts import render

# Create your views here.
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.models import User
from .serializers import RegisterSerializer, LoginSerializer


def generate_auth_key(user):
    refresh = RefreshToken.for_user(user)
    return {
        "auth_key": str(refresh.access_token),  # 🔑 OAuth-style key
        "expires_in_days": 7
    }


# 
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings
from django.utils.encoding import force_str  # for decode later

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # 🔹 Generate verification link
        uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()  # 🔹 convert to string
        token = default_token_generator.make_token(user)
        verify_link = f"http://127.0.0.1:8000/api/verify-email/{uid}/{token}/"

        # 🔹 Send email
        send_mail(
            subject="Verify your email",
            message=f"Hi {user.first_name},\n\nClick the link below to verify your email:\n{verify_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

        return Response(
            {
                "message": "Registration successful! Please check your email for the verification link to activate your account."
            },
            status=status.HTTP_201_CREATED
        )



class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        token = generate_auth_key(user)

        return Response({
            "message": "Login successful",
            **token
        }, status=status.HTTP_200_OK)


from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str


class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, uid, token):
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)

            if default_token_generator.check_token(user, token):
                user.is_email_verified = True
                user.save()
                return Response(
                    {"message": "Email verified successfully. You can now login."},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"error": "Invalid or expired token"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Exception:
            return Response(
                {"error": "Invalid verification link"},
                status=status.HTTP_400_BAD_REQUEST
            )
