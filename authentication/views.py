from django.shortcuts import render

# Create your views here.
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, LoginSerializer

def generate_auth_key(user):
    refresh = RefreshToken.for_user(user)
    return {
        "auth_key": str(refresh.access_token),  # 🔑 OAuth-style key
        "expires_in_days": 7
    }


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user = serializer.save()

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
