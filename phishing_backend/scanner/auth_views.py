import secrets
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.db import connection
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authtoken.models import Token

User = get_user_model()

def ensure_otp_cache_table():
    with connection.cursor() as c:
        c.execute("CREATE TABLE IF NOT EXISTS threatlens_otp_cache (cache_key varchar(255) PRIMARY KEY, value text NOT NULL, expires timestamptz NOT NULL);")


class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = (request.data.get("username") or "").strip()
        email = (request.data.get("email") or "").strip().lower()
        password = request.data.get("password") or ""

        if not username or not email or not password:
            return Response({"error": "Username, email and password are required."}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists."}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email__iexact=email).exists():
            return Response({"error": "Email already registered."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(password)
        except DjangoValidationError as error:
            return Response({"error": list(error.messages)}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, email=email, password=password)
        token, _ = Token.objects.get_or_create(user=user)

        return Response({
            "message": "Account created successfully.",
            "token": token.key,
            "user": {"id": user.id, "username": user.username, "email": user.email}
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = (request.data.get("username") or "").strip()
        password = (request.data.get("password") or "")

        if not username or not password:
            return Response({"error": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=username, password=password)
        if user is None:
            return Response({"error": "Invalid username or password."}, status=status.HTTP_401_UNAUTHORIZED)

        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            "message": "Login successful.",
            "token": token.key,
            "user": {"id": user.id, "username": user.username, "email": user.email}
        })


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.auth.delete()
        return Response({"message": "Logout successful."})


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"id": request.user.id, "username": request.user.username, "email": request.user.email})


class SendResetOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        if not email:
            return Response({"error": "Registered email is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email__iexact=email).first()
        if user is None:
            return Response({"error": "No account found with this email."}, status=status.HTTP_404_NOT_FOUND)

        otp = f"{secrets.randbelow(900000) + 100000}"
        ensure_otp_cache_table()
        cache.set(f"threatlens_otp_{email}", otp, timeout=600)

        print(f"\n[THREATLENS OTP] Email: {email} | Username: {user.username} | OTP: {otp}\n")

        try:
            send_mail(
                subject="ThreatLens Password Reset OTP",
                message=f"Hello {user.username},\n\nYour ThreatLens password reset OTP is: {otp}\nThis code expires in 10 minutes.",
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@threatlens.local"),
                recipient_list=[email],
                fail_silently=False,
            )
            msg = f"6-digit OTP sent to {email}."
        except Exception:
            msg = "OTP generated (check backend terminal in demo mode)."

        return Response({"message": msg, "username": user.username}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        otp = (request.data.get("otp") or "").strip()
        new_password = request.data.get("new_password") or ""

        if not email or not otp or not new_password:
            return Response({"error": "Email, OTP, and new password are required."}, status=status.HTTP_400_BAD_REQUEST)

        ensure_otp_cache_table()
        saved_otp = cache.get(f"threatlens_otp_{email}")
        if not saved_otp or saved_otp != otp:
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email__iexact=email).first()
        if user is None:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as error:
            return Response({"error": list(error.messages)}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        cache.delete(f"threatlens_otp_{email}")
        Token.objects.filter(user=user).delete()

        return Response({"message": "Password reset successful. Please sign in with your new password."}, status=status.HTTP_200_OK)
