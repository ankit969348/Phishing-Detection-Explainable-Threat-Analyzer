from django.urls import path
from .views import ScanView, HistoryView
from .auth_views import SignupView, LoginView, LogoutView, MeView, SendResetOTPView, ResetPasswordView

urlpatterns = [
    path("scan/", ScanView.as_view(), name="scan"),
    path("history/", HistoryView.as_view(), name="history"),
    path("auth/signup/", SignupView.as_view(), name="signup"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/me/", MeView.as_view(), name="me"),
    path("auth/send-reset-otp/", SendResetOTPView.as_view(), name="send-reset-otp"),
    path("auth/reset-password/", ResetPasswordView.as_view(), name="reset-password"),
]
