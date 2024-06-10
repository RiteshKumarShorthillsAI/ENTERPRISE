from django.urls import path
from users.views import (
    SendEmailRegistrationView,
    UserLogin,
    UserProductsView,
    EmailVerificationAndSetPassword,
    PasswordReset,
)
from .google_connector import google_drive_auth, google_drive_callback

urlpatterns = [
    path("mail-verify/", SendEmailRegistrationView.as_view(), name="mail-verify"),
    path("login/", UserLogin.as_view(), name="token"),
    path(
        "verification-link-set-password/",
        EmailVerificationAndSetPassword.as_view(),
        name="set-password",
    ),
    path(
        "send-reset-password-email/",
        PasswordReset.as_view(),
        name="send-reset-password-email",
    ),
    path("user-products/", UserProductsView.as_view(), name="user-products"),
    path('google-drive/auth/', google_drive_auth, name='google_drive_auth'),
    path('google-drive/callback/', google_drive_callback, name='google_drive_callback'),
]
