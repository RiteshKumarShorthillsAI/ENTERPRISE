from datetime import datetime
from typing import Any
from django.contrib.auth import authenticate
from django.contrib.auth.models import User 
from AIStudioEnterprise.settings import CLIENT_ID
from rest_framework.authtoken.models import Token 
from rest_framework import status
from users.models import  AccountDetail


class LoginUtils:
    @staticmethod
    def credentials_login(request)->tuple[dict, Any]:
        try:
            email = username = request.data.get("email")
            password = request.META.get("HTTP_PASSWORD")
            _user = authenticate(
                request,
                # email = email,
                username= username,
                password = password
            )
            if not _user:
                return (
                    { "message": "Invalid email or password" }, 
                    status.HTTP_403_FORBIDDEN
                )
            
            account, is_first_login = AccountDetail.objects.get_or_create(
                user_id = _user.id
            )
            _token, _ =Token.objects.get_or_create(user_id=_user.id)
            _user.last_login = datetime.now()
            _user.save()
            return (
                {
                    "message": "Login Successful",
                    "email": _user.username,
                    "access_token": _token.key,
                    "coin_popup": is_first_login
                },
                status.HTTP_202_ACCEPTED
            )
        except Exception as e:
            return (
                {"message": str(e)},
                status.HTTP_408_REQUEST_TIMEOUT
            )
    
    @staticmethod
    def google_auth_login(username)->tuple[dict, Any]:
        try:
            # Get or create the user in your system
            _user, created = User.objects.get_or_create(username=username)
            if created:
                account = AccountDetail.objects.create(user_id = _user.id)

            _token, _ = Token.objects.get_or_create(user_id=_user.id)
            _user.last_login = datetime.now()
            _user.save()
            return (
                {
                    "message": "Token verification successful",
                    "email": _user.username,
                    "access_token": str(_token),
                    "coin_popup": created
                },
                status.HTTP_200_OK,
            )
        except Exception as e:
            return (
                {"message": str(e)}, status.HTTP_400_BAD_REQUEST
            )