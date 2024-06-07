from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
# from rest_framework.authentication import TokenAuthentication
from rest_framework import status
from users.models import UserVerification
from django.core.validators import validate_email
from .utils import Utils
from AIStudioEnterprise.settings import (
    PASSWORD_SET_BASEURL,
    CLIENT_ID,
    PASSWORD_RESET_BASEURL,
)
from google.auth.transport import requests
from google.oauth2 import id_token
from django.contrib.auth.models import User
from django.db.models import F, Case, Value, When, OuterRef, Subquery
from rest_framework.permissions import IsAuthenticated
from users.logic_source import LoginUtils, UserAIProductManage


class SendEmailRegistrationView(APIView):

    @staticmethod
    def generate_token_and_send_email(id, username):
        try:
            jwt_token = Utils.get_jwt_token_via_user_for_verification(
                payload={"user_id": id, "username": username}
            )
            verification_link = f"{PASSWORD_SET_BASEURL}/?token={jwt_token}"
            subject = "Activate Your Account"
            body = """
                <html>
                <head></head>
                <body>
                    <p>Hi,</p>
                    <p>Thanks for signing up with us. Please click the link below to verify your email address.</p>
                    <a href="{verification_link}">Verify Email</a>
                    <p>Thanks</p>
            """.format(
                verification_link=verification_link
            )
            to = username
            sendStatus = Utils.send_email(subject, body, to)
            if not sendStatus:
                raise Exception("Email not sent.")
        except Exception as e:
            return Response({"Message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        try:
            signup_type = request.GET.get("signup_type", None)
            if not signup_type or signup_type not in ["CREDENTIALS", "GMAIL_AUTH_2.0"]:
                return Response(
                    {"Message": "Invalid request."}, status=status.HTTP_400_BAD_REQUEST
                )
            userEmailAddress = None
            if signup_type == "CREDENTIALS":
                userEmailAddress = request.data.get("email")
            else:
                google_auth_token = request.data.get("id_token")
                if not google_auth_token:
                    return Response(
                        {"Message": "Invalid Google Auth 2.0."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                try:
                    userAuthInfo = id_token.verify_oauth2_token(
                        google_auth_token, requests.Request(), CLIENT_ID
                    )
                    userEmailAddress = userAuthInfo["email"]
                except:
                    return Response(
                        {"Message": "Invalid Google Auth 2.0."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            validate_email(userEmailAddress)
            if not userEmailAddress:
                if signup_type == "CREDENTIALS":
                    return Response(
                        {"Message": "Invalid email."}, status=status.HTTP_400_BAD_REQUEST
                    )
                return Response(
                    {"Message": "Invalid Gmail."}, status=status.HTTP_400_BAD_REQUEST
                )
            try:
                user = User.objects.get(username__iexact=userEmailAddress)
            except User.DoesNotExist:
                user = User.objects.create_user(
                    username=userEmailAddress,
                    email = userEmailAddress,
                    is_active=not (signup_type == "CREDENTIALS"),
                )
                user.save()

            if user.is_active:
                return Response(
                    {"Message": "Your Email Is already registered."},
                    status=status.HTTP_200_OK,
                )

            if signup_type == "CREDENTIALS":
                self.generate_token_and_send_email(user.id, user.username)
                return Response(
                    {"Message": "Pls, verified your email account."},
                    status=status.HTTP_201_CREATED,
                )
            return Response(
                {"Message": "You are registered successfully."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response({"Message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView, LoginUtils):

    def post(self, request):
        try:
            LOGIN_TYPE = request.GET.get("login_type", None)
            if not LOGIN_TYPE or LOGIN_TYPE not in ["GOOGLE_AUTH", "CREDENTIALS"]:
                return Response(
                    {"message": "Invalid request."}, status=status.HTTP_400_BAD_REQUEST
                )
            if LOGIN_TYPE == "GOOGLE_AUTH":
                google_auth_token = request.data.get("token")
                response_data = Utils.authenticate_jwt_token(google_auth_token)
                payload = response_data.get("payload")
                if not payload:
                    return Response(response_data, status=response_data["status"])
                res, res_status = self.google_auth_login(payload["username"])
            else:
                res, res_status = self.credentials_login(request=request)
            return Response(res, status=res_status)
        except Exception as e:
            return Response(
                {"Message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserProductsView(APIView, UserAIProductManage):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            return Response(
                self.Get_User_Assigned_Products_Status(user_id=request.user.id)
            )
        except Exception as e:
            return Response({"Message": str(e)}, status=status.HTTP_408_REQUEST_TIMEOUT)

    def put(self, request):
        try:
            return Response(self.UnlockedAIProductByInfo(request=request))
        except ValueError as e:
            return Response({"Message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            raise Exception(e)


class EmailVerificationAndSetPassword(APIView):
    def put(self, request):
        try:
            user = User.objects.get(username=Utils.get_vaidated_user_to_set_password(request))
            if user.is_active:
                return Response(
                    {"Message": "You have already set your password."},
                    status=status.HTTP_200_OK,
                )
            user.set_password(request.META.get("HTTP_PASSWORD"))
            user.is_active = True
            user.save()
            return Response(
                {"Message": "Email verified & Password successfully set."},
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response({"Message": "You are not registered with us, pls registered yourself"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PasswordReset(APIView, Utils):
    def post(self, request):
        try:
            userEmail = request.data.get("email", None)
            if not userEmail:
                return Response(
                    {"Message": "Email addrees is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user = User.objects.get(username=userEmail)
            user_verification_obj = None
            jwt_auth_token = self.get_jwt_token_via_user_for_verification(
                payload={"user_id": user.id, "username": user.username}
            )
            try:
                user_verification_obj = UserVerification.objects.get(user_id=user.id)
                user_verification_obj.verification_jwt = jwt_auth_token
                user_verification_obj.max_retry_count = 3
            except UserVerification.DoesNotExist:
                user_verification_obj = UserVerification(
                    **{"user": user, "verification_jwt": jwt_auth_token}
                )
            user_verification_obj.save()
            if not user_verification_obj:
                return Response(
                    {
                        "Message": "Unable to process your request at this time, pls try again later."
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            verification_link = f"{PASSWORD_RESET_BASEURL}/?token={jwt_auth_token}"
            subject = "Reset Your Password"
            body = """
                <html>
                <head></head>
                <body>
                    <p>Hi,</p>
                    <p>Please click the link below to reset your password.</p>
                    <a href="{verification_link}">Reset Password</a>
                    <p>Thanks</p>
            """.format(verification_link=verification_link)
            to = user.username
            sendStatus = self.send_email(subject, body, to)
            if not sendStatus:
                return Response(
                    "We are unable to send the password reset mail. Please retry again later",
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            return Response(
                {"Message": "Password reset link sent to your registered email"},
                status=status.HTTP_200_OK,
            )

        except User.DoesNotExist:
            return Response(
                {"Message": "You are not registered with us, pls registered yourself"},
                status=status.HTTP_404_NOT_FOUND,
            )

        except Exception as e:
            return Response({"Message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        try:
            # We will check the recieved token is valid or not
            # If valid then we will check the user is valid or not
            # Then match the user with the token user
            username = Utils.get_vaidated_user_to_set_password(request)
            user_verification_obj = UserVerification.objects.get(
                user__username = username
            )
            
            # Update the retry count if not excced the limit
            if not user_verification_obj.haveRetryLimit():
                user_verification_obj.delete()
                return Response(
                    {
                        "Message": "You have reached the maximum retry limit. Please resend password reset verification."
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            if user_verification_obj.verification_jwt != request.data.get("token"):
                user_verification_obj.save()
                return Response(
                    {
                        "Message": "Invalid Link. Please retry with latest token."
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            user = User.objects.get(id=user_verification_obj.user_id)
            user.set_password(request.META.get("HTTP_PASSWORD"))
            user.save()
            # After reset the password we will delete the auth entry
            # Prevent from multiple password reset and misuse of the link
            user_verification_obj.delete()
            return Response(
                {
                    "Message": "Password successfully reset. Please login with your new password."
                },
                status=status.HTTP_200_OK,
            )
        except UserVerification.DoesNotExist:
            return Response(
                {
                    "Message": "Invalid auth link. Please resend password reset verification."
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        except Exception as e:
            return Response({"Message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
