import re
from AIStudioEnterprise.settings import SIMPLE_JWT, SEND_EMAIL, SEND_MAIL_PASSWORD
import jwt
from rest_framework import status
from datetime import datetime
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from users.models import User


class Utils:

    @staticmethod
    def send_email(subject: str, body: str, to: str) -> bool:
        try:
            smtp_server = "smtp.outlook.com"
            port = 587
            sender_email = SEND_EMAIL
            sender_password = SEND_MAIL_PASSWORD
            receiver_email = to
            # Create a multipart message and set headers
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = receiver_email
            message["Subject"] = subject

            message.attach(MIMEText(body, "html"))

            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_server, port) as server:
                server.ehlo()
                server.starttls(context=context)
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, receiver_email, message.as_string())
            return True
        except:
            return False

    @staticmethod
    def password_validation(password) -> bool:
        try:
            if len(password) < 8:
                return False
            if re.search("[a-z]", password) is None:
                return False
            if re.search("[A-Z]", password) is None:
                return False
            if re.search("[0-9]", password) is None:
                return False
            if re.search("[_@$]", password) is None:
                return False
            return True
        except:
            return False

    @staticmethod
    def authenticate_jwt_token(verification_jwt_token) -> dict:
        try:
            payload = jwt.decode(
                jwt=verification_jwt_token,
                key=SIMPLE_JWT["SIGNING_KEY"],
                algorithms=SIMPLE_JWT["ALGORITHM"],
            )
            return {
                "message": "Valid Mail verification token",
                "status": status.HTTP_200_OK,
                "payload": payload,
            }
        except:
            return {
                "message": "Invalid verification Link. Please request a new verification.",
                "status": status.HTTP_403_FORBIDDEN,
            }

    @staticmethod
    def get_jwt_token_via_user_for_verification(payload) -> str:
        try:
            current_time = datetime.now()
            expriy_time = current_time + SIMPLE_JWT["EMAIL_VERIFY_TIME_LIMIT"]
            payload["exp"] = expriy_time
            payload["iat"] = current_time
            return jwt.encode(
                payload=payload, key=SIMPLE_JWT["SIGNING_KEY"], algorithm="HS256"
            )
        except:
            raise Exception("Unable to generate the auth link, pls try again later.")

    @staticmethod
    def validate_password_and_confirm_password(password, confirm_password) -> bool:
        try:
            if not password or not confirm_password:
                raise ValueError("Password and Confirm Password are required")
            if password != confirm_password:
                raise ValueError("Password and Confirm Password do not match")
            if not Utils.password_validation(password):
                raise ValueError(
                    "Enter a strong password with minimum 8 characters, 1 uppercase, 1 lowercase, 1 digit and 1 special character"
                )
            return True
        except ValueError as e:
            raise ValueError(str(e))

    @staticmethod
    def validate_and_extract_username(access_token) -> str:
        try:
            payload = Utils.authenticate_jwt_token(access_token)
            if payload['status'] != 200:
                raise Exception(payload['message'])
            return payload['payload']['username']
        except Exception as e:
            raise Exception(f"Error validating token: {str(e)}")

    @staticmethod
    def get_vaidated_user_to_set_password(request) -> str:
        """
        Retrieves a validated user based on the provided request.

        This function is used in Email verification & Set Password view, and Reset Password view to:
            1. Validate the password and confirm password.
            2. Validate the access token and extract the user.

        Args:
            request (Request): The request object.

        Returns:
            User: The validated user object, or None if validation fails.
        """
        try:
            jwt_token = request.data.get("token", None)
            password = request.META.get("HTTP_PASSWORD", None)
            confirm_password = request.META.get("HTTP_PASSWORD2", None)
            if not jwt_token:
                raise Exception("Invalid Authentication Link")
            if not Utils.validate_password_and_confirm_password(
                password, confirm_password
            ):
                raise Exception("Password validation failed")

            return Utils.validate_and_extract_username(jwt_token)
        except User.DoesNotExist:
            raise Exception("User doesn't exists.")
        except Exception as e:
            raise Exception(e)
