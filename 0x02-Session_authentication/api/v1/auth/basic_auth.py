#!/usr/bin/env python3
""" The Basic Auth """
from api.v1.auth.auth import Auth
from typing import TypeVar
import base64
from models.user import User


class BasicAuth(Auth):
    """The Basic auth Class"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """that returns the Base64 part
        of the Authorization header for a Basic Authentication
        """
        if (
            authorization_header is None
            or not isinstance(authorization_header, str)
            or not authorization_header.startswith("Basic ")
        ):
            return None
        return authorization_header.split()[-1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """ returns the decoded value of a Base64 string
            base64_authorization_header
        """
        if base64_authorization_header is None or not isinstance(
                       base64_authorization_header, str):
            return None
        try:
            value = base64.b64decode(base64_authorization_header)
            return value.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """ returns the user email and password
            from the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        data = decoded_base64_authorization_header.split(':')
        email = data[0]
        password = ':'.join(data[1:])
        return (email, password)

    def user_object_from_credentials(self, user_email: str, user_pwd: str
                                     ) -> TypeVar('User'):
        """  that returns the User instance based on his email and password """
        if user_pwd is None or user_email is None:
            return None
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        if len(User.all()) == 0:
            return None
        users = User.search({'email': user_email})
        if len(users) == 0:
            return None
        user = users[0]
        user_test = User.get(user.id)
        if not user.__eq__(user_test):
            return None
        if not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """ overloads Auth and retrieves the User instance for a request """
        auth_header = super().authorization_header(request)
        if auth_header is None:
            return None

        auth_header_value = self.extract_base64_authorization_header(
            auth_header)
        if auth_header_value is None:
            return None

        auth_header_decoded_value = self.decode_base64_authorization_header(
                                    auth_header_value)
        if auth_header_decoded_value is None:
            return None

        user_data = self.extract_user_credentials(auth_header_decoded_value)
        if user_data == (None, None):
            return None

        user = self.user_object_from_credentials(user_data[0], user_data[1])
        return user
