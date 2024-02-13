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
        return tuple(i for i in decoded_base64_authorization_header.split(':'))

    def user_object_from_credentials(self, user_email: str, user_pwd: str
                                     ) -> TypeVar('User'):
        """  that returns the User instance based on his email and password """
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        if len(User.all()) == 0:
            return None
        users = User.search({'email': user_email})
        if len(users) == 0:
            return None
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user
