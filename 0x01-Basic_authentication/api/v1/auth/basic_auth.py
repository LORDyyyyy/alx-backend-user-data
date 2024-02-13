#!/usr/bin/env python3
""" The Basic Auth """
from flask import request
from api.v1.auth.auth import Auth
import base64


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
        except:
            return None