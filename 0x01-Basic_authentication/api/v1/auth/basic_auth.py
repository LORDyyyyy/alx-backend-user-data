#!/usr/bin/env python3
""" The Basic Auth """
from flask import request
from api.v1.auth.auth import Auth


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
