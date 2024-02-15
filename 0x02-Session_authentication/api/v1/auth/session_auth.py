#!/usr/bin/env python3
""" SessionAuth Class """
from api.v1.auth.auth import Auth
from uuid import uuid4
# from typing import TypeVar
# import base64
# from models.user import User


class SessionAuth(Auth):
    """ The Session Authentication Class"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ creates a Session ID for a user_id """
        if user_id is None or not isinstance(user_id, str):
            return None

        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id
