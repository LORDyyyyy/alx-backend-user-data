#!/usr/bin/env python3
""" Auth """
import bcrypt
from uuid import uuid4
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Encrypting passwords"""
    bytes = password.encode("utf-8")
    hash = bcrypt.hashpw(bytes, bcrypt.gensalt())

    return hash


def _generate_uuid() -> str:
    """Generate UUID"""

    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """register a new user if not exists"""
        try:
            self._db.find_user_by(email=email)
        except Exception:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Validate user"""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode("utf-8"),
                                  user.hashed_password)
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """Returns the session ID as a string"""

        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """eturns the corresponding User or None"""

        if session_id is None:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """sets the session_id of a user to None"""
        try:
            user = self._db.find_user_by(id=user_id)
        except Exception:
            return None
        self._db.update_user(user.id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """generate a UUID and update the user’s reset_token database field"""

        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except Exception:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """ update password for a user by his reset_token"""

        try:
            user = self._db.find_user_by(reset_token=reset_token)
            self._db.update_user(user.id,
                                 hashed_password=_hash_password(password),
                                 reset_token=None)
            return None
        except Exception:
            raise ValueError
