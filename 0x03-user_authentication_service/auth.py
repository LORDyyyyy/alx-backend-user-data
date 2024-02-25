#!/usr/bin/env python3
""" Auth """
import bcrypt
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Encrypting passwords"""
    bytes = password.encode("utf-8")
    hash = bcrypt.hashpw(bytes, bcrypt.gensalt())

    return hash


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
