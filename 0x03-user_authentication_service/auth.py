#!/usr/bin/env python3
""" Auth """
import bcrypt


def _hash_password(password: str) -> bytes:
    """ Encrypting passwords """
    bytes = password.encode('utf-8')
    hash = bcrypt.hashpw(bytes, bcrypt.gensalt())

    return hash
