#!/usr/bin/env python3
""" The Auth """
from flask import request
from typing import List, TypeVar


class Auth():
    """ a class to manage the API authentication """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Define which routes don't need authentication """
        if path is None or excluded_paths is None:
            return True
        if path in excluded_paths or path + '/' in excluded_paths:
            return False
        return True

    def authorization_header(self, request: request = None) -> str:
        """ Request validation """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """ Will be Implemented """
        return None
