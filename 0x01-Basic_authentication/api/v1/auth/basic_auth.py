#!/usr/bin/env python3
""" The Basic Auth """
from flask import request
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ The Basic auth Class """
