#
# Copyright (c) 2017, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

import functools

import argon2

try:
    import secrets
except ImportError:
    from .compat import secrets

import flask

USER_TOKENS = dict()

# FIXME: Yes, this is insecure, but it'll do for a demo
USER_PASSWORDS = {
    'admin': '$argon2i$v=19$m=512,t=2,p=2'
    '$pFBhJgKOtM96r1n38GQX5Q$OE2vG2Dg/VZXE60W/fyHwA',
}

__all__ = (
    'requires_auth',
    'get_user',
    'login',
    'logout',
)


def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = flask.request.headers.get('X-AUTH-TOKEN')
        if token and token in USER_TOKENS:
            resp = flask.make_response(f(*args, **kwargs))
            resp.headers['Vary'] = 'X-AUTH-TOKEN'
            return resp
        else:
            return '', 401
    return decorated


def login(username, password):
    try:
        argon2.PasswordHasher().verify(
            USER_PASSWORDS[username],
            password,
        )
    except (argon2.exceptions.VerifyMismatchError, KeyError):
        return None

    token = secrets.token_urlsafe()

    USER_TOKENS[token] = username

    return {
        "user": username,
        "token": token,
        "role": [],
    }


def logout(user, token):
    try:
        return USER_TOKENS.pop(token) == user
    except KeyError:
        return False
