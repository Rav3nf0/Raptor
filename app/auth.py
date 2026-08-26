"""JWT cookie auth — sign/verify session tokens, require_auth dependency."""
from __future__ import annotations

import hashlib
import os
import time
import jwt
from fastapi import Cookie, Request
from fastapi.responses import RedirectResponse
from typing import Optional

_SECRET_ENV = "DEEPINTEL_JWT_SECRET"
_COOKIE_NAME = "deepintel_session"
_TTL_SECONDS = 8 * 3600  # 8 hours


def _secret() -> str:
    s = os.getenv(_SECRET_ENV, "")
    if s:
        return s
    # Derive a stable secret from the admin password so tokens survive pod restarts.
    pwd = os.getenv("DEEPINTEL_PASSWORD", "")
    if pwd:
        return hashlib.sha256(f"deepintel-jwt:{pwd}".encode()).hexdigest()
    raise RuntimeError("DEEPINTEL_JWT_SECRET not set and DEEPINTEL_PASSWORD not set")


def create_token(username: str) -> str:
    payload = {"sub": username, "iat": int(time.time()), "exp": int(time.time()) + _TTL_SECONDS}
    return jwt.encode(payload, _secret(), algorithm="HS256")


def verify_token(token: str) -> Optional[str]:
    try:
        data = jwt.decode(token, _secret(), algorithms=["HS256"])
        return data.get("sub")
    except Exception:
        return None


def require_auth(request: Request):
    token = request.cookies.get(_COOKIE_NAME)
    if not token or not verify_token(token):
        raise _RedirectToLogin()
    return verify_token(token)


class _RedirectToLogin(Exception):
    pass


def refresh_session_cookie(response, username: str) -> None:
    """Re-issue the session cookie on an existing response, resetting the TTL."""
    token = create_token(username)
    response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=_TTL_SECONDS,
    )


def make_session_response(redirect_to: str, username: str) -> RedirectResponse:
    token = create_token(username)
    resp = RedirectResponse(url=redirect_to, status_code=302)
    resp.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=_TTL_SECONDS,
    )
    return resp


def clear_session_response(redirect_to: str) -> RedirectResponse:
    resp = RedirectResponse(url=redirect_to, status_code=302)
    resp.delete_cookie(key=_COOKIE_NAME)
    return resp
