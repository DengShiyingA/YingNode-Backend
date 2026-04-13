"""Bearer token authentication for the YingNode control panel.

Two failure modes are gated by the ``YINGNODE_AUTH_REQUIRED`` env var:

- ``0`` / unset (default):   auth is **advisory** — routes accept any caller
  so existing iOS clients keep working while they get updated to send tokens.
- ``1`` / ``true`` / ``yes``: auth is **enforced** — every request without a
  valid bearer token is rejected with 401.

Whitelisted paths (always open) are defined in ``PUBLIC_PATHS``: the root
health page, static assets, and the auth endpoints themselves.

The iOS client obtains a token by POSTing to ``/auth/login`` with JSON
``{"username": "...", "password": "..."}``. The first call to
``ensure_default_user()`` on an empty database bootstraps a single admin
account; the default credentials are read from the environment or fall back
to ``admin / admin`` with a stderr warning.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import sys
from datetime import datetime
from functools import wraps
from typing import Callable, Optional

from flask import Blueprint, g, jsonify, request

from core.crypto import generate_api_token, hash_password, verify_password
from core.db import get_session, init_db
from core.models import User


# Paths that never require authentication.
PUBLIC_PATHS: set[str] = {
    "/",
    "/health",
    "/auth/login",
    "/auth/bootstrap",
    "/auth/pair",
    "/static",
}


def _is_private_request() -> bool:
    """Return True if the calling HTTP client is on a loopback or private
    network. Used to gate the pairing endpoint — only callers with local
    network access may read the admin token."""
    remote = request.remote_addr or ""
    if not remote:
        return False
    try:
        ip = ipaddress.ip_address(remote)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _auth_required() -> bool:
    return (os.environ.get("YINGNODE_AUTH_REQUIRED", "").strip().lower()
            in {"1", "true", "yes", "on"})


def _is_public_path(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    for prefix in ("/static/",):
        if path.startswith(prefix):
            return True
    return False


def _extract_token() -> Optional[str]:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header.split(" ", 1)[1].strip() or None
    token = request.headers.get("X-API-Token", "").strip()
    return token or None


def authenticate_request() -> Optional[User]:
    """Look up the caller from the bearer token. Returns None if missing/invalid.

    Stashes the user on ``flask.g.current_user`` for downstream handlers.
    """
    token = _extract_token()
    if not token:
        return None

    with get_session() as session:
        user = session.query(User).filter_by(api_token=token).one_or_none()
        if user:
            # Detach from session so it's safe to reference after return.
            session.expunge(user)
        return user


def require_auth_before_request():
    """Flask ``before_request`` hook — install via ``app.before_request``."""
    g.current_user = None
    if _is_public_path(request.path):
        return None

    user = authenticate_request()
    g.current_user = user

    if _auth_required() and user is None:
        return jsonify({"ok": False, "error": "unauthorized", "message": "missing or invalid bearer token"}), 401
    return None


def require_auth(view: Callable):
    """Decorator form — use on routes that must *always* require auth
    regardless of the global flag (e.g. destructive admin actions)."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = authenticate_request()
        if not user:
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        g.current_user = user
        return view(*args, **kwargs)
    return wrapper


# ---- User bootstrap --------------------------------------------------


def ensure_default_user() -> None:
    """On first boot with an empty ``users`` table, create a single admin
    account so the panel isn't permanently locked out. Credentials:

    - ``YINGNODE_ADMIN_USERNAME`` / ``YINGNODE_ADMIN_PASSWORD`` env vars, or
    - fall back to ``admin`` / ``admin`` with a stderr warning.
    """
    username = os.environ.get("YINGNODE_ADMIN_USERNAME", "").strip() or "admin"
    password = os.environ.get("YINGNODE_ADMIN_PASSWORD", "").strip() or "admin"

    # Make sure the schema exists — auth may be called before any route
    # that would otherwise trigger init_db via core.history import.
    init_db()

    with get_session() as session:
        existing = session.query(User).count()
        if existing > 0:
            return
        user = User(
            username=username,
            password_hash=hash_password(password),
            api_token=generate_api_token(),
            is_admin=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        if password == "admin":
            print(
                f"[auth] Bootstrap admin user created with default password 'admin'. "
                f"Set YINGNODE_ADMIN_PASSWORD before first run to avoid this warning.",
                file=sys.stderr,
            )
        else:
            print(f"[auth] Bootstrap admin user '{username}' created.", file=sys.stderr)


# ---- Routes ---------------------------------------------------------


@auth_bp.route("/pair", methods=["GET"])
def pair():
    """Return the admin's bearer token to local-network callers.

    This is the primary pairing path for the iOS client:

    1. Backend is installed on a VPS (or runs on LAN).
    2. User hits ``http://<host>:5001/auth/pair`` from a device on the same
       private network (laptop on LAN, or via SSH port-forward for VPS).
    3. Response body contains the token; user types or scans it into the
       iOS app.

    The endpoint is **refused** for callers whose IP is not loopback or
    private (RFC1918 / link-local), so exposing the panel to the public
    internet doesn't leak the admin token.
    """
    if not _is_private_request():
        return jsonify({
            "ok": False,
            "error": "forbidden",
            "message": "pairing is only available from the local network",
        }), 403

    with get_session() as session:
        user = session.query(User).filter_by(is_admin=True).first()
        if not user or not user.api_token:
            return jsonify({"ok": False, "error": "no_admin"}), 500

        return jsonify({
            "ok": True,
            "pairing": {
                "host": request.host.split(":")[0],
                "port": int(request.host.split(":")[1]) if ":" in request.host else 5001,
                "token": user.api_token,
                "token_type": "Bearer",
            },
            "url": f"yingnode://pair?host={request.host.split(':')[0]}"
                   f"&port={int(request.host.split(':')[1]) if ':' in request.host else 5001}"
                   f"&token={user.api_token}",
        })


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "missing_credentials"}), 400

    with get_session() as session:
        user = session.query(User).filter_by(username=username).one_or_none()
        if not user or not verify_password(password, user.password_hash):
            return jsonify({"ok": False, "error": "invalid_credentials"}), 401

        # Rotate token on every successful login so old tokens are invalidated.
        user.api_token = generate_api_token()
        user.last_login_at = datetime.utcnow()
        session.commit()

        return jsonify({
            "ok": True,
            "user": {
                "username": user.username,
                "is_admin": bool(user.is_admin),
            },
            "token": user.api_token,
            "token_type": "Bearer",
        })


@auth_bp.route("/me", methods=["GET"])
def me():
    user = authenticate_request()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({
        "ok": True,
        "user": {
            "username": user.username,
            "is_admin": bool(user.is_admin),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        },
        "auth_required": _auth_required(),
    })


def print_pairing_banner() -> None:
    """Called once at startup to surface the pairing info in server logs.

    The admin token is only printed if it exists; callers rotating the token
    via ``/auth/login`` or manual DB update will see the new token on the
    next restart.
    """
    try:
        with get_session() as session:
            user = session.query(User).filter_by(is_admin=True).first()
            if not user or not user.api_token:
                return

            hostname = socket.gethostname()
            try:
                lan_ip = socket.gethostbyname(hostname)
            except OSError:
                lan_ip = "127.0.0.1"
            port = os.environ.get("YINGNODE_PORT", "5001")

            banner = [
                "",
                "=" * 60,
                "  YingNode Backend ready — client pairing info",
                "=" * 60,
                f"  Token:       {user.api_token}",
                f"  Pair URL:    yingnode://pair?host={lan_ip}&port={port}"
                f"&token={user.api_token}",
                f"  Pair fetch:  curl http://{lan_ip}:{port}/auth/pair",
                "=" * 60,
                "  Paste the token or Pair URL into the YingNode iOS app",
                "  (Settings → Server → Add pairing). This is a one-time step.",
                "=" * 60,
                "",
            ]
            for line in banner:
                print(line, file=sys.stderr)
    except Exception as exc:  # pragma: no cover — never block startup
        print(f"[auth] could not print pairing banner: {exc}", file=sys.stderr)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    user = authenticate_request()
    if not user:
        return jsonify({"ok": True, "message": "no session"}), 200
    with get_session() as session:
        db_user = session.query(User).filter_by(id=user.id).one_or_none()
        if db_user:
            db_user.api_token = None
            session.commit()
    return jsonify({"ok": True})
