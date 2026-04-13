"""Password hashing + field encryption utilities.

- **User passwords** (login credentials for the YingNode panel itself): bcrypt,
  one-way hash.
- **VPS SSH passwords** (credentials we need to be able to read back to log
  into the remote machine): Fernet symmetric encryption with a key derived
  from ``YINGNODE_SECRET_KEY``.

The secret key is read from the environment (via .env). If it is unset on
first boot, a new key is generated and written into a local file so the value
survives restarts — losing it means all stored VPS passwords become unreadable,
so treat it like a private key and back it up.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path
from typing import Optional

import bcrypt
from cryptography.fernet import Fernet, InvalidToken


_BASE_DIR = Path(__file__).resolve().parent.parent
_SECRET_FILE = _BASE_DIR / "data" / "secret_key"


def _load_secret_key() -> str:
    """Return a persistent secret key, bootstrapping one on first run."""
    env_value = os.environ.get("YINGNODE_SECRET_KEY", "").strip()
    if env_value:
        return env_value

    if _SECRET_FILE.exists():
        value = _SECRET_FILE.read_text(encoding="utf-8").strip()
        if value:
            return value

    # First-time bootstrap: generate 256 bits of entropy and persist it.
    _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(32)
    _SECRET_FILE.write_text(value, encoding="utf-8")
    try:
        os.chmod(_SECRET_FILE, 0o600)
    except OSError:
        pass
    return value


def _fernet() -> Fernet:
    raw = _load_secret_key()
    # Fernet requires a 32-byte urlsafe-base64 key; derive one from whatever
    # the user supplied via SHA-256 so arbitrary-length secrets work.
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


# ---- User password hashing (bcrypt) ---------------------------------


def hash_password(password: str) -> str:
    if not password:
        return ""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


# ---- VPS password encryption (Fernet, reversible) -------------------


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


# ---- Random token generation ----------------------------------------


def generate_api_token() -> str:
    """A 32-byte URL-safe random token for bearer authentication."""
    return secrets.token_urlsafe(32)
