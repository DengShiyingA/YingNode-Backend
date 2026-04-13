"""Shadowsocks 2022 inbound.

Params schema:
- ``port`` (int)
- ``method`` (str)   — AEAD cipher (default ``2022-blake3-aes-128-gcm``)
- ``password`` (str) — base64-encoded key (16 bytes for AES-128)
"""
from __future__ import annotations

import base64
import secrets
from typing import Any, Dict, Optional

from core.protocols.base import ProtocolSpec
from core.protocols.registry import register


DEFAULT_METHOD = "2022-blake3-aes-128-gcm"
# 2022-blake3-aes-128-gcm needs a 16-byte base64 key
_KEY_BYTES_BY_METHOD = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}


def generate_shadowsocks_password(method: str = DEFAULT_METHOD) -> str:
    """Generate a base64-encoded random key of the correct length for the
    chosen method. Usable offline — no VPS round trip required."""
    n = _KEY_BYTES_BY_METHOD.get(method, 16)
    return base64.b64encode(secrets.token_bytes(n)).decode("ascii")


class Shadowsocks2022Protocol(ProtocolSpec):
    name = "shadowsocks_2022"
    display_name = "Shadowsocks 2022"
    default_tag = "ss2022-in"

    def build_inbound(self, params: Dict[str, Any]) -> Dict[str, Any]:
        for required in ("port", "method", "password"):
            if not params.get(required):
                raise ValueError(f"shadowsocks_2022 missing required param: {required}")

        return {
            "type": "shadowsocks",
            "tag": self.default_tag,
            "listen": "::",
            "listen_port": int(params["port"]),
            "sniff": True,
            "sniff_override_destination": True,
            "method": params["method"],
            "password": params["password"],
        }

    def parse_inbound(self, inbound: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "port": inbound.get("listen_port"),
            "method": inbound.get("method", DEFAULT_METHOD),
            "password": inbound.get("password", ""),
        }

    def default_params(self, port: Optional[int] = None) -> Dict[str, Any]:
        return {
            "port": port,
            "method": DEFAULT_METHOD,
            "password": generate_shadowsocks_password(DEFAULT_METHOD),
        }


register(Shadowsocks2022Protocol())
