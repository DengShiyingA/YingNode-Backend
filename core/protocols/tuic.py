"""TUIC v5 inbound.

Params schema:
- ``port`` (int)     — listen_port (UDP)
- ``uuid`` (str)     — user UUID
- ``password`` (str) — shared password (may equal uuid, matching install.sh)
- ``cert_path``/``key_path`` — remote cert locations
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.protocols.base import ProtocolSpec
from core.protocols.registry import register


DEFAULT_CERT = "/etc/s-box/cert.pem"
DEFAULT_KEY = "/etc/s-box/private.key"


class TuicProtocol(ProtocolSpec):
    name = "tuic"
    display_name = "TUIC v5"
    default_tag = "tuic-in"

    def build_inbound(self, params: Dict[str, Any]) -> Dict[str, Any]:
        for required in ("port", "uuid", "password"):
            if not params.get(required):
                raise ValueError(f"tuic missing required param: {required}")

        return {
            "type": "tuic",
            "tag": self.default_tag,
            "listen": "::",
            "listen_port": int(params["port"]),
            "sniff": True,
            "sniff_override_destination": True,
            "users": [{"uuid": params["uuid"], "password": params["password"]}],
            "congestion_control": params.get("congestion_control", "bbr"),
            "tls": {
                "enabled": True,
                "alpn": ["h3"],
                "certificate_path": params.get("cert_path") or DEFAULT_CERT,
                "key_path": params.get("key_path") or DEFAULT_KEY,
            },
        }

    def parse_inbound(self, inbound: Dict[str, Any]) -> Dict[str, Any]:
        users = inbound.get("users") or [{}]
        tls = inbound.get("tls") or {}
        return {
            "port": inbound.get("listen_port"),
            "uuid": users[0].get("uuid", ""),
            "password": users[0].get("password", ""),
            "congestion_control": inbound.get("congestion_control", "bbr"),
            "cert_path": tls.get("certificate_path", DEFAULT_CERT),
            "key_path": tls.get("key_path", DEFAULT_KEY),
        }

    def default_params(self, port: Optional[int] = None) -> Dict[str, Any]:
        return {
            "port": port,
            "uuid": None,
            "password": None,
            "congestion_control": "bbr",
            "cert_path": DEFAULT_CERT,
            "key_path": DEFAULT_KEY,
        }


register(TuicProtocol())
