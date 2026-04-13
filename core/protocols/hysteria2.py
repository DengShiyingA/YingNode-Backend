"""Hysteria2 inbound.

Params schema:
- ``port`` (int)     — listen_port (UDP)
- ``password`` (str) — shared password (defaults to a UUID for parity with install.sh)
- ``cert_path`` (str) — path to cert on VPS (default ``/etc/s-box/cert.pem``)
- ``key_path`` (str)  — path to private key on VPS (default ``/etc/s-box/private.key``)
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.protocols.base import ProtocolSpec
from core.protocols.registry import register


DEFAULT_CERT = "/etc/s-box/cert.pem"
DEFAULT_KEY = "/etc/s-box/private.key"


class Hysteria2Protocol(ProtocolSpec):
    name = "hysteria2"
    display_name = "Hysteria2"
    default_tag = "hy2-in"

    def build_inbound(self, params: Dict[str, Any]) -> Dict[str, Any]:
        for required in ("port", "password"):
            if not params.get(required):
                raise ValueError(f"hysteria2 missing required param: {required}")

        return {
            "type": "hysteria2",
            "tag": self.default_tag,
            "listen": "::",
            "listen_port": int(params["port"]),
            "sniff": True,
            "sniff_override_destination": True,
            "ignore_client_bandwidth": False,
            "users": [{"password": params["password"]}],
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
            "password": users[0].get("password", ""),
            "cert_path": tls.get("certificate_path", DEFAULT_CERT),
            "key_path": tls.get("key_path", DEFAULT_KEY),
        }

    def default_params(self, port: Optional[int] = None) -> Dict[str, Any]:
        return {
            "port": port,
            "password": None,
            "cert_path": DEFAULT_CERT,
            "key_path": DEFAULT_KEY,
        }


register(Hysteria2Protocol())
