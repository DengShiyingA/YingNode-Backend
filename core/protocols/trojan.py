"""Trojan-TLS inbound.

Params schema:
- ``port`` (int)
- ``password`` (str)
- ``sni`` (str)  — server_name
- ``name`` (str) — user label (default ``yingnode``)
- ``cert_path`` / ``key_path``
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.protocols.base import ProtocolSpec
from core.protocols.registry import register


DEFAULT_CERT = "/etc/s-box/cert.pem"
DEFAULT_KEY = "/etc/s-box/private.key"


class TrojanProtocol(ProtocolSpec):
    name = "trojan"
    display_name = "Trojan"
    default_tag = "trojan-in"

    def build_inbound(self, params: Dict[str, Any]) -> Dict[str, Any]:
        for required in ("port", "password"):
            if not params.get(required):
                raise ValueError(f"trojan missing required param: {required}")

        return {
            "type": "trojan",
            "tag": self.default_tag,
            "listen": "::",
            "listen_port": int(params["port"]),
            "sniff": True,
            "sniff_override_destination": True,
            "users": [
                {
                    "name": params.get("name") or "yingnode",
                    "password": params["password"],
                }
            ],
            "tls": {
                "enabled": True,
                "server_name": params.get("sni") or "apple.com",
                "certificate_path": params.get("cert_path") or DEFAULT_CERT,
                "key_path": params.get("key_path") or DEFAULT_KEY,
            },
        }

    def parse_inbound(self, inbound: Dict[str, Any]) -> Dict[str, Any]:
        users = inbound.get("users") or [{}]
        tls = inbound.get("tls") or {}
        return {
            "port": inbound.get("listen_port"),
            "name": users[0].get("name", ""),
            "password": users[0].get("password", ""),
            "sni": tls.get("server_name", ""),
            "cert_path": tls.get("certificate_path", DEFAULT_CERT),
            "key_path": tls.get("key_path", DEFAULT_KEY),
        }

    def default_params(self, port: Optional[int] = None) -> Dict[str, Any]:
        return {
            "port": port,
            "name": "yingnode",
            "password": None,
            "sni": "apple.com",
            "cert_path": DEFAULT_CERT,
            "key_path": DEFAULT_KEY,
        }


register(TrojanProtocol())
