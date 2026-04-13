"""VLESS-Reality with xtls-rprx-vision flow.

This is the REFERENCE IMPLEMENTATION for P0-3. Other protocols
(vmess_ws, hy2, tuic, trojan, ss2022, anytls) should follow the same shape:

1. Subclass ``ProtocolSpec`` in ``core/protocols/<name>.py``
2. Implement ``build_inbound`` / ``parse_inbound`` / ``default_params``
3. Register the instance at the bottom of the module

Registration happens on import — importing ``core.protocols`` gets them all.

The ``params`` schema used here:

- ``port``        (int)  — listen_port
- ``uuid``        (str)  — user UUID
- ``sni``         (str)  — Reality server_name + handshake server
- ``private_key`` (str)  — Reality private key
- ``short_id``    (str)  — Reality short_id (hex)
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, Optional

from core.protocols.base import ProtocolSpec
from core.protocols.registry import register


class VlessRealityProtocol(ProtocolSpec):
    name = "vless_reality"
    display_name = "VLESS Reality"
    default_tag = "vless-reality-in"

    def build_inbound(self, params: Dict[str, Any]) -> Dict[str, Any]:
        # Validate required fields up front so a bad API call fails fast
        # rather than producing a half-baked inbound that sing-box rejects.
        for required in ("port", "uuid", "sni", "private_key", "short_id"):
            if not params.get(required):
                raise ValueError(f"vless_reality missing required param: {required}")

        return {
            "type": "vless",
            "tag": self.default_tag,
            "listen": "::",
            "listen_port": int(params["port"]),
            "sniff": True,
            "sniff_override_destination": True,
            "users": [
                {
                    "uuid": params["uuid"],
                    "flow": "xtls-rprx-vision",
                }
            ],
            "tls": {
                "enabled": True,
                "server_name": params["sni"],
                "reality": {
                    "enabled": True,
                    "handshake": {
                        "server": params["sni"],
                        "server_port": 443,
                    },
                    "private_key": params["private_key"],
                    "short_id": [params["short_id"]],
                },
            },
        }

    def parse_inbound(self, inbound: Dict[str, Any]) -> Dict[str, Any]:
        users = inbound.get("users") or [{}]
        tls = inbound.get("tls") or {}
        reality = (tls.get("reality") or {})
        short_ids = reality.get("short_id") or [""]

        return {
            "port": inbound.get("listen_port"),
            "uuid": users[0].get("uuid", ""),
            "sni": tls.get("server_name", ""),
            "private_key": reality.get("private_key", ""),
            "short_id": short_ids[0] if short_ids else "",
        }

    def default_params(self, port: Optional[int] = None) -> Dict[str, Any]:
        """Fresh install defaults. Note: ``uuid``/``private_key`` are NOT
        set here — the caller must generate them server-side via
        ``sing-box generate uuid`` and ``sing-box generate reality-keypair``
        over SSH, then pass them in. This function only encodes what can
        safely be decided locally.
        """
        return {
            "port": port,
            "uuid": None,         # server-side: sing-box generate uuid
            "sni": "apple.com",
            "private_key": None,  # server-side: sing-box generate reality-keypair
            "short_id": secrets.token_hex(4),
        }


register(VlessRealityProtocol())
