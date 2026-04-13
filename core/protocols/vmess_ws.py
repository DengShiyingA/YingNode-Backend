"""VMess over WebSocket inbound.

Params schema:
- ``port`` (int)       — listen_port
- ``uuid`` (str)       — user UUID
- ``path`` (str)       — WebSocket path (defaults to ``/<uuid>-vm``)
- ``host`` (str)       — WebSocket Host header (defaults to ``www.bing.com``)
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.protocols.base import ProtocolSpec
from core.protocols.registry import register


class VmessWsProtocol(ProtocolSpec):
    name = "vmess_ws"
    display_name = "VMess WebSocket"
    default_tag = "vmess-sb"

    def build_inbound(self, params: Dict[str, Any]) -> Dict[str, Any]:
        for required in ("port", "uuid"):
            if not params.get(required):
                raise ValueError(f"vmess_ws missing required param: {required}")

        uuid_ = params["uuid"]
        path = params.get("path") or f"/{uuid_}-vm"
        host = params.get("host") or "www.bing.com"

        return {
            "type": "vmess",
            "tag": self.default_tag,
            "listen": "::",
            "listen_port": int(params["port"]),
            "sniff": True,
            "sniff_override_destination": True,
            "users": [{"uuid": uuid_, "alterId": 0}],
            "transport": {
                "type": "ws",
                "path": path,
                "headers": {"Host": host},
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol",
            },
        }

    def parse_inbound(self, inbound: Dict[str, Any]) -> Dict[str, Any]:
        users = inbound.get("users") or [{}]
        transport = inbound.get("transport") or {}
        headers = transport.get("headers") or {}
        return {
            "port": inbound.get("listen_port"),
            "uuid": users[0].get("uuid", ""),
            "path": transport.get("path", ""),
            "host": headers.get("Host", ""),
        }

    def default_params(self, port: Optional[int] = None) -> Dict[str, Any]:
        return {"port": port, "uuid": None, "path": None, "host": "www.bing.com"}


register(VmessWsProtocol())
