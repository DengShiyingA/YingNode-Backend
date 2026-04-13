"""Sing-box backend.

This is a thin facade that delegates to the existing module-level functions
in ``core.installer``. It exists so call sites that want backend-agnostic
code have something to program against, and so future refactors can gather
sing-box-specific logic here without touching call sites.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.backends.base import ProtocolBackend


class SingBoxBackend(ProtocolBackend):
    """Default backend — sing-box installed via the VPS install script."""

    name = "sing-box"

    def deploy(
        self,
        host: str,
        username: str,
        password: str,
        log=None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        # Imported lazily to avoid a top-level cycle with core.installer,
        # which itself imports several core.* modules at load time.
        from core.installer import deploy_to_server
        return deploy_to_server(
            host=host,
            username=username,
            password=password,
            log=log,
            settings=settings,
        )

    def uninstall(
        self,
        host: str,
        username: str,
        password: str,
        log=None,
    ) -> Dict[str, Any]:
        from core.installer import uninstall_from_server
        return uninstall_from_server(
            host=host,
            username=username,
            password=password,
            log=log,
        )

    def summarize_ports(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        from core.installer import summarize_ports
        return summarize_ports(nodes)
