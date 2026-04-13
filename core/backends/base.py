"""Abstract protocol backend interface.

Each concrete backend implements the operations YingNode-Backend performs
against a remote VPS running the proxy software (install, uninstall, read
generated node configs, validate runtime state). See
`core/backends/singbox.py` for the reference implementation.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class ProtocolBackend(ABC):
    """Interface every backend must implement.

    All methods are synchronous — the Flask request thread calls directly,
    and long-running operations are already wrapped in the job system at a
    higher layer (see ``core.runtime``).
    """

    name: str = "abstract"

    # ---- lifecycle on the remote VPS ---------------------------------

    @abstractmethod
    def deploy(
        self,
        host: str,
        username: str,
        password: str,
        log=None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Install and start the backend on the target VPS.

        Returns a dict describing what was installed — at minimum
        ``{"success": bool, "nodes": list, "validation": dict}``.
        """

    @abstractmethod
    def uninstall(
        self,
        host: str,
        username: str,
        password: str,
        log=None,
    ) -> Dict[str, Any]:
        """Stop and remove the backend from the target VPS."""

    # ---- introspection -----------------------------------------------

    @abstractmethod
    def summarize_ports(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Given a parsed node list, return a per-protocol port summary."""

    @property
    def supported_protocols(self) -> List[str]:
        """Human-readable protocol identifiers supported by this backend.

        Override if your backend supports a subset or different set.
        """
        return [
            "vless-reality",
            "vmess-ws",
            "hysteria2",
            "tuic-v5",
            "trojan",
            "shadowsocks-2022",
            "anytls",
        ]
