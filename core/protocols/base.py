"""Base protocol interface.

Each protocol module in ``core.protocols`` implements one concrete class and
registers it with the registry. A protocol is responsible for three things:

1. Building a sing-box inbound dict from a parameter dict (``build_inbound``).
2. Parsing an existing inbound dict back to parameters (``parse_inbound``).
3. Providing default parameter values for fresh installs (``default_params``).

Everything is pure Python — no I/O, no SSH, no state. Operations that touch
remote VPS go through ``core.installer``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class ProtocolSpec(ABC):
    """Abstract base for sing-box inbound protocol handlers."""

    name: str = ""              # Stable identifier, e.g. "vless_reality"
    display_name: str = ""      # Human-readable, e.g. "VLESS Reality"
    default_tag: str = ""       # Default sing-box tag, e.g. "vless-in"
    default_port_range: tuple[int, int] = (20000, 45000)

    @abstractmethod
    def build_inbound(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Build a sing-box inbound object from ``params``.

        ``params`` keys vary per protocol. See each subclass's docstring.
        Returns a dict ready to append to ``config["inbounds"]``.
        """

    @abstractmethod
    def parse_inbound(self, inbound: Dict[str, Any]) -> Dict[str, Any]:
        """Reverse of ``build_inbound``: extract user-editable params from
        an existing sing-box inbound. Used when the backend needs to show
        current values in the UI."""

    def default_params(self, port: Optional[int] = None) -> Dict[str, Any]:
        """Return a parameter dict suitable for a fresh install. Subclasses
        override to populate defaults (e.g. random UUID, Reality keypair)."""
        return {"port": port} if port is not None else {}

    def tag_for(self, params: Dict[str, Any]) -> str:
        """Compute the sing-box tag used by an inbound built from these
        params. Default is ``default_tag`` — protocols that support
        multiple instances on the same server override this to include the
        port or a user label."""
        return self.default_tag
