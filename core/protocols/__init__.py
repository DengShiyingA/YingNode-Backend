"""Protocol registry.

Importing this package triggers protocol registration as a side effect —
every module listed below is imported and registers its ``ProtocolSpec``
subclass on load. To add a new protocol, create the module and add an
import line here.
"""
from core.protocols.base import ProtocolSpec
from core.protocols.registry import all_protocols, get, protocol_names, register

# Register built-in protocols. Import order defines listing order.
from core.protocols import vless_reality       # noqa: F401
from core.protocols import vmess_ws            # noqa: F401
from core.protocols import hysteria2           # noqa: F401
from core.protocols import tuic                # noqa: F401
from core.protocols import trojan              # noqa: F401
from core.protocols import shadowsocks_2022    # noqa: F401
from core.protocols import anytls              # noqa: F401

__all__ = [
    "ProtocolSpec",
    "register",
    "get",
    "all_protocols",
    "protocol_names",
]
