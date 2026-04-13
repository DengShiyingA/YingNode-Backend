"""Protocol backends.

A backend is the piece of software running on the remote VPS that actually
terminates the proxy protocols. Right now the only backend is sing-box; this
package exists so that adding e.g. Xray-core later is a matter of implementing
`ProtocolBackend` against `core/backends/xray.py`, not refactoring the entire
installer pipeline.

Usage::

    from core.backends import DEFAULT_BACKEND

    result = DEFAULT_BACKEND.deploy(host=..., username=..., password=..., settings=...)

Most existing call sites still import the underlying functions from
`core.installer` directly; that's fine during the transition. New code should
prefer the backend interface.
"""
from core.backends.base import ProtocolBackend
from core.backends.singbox import SingBoxBackend

DEFAULT_BACKEND: ProtocolBackend = SingBoxBackend()

__all__ = ["ProtocolBackend", "SingBoxBackend", "DEFAULT_BACKEND"]
