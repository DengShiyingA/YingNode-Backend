"""Protocol registry — the single source of truth for which inbound types
YingNode knows how to manage incrementally."""
from __future__ import annotations

from typing import Dict, Iterator

from core.protocols.base import ProtocolSpec


_registry: Dict[str, ProtocolSpec] = {}


def register(spec: ProtocolSpec) -> None:
    if not spec.name:
        raise ValueError("ProtocolSpec must have a non-empty name")
    if spec.name in _registry:
        raise ValueError(f"protocol {spec.name!r} already registered")
    _registry[spec.name] = spec


def get(name: str) -> ProtocolSpec:
    try:
        return _registry[name]
    except KeyError:
        raise KeyError(f"unknown protocol: {name!r}. Registered: {list(_registry)}")


def all_protocols() -> Iterator[ProtocolSpec]:
    yield from _registry.values()


def protocol_names() -> list[str]:
    return sorted(_registry.keys())
