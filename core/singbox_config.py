"""Pure-function sing-box config.json manipulation.

These helpers operate on an in-memory dict representing the parsed config —
no I/O, no SSH, no state. Call sites are responsible for loading the JSON,
calling a mutation function, and saving the result back.

The intent is that every P0-3 incremental operation (add/remove/patch a
single protocol inbound) reduces to:

    config = load_config(local_path)
    config = add_inbound(config, spec)
    save_config(local_path, config)
    # ... then push to the remote server

Every function here is side-effect-free and unit-testable.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---- IO (thin) -------------------------------------------------------


def load_config(path: str | Path) -> Dict[str, Any]:
    """Parse a sing-box config file. Returns a plain dict."""
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def save_config(path: str | Path, config: Dict[str, Any]) -> None:
    """Serialize a sing-box config dict to disk with stable formatting."""
    Path(path).write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_config(text: str) -> Dict[str, Any]:
    """Parse config text (as read via SSH ``cat``)."""
    return json.loads(text)


def serialize_config(config: Dict[str, Any]) -> str:
    """Serialize to the same format ``save_config`` writes."""
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"


# ---- Inbound operations ---------------------------------------------


def list_inbounds(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a shallow copy of the inbounds list. Mutations to the list
    itself don't affect ``config``, but mutations to individual items do
    — intentional so callers can read fields cheaply."""
    return list(config.get("inbounds") or [])


def find_inbound(config: Dict[str, Any], tag: str) -> Optional[Dict[str, Any]]:
    """Look up an inbound by its ``tag`` field. Returns None if absent."""
    if not tag:
        return None
    for inbound in config.get("inbounds") or []:
        if inbound.get("tag") == tag:
            return inbound
    return None


def add_inbound(config: Dict[str, Any], spec: Dict[str, Any]) -> Dict[str, Any]:
    """Append a new inbound, returning a NEW config dict (original unchanged).

    Raises ``ValueError`` if an inbound with the same tag already exists —
    use ``update_inbound`` for replacement semantics.
    """
    tag = spec.get("tag")
    if not tag:
        raise ValueError("inbound spec must have a 'tag' field")

    out = deepcopy(config)
    inbounds = list(out.get("inbounds") or [])

    if any(ib.get("tag") == tag for ib in inbounds):
        raise ValueError(f"inbound with tag {tag!r} already exists")

    inbounds.append(spec)
    out["inbounds"] = inbounds
    return out


def remove_inbound(config: Dict[str, Any], tag: str) -> Dict[str, Any]:
    """Return a new config with the matching inbound removed. No-op if tag
    is not present (no error — idempotent)."""
    out = deepcopy(config)
    inbounds = list(out.get("inbounds") or [])
    out["inbounds"] = [ib for ib in inbounds if ib.get("tag") != tag]
    return out


def update_inbound(config: Dict[str, Any], tag: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    """Shallow-merge ``patch`` into the inbound with ``tag``.

    ``patch`` keys overwrite the existing inbound's keys; nested dicts are
    replaced, not deep-merged (sing-box inbound objects are flat enough that
    shallow merge is almost always what you want).

    Raises ``ValueError`` if no inbound matches ``tag``.
    """
    out = deepcopy(config)
    inbounds = list(out.get("inbounds") or [])

    for index, inbound in enumerate(inbounds):
        if inbound.get("tag") == tag:
            merged = dict(inbound)
            merged.update(patch)
            inbounds[index] = merged
            out["inbounds"] = inbounds
            return out

    raise ValueError(f"no inbound with tag {tag!r}")


def replace_inbound(config: Dict[str, Any], tag: str, new_spec: Dict[str, Any]) -> Dict[str, Any]:
    """Fully replace the inbound with ``tag`` with ``new_spec``. The new
    spec's tag may differ from the old one.

    Raises ``ValueError`` if no inbound matches ``tag`` or the new spec
    lacks a tag.
    """
    if not new_spec.get("tag"):
        raise ValueError("new inbound spec must have a 'tag' field")

    out = deepcopy(config)
    inbounds = list(out.get("inbounds") or [])

    for index, inbound in enumerate(inbounds):
        if inbound.get("tag") == tag:
            inbounds[index] = new_spec
            out["inbounds"] = inbounds
            return out

    raise ValueError(f"no inbound with tag {tag!r}")
