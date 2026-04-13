"""REST routes for incremental protocol management.

Mounted under /api/vps/<server_id>/protocols by app.py. Every route is
an HTTP wrapper around a function in core.protocol_manager — the routes
themselves just handle JSON parsing, status codes, and error mapping.

Endpoints:

    GET    /api/vps/<sid>/protocols
        List protocol instances installed on the given VPS.

    POST   /api/vps/<sid>/protocols
        Install a new protocol. Body: {"proto": "vless_reality", "params": {...}}
        If params omits generated fields (uuid, private_key, ...) the
        server generates them over SSH.

    DELETE /api/vps/<sid>/protocols/<tag>
        Uninstall the protocol with this sing-box tag.

    GET    /api/vps/<sid>/protocols/reconcile
        Compare DB state to VPS on-disk config. Read-only diff report.

    GET    /api/protocols/available
        List protocol types the backend can install.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from core.protocol_manager import (
    ProtocolManagerError,
    install_protocol,
    list_protocols,
    reconcile,
    uninstall_protocol,
)
from core.protocols import all_protocols, protocol_names


api_protocols_bp = Blueprint("api_protocols", __name__, url_prefix="/api")


def _json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


@api_protocols_bp.route("/protocols/available", methods=["GET"])
def available_protocols():
    specs = list(all_protocols())
    return jsonify({
        "ok": True,
        "protocols": [
            {
                "name": s.name,
                "display_name": s.display_name,
                "default_tag": s.default_tag,
            }
            for s in specs
        ],
    })


@api_protocols_bp.route("/vps/<int:server_id>/protocols", methods=["GET"])
def list_server_protocols(server_id: int):
    try:
        rows = list_protocols(server_id)
    except ProtocolManagerError as exc:
        return _json_error(str(exc), 404)
    return jsonify({"ok": True, "server_id": server_id, "protocols": rows})


@api_protocols_bp.route("/vps/<int:server_id>/protocols", methods=["POST"])
def install_server_protocol(server_id: int):
    data = request.get_json(silent=True) or {}
    proto = (data.get("proto") or "").strip()
    params = data.get("params") or {}

    if not proto:
        return _json_error("'proto' is required", 400)
    if proto not in protocol_names():
        return _json_error(f"unknown protocol: {proto}", 400)
    if not isinstance(params, dict):
        return _json_error("'params' must be an object", 400)

    try:
        result = install_protocol(server_id, proto, params)
    except ProtocolManagerError as exc:
        return _json_error(str(exc), 500)

    return jsonify(result), 201


@api_protocols_bp.route("/vps/<int:server_id>/protocols/<tag>", methods=["DELETE"])
def uninstall_server_protocol(server_id: int, tag: str):
    try:
        result = uninstall_protocol(server_id, tag)
    except ProtocolManagerError as exc:
        return _json_error(str(exc), 500)
    return jsonify(result)


@api_protocols_bp.route("/vps/<int:server_id>/protocols/reconcile", methods=["GET"])
def reconcile_server(server_id: int):
    try:
        report = reconcile(server_id)
    except ProtocolManagerError as exc:
        return _json_error(str(exc), 500)
    return jsonify(report)
