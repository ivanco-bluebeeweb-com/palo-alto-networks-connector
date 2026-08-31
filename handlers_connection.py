"""Chat functions for Palo Alto Networks Connector: connection management
(PAN-OS + Panorama, two independent BYOK auth surfaces sharing the same
XML API keygen flow). Built on pan_client.py / schemas.py, following the
same shape as Fortinet Connector's handlers_connection.py.
"""
from __future__ import annotations

import json
import uuid

from imperal_sdk import ActionResult

import pan_client as pc
from app import ext, chat
from schemas import (
    NoParams,
    ConnectPanosParams, ConnectPanoramaParams,
    ProviderConnection, ProviderConnectionList,
    DisconnectParams, DeleteResult,
)

_SECRET_NAME = "panw_connections"


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_SECRET_NAME)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, connections: list[dict]) -> None:
    await ctx.secrets.set(_SECRET_NAME, json.dumps(connections))


async def _resolve_connection(ctx, kind: str, connection_id: str = "") -> dict | None:
    connections = [c for c in await _load_connections(ctx) if c.get("kind") == kind]
    if not connections:
        return None
    if connection_id:
        for c in connections:
            if c.get("id") == connection_id:
                return c
        return None
    return connections[0]


async def _authed_panos(ctx, connection_id: str = "") -> dict | ActionResult:
    conn = await _resolve_connection(ctx, "panos", connection_id)
    if conn is None:
        return ActionResult.error(pc._MESSAGES[pc.ACCOUNT_MISSING])
    return conn


async def _authed_panorama(ctx, connection_id: str = "") -> dict | ActionResult:
    conn = await _resolve_connection(ctx, "panorama", connection_id)
    if conn is None:
        return ActionResult.error(pc._MESSAGES[pc.ACCOUNT_MISSING])
    return conn


@chat.function(
    "connect_panos",
    "Connect a PAN-OS firewall by saving its host and admin credentials, after exchanging them once for an API key.",
    action_type="write",
    data_model=ProviderConnection,
)
async def connect_panos(ctx, params: ConnectPanosParams) -> ActionResult:
    try:
        api_key = await pc.keygen(ctx, params.host, params.username, params.password)
    except pc.ClientFail as exc:
        return ActionResult.error(exc.message(), retryable=exc.status in (0, 429, 500, 502, 503))
    connections = await _load_connections(ctx)
    conn_id = str(uuid.uuid4())
    label = params.label or params.host
    connections.append({
        "id": conn_id, "kind": "panos", "host": params.host,
        "api_key": api_key, "label": label,
    })
    await _save_connections(ctx, connections)
    return ActionResult.success(ProviderConnection(
        id=conn_id, title=label, kind="panos", connected=True, detail=params.host,
    ), summary="Panos connected.")


@chat.function(
    "connect_panorama",
    "Connect a Panorama instance by saving its host and admin credentials, after exchanging them once for an API key.",
    action_type="write",
    data_model=ProviderConnection,
)
async def connect_panorama(ctx, params: ConnectPanoramaParams) -> ActionResult:
    try:
        api_key = await pc.keygen(ctx, params.host, params.username, params.password)
    except pc.ClientFail as exc:
        return ActionResult.error(exc.message(), retryable=exc.status in (0, 429, 500, 502, 503))
    connections = await _load_connections(ctx)
    conn_id = str(uuid.uuid4())
    label = params.label or params.host
    connections.append({
        "id": conn_id, "kind": "panorama", "host": params.host,
        "api_key": api_key, "label": label,
    })
    await _save_connections(ctx, connections)
    return ActionResult.success(ProviderConnection(
        id=conn_id, title=label, kind="panorama", connected=True, detail=params.host,
    ), summary="Panorama connected.")


@chat.function(
    "list_connections",
    "List the connected PAN-OS firewalls and Panorama instances.",
    action_type="read",
    data_model=ProviderConnectionList,
)
async def list_connections(ctx, params: NoParams) -> ActionResult:
    connections = await _load_connections(ctx)
    items = [
        ProviderConnection(
            id=c.get("id", ""), title=c.get("label", "") or c.get("host", ""),
            kind=c.get("kind", ""), connected=True, detail=c.get("host", ""),
        )
        for c in connections
    ]
    return ActionResult.success(ProviderConnectionList(items=items), summary="Connections listed.")


@chat.function(
    "disconnect_palo_alto",
    "Disconnect a PAN-OS firewall or Panorama instance: deletes the saved API key. Nothing on the device itself is changed.",
    action_type="write",
    data_model=DeleteResult,
)
async def disconnect_palo_alto(ctx, params: DisconnectParams) -> ActionResult:
    connections = await _load_connections(ctx)
    remaining = [c for c in connections if c.get("id") != params.connection_id]
    if len(remaining) == len(connections):
        return ActionResult.error("Connection not found.")
    await _save_connections(ctx, remaining)
    return ActionResult.success(DeleteResult(deleted=True), summary="Palo alto disconnected.")
