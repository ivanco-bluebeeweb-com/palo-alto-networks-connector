"""Palo Alto Networks XML API client -- shared by PAN-OS firewall and
Panorama (Panorama is a superset of the same XML API, different host and
Device Group scoping). WHY `ctx.http.*`, NOT A RAW `httpx` CLIENT -- same
convention as every other connector in this portfolio: the SDK's own async
HTTP client goes through the platform's sandboxed egress path.

Auth: username/password exchanged ONCE via `type=keygen` for an API key,
which is then stored and sent as the `key` query param on every subsequent
request (`type=config`/`type=op`/`type=commit`). On a key-rejected response
the client re-runs keygen once and retries -- same lazy-refresh shape as
this portfolio's OAuth2 client_credentials connectors, but the trigger is
an XML response code, not an HTTP status.
"""
from __future__ import annotations

from typing import Any
from xml.etree import ElementTree as ET

ACCOUNT_MISSING = "PANW_ACCOUNT_MISSING"
TOKEN_REJECTED = "PANW_TOKEN_REJECTED"
PERMISSION_DENIED = "PANW_PERMISSION_DENIED"
NOT_FOUND = "PANW_NOT_FOUND"
VALIDATION_FAILED = "PANW_VALIDATION_FAILED"
RESPONSE_UNEXPECTED = "PANW_RESPONSE_UNEXPECTED"
UNREACHABLE = "PANW_UNREACHABLE"
RATE_LIMITED = "PANW_RATE_LIMITED"
BACKEND_5XX = "PANW_BACKEND_5XX"
BACKEND_TIMEOUT = "PANW_BACKEND_TIMEOUT"
COMMIT_IN_PROGRESS = "PANW_COMMIT_IN_PROGRESS"

_MESSAGES = {
    ACCOUNT_MISSING: "No Palo Alto Networks connection is set up yet.",
    TOKEN_REJECTED: "Palo Alto Networks rejected these credentials. Check the username/password, then reconnect.",
    PERMISSION_DENIED: "Palo Alto Networks accepted the credentials, but this account lacks permission for this action.",
    NOT_FOUND: "That object was not found on the connected device.",
    VALIDATION_FAILED: "Palo Alto Networks rejected this request -- check the field values.",
    RESPONSE_UNEXPECTED: "Palo Alto Networks returned an unexpected response.",
    UNREACHABLE: "Could not reach the Palo Alto Networks device. Check the host/network.",
    RATE_LIMITED: "Palo Alto Networks is rate-limiting requests right now -- try again shortly.",
    BACKEND_5XX: "Palo Alto Networks is having trouble on its side right now.",
    BACKEND_TIMEOUT: "The request to Palo Alto Networks timed out.",
    COMMIT_IN_PROGRESS: "A commit is already running on this device -- wait for it to finish before starting another.",
}


class ClientFail(Exception):
    def __init__(self, code: str, status: int = 0, extra: str = ""):
        self.code = code
        self.status = status
        self.extra = extra
        super().__init__(f"{code} ({status}): {extra}")

    def message(self) -> str:
        base = _MESSAGES.get(self.code, "Palo Alto Networks request failed.")
        return f"{base} {self.extra}".strip() if self.extra else base


def _classify_status(status: int) -> str:
    if status == 401 or status == 403:
        return TOKEN_REJECTED
    if status == 404:
        return NOT_FOUND
    if status == 429:
        return RATE_LIMITED
    if 500 <= status < 600:
        return BACKEND_5XX
    return RESPONSE_UNEXPECTED


def _parse_xml_response(text: str) -> ET.Element:
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise ClientFail(RESPONSE_UNEXPECTED, 0, f"Could not parse XML response: {exc}")


def _check_xml_status(root: ET.Element) -> None:
    status = root.get("status", "")
    if status == "success":
        return
    code = root.get("code", "")
    msg_el = root.find(".//msg")
    msg = "".join(msg_el.itertext()) if msg_el is not None else (root.text or "")
    if code == "17" or "already in progress" in msg.lower():
        raise ClientFail(COMMIT_IN_PROGRESS, 0, msg)
    if code in ("400", "1"):
        raise ClientFail(VALIDATION_FAILED, 0, msg)
    if code in ("403",):
        raise ClientFail(PERMISSION_DENIED, 0, msg)
    if code in ("7",):
        raise ClientFail(NOT_FOUND, 0, msg)
    raise ClientFail(RESPONSE_UNEXPECTED, 0, msg or f"status={status} code={code}")


async def keygen(ctx, host: str, username: str, password: str) -> str:
    """Exchange username/password for an API key (one-time, at connect time)."""
    url = f"{host.rstrip('/')}/api/"
    try:
        resp = await ctx.http.get(url, params={"type": "keygen", "user": username, "password": password}, timeout=30)
    except Exception as exc:
        raise ClientFail(UNREACHABLE, 0, str(exc))
    if resp.status_code >= 400:
        raise ClientFail(_classify_status(resp.status_code), resp.status_code)
    root = _parse_xml_response(resp.text)
    if root.get("status") != "success":
        raise ClientFail(TOKEN_REJECTED, 0, "Invalid username or password.")
    key_el = root.find(".//key")
    if key_el is None or not key_el.text:
        raise ClientFail(RESPONSE_UNEXPECTED, 0, "No API key in keygen response.")
    return key_el.text


async def xml_request(ctx, conn: dict, params: dict[str, Any]) -> ET.Element:
    """Issue one XML API request (`type=config|op|commit`) against a PAN-OS
    firewall or Panorama connection, re-running keygen once on a rejected key."""
    host = conn.get("host", "")
    api_key = conn.get("api_key", "")
    url = f"{host.rstrip('/')}/api/"
    req_params = dict(params)
    req_params["key"] = api_key
    try:
        resp = await ctx.http.get(url, params=req_params, timeout=60)
    except Exception as exc:
        raise ClientFail(UNREACHABLE, 0, str(exc))
    if resp.status_code >= 400:
        raise ClientFail(_classify_status(resp.status_code), resp.status_code)
    root = _parse_xml_response(resp.text)
    if root.get("status") != "success":
        msg_el = root.find(".//msg")
        msg = "".join(msg_el.itertext()) if msg_el is not None else ""
        if "Invalid credentials" in msg or "Invalid key" in msg:
            raise ClientFail(TOKEN_REJECTED, 0, msg)
        _check_xml_status(root)
    return root


async def op_command(ctx, conn: dict, cmd_xml: str) -> ET.Element:
    return await xml_request(ctx, conn, {"type": "op", "cmd": cmd_xml})


async def config_get(ctx, conn: dict, xpath: str) -> ET.Element:
    return await xml_request(ctx, conn, {"type": "config", "action": "get", "xpath": xpath})


async def config_set(ctx, conn: dict, xpath: str, element_xml: str) -> ET.Element:
    return await xml_request(ctx, conn, {"type": "config", "action": "set", "xpath": xpath, "element": element_xml})


async def config_edit(ctx, conn: dict, xpath: str, element_xml: str) -> ET.Element:
    return await xml_request(ctx, conn, {"type": "config", "action": "edit", "xpath": xpath, "element": element_xml})


async def config_delete(ctx, conn: dict, xpath: str) -> ET.Element:
    return await xml_request(ctx, conn, {"type": "config", "action": "delete", "xpath": xpath})


async def config_move(ctx, conn: dict, xpath: str, where: str, dst: str = "") -> ET.Element:
    params = {"type": "config", "action": "move", "xpath": xpath, "where": where}
    if dst:
        params["dst"] = dst
    return await xml_request(ctx, conn, params)


async def commit(ctx, conn: dict, cmd_xml: str = "<commit></commit>") -> ET.Element:
    return await xml_request(ctx, conn, {"type": "commit", "cmd": cmd_xml})
