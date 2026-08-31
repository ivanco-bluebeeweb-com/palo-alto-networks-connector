"""Chat functions for Panorama (centralized management): Device Groups,
Managed Devices, Templates, Panorama-scoped Security Rules, and Push to
managed firewalls. Built on pan_client.py / schemas.py -- Panorama exposes
the SAME XML API shape as PAN-OS, so this module reuses pan_client.py's
transport but with Panorama-specific xpaths (shared/device-group scoping
instead of vsys scoping) and `commit` -> Panorama's "push to devices"
operation instead of a plain local commit.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import pan_client as pc
from app import chat
from handlers_connection import _authed_panorama
from schemas import (
    ListDeviceGroupsParams, DeviceGroup, DeviceGroupList,
    ListManagedDevicesParams, ManagedDevice, ManagedDeviceList, GetManagedDeviceParams,
    ListTemplatesParams, Template, TemplateList,
    ListPanoramaSecurityRulesParams, PanoramaSecurityRule, PanoramaSecurityRuleList,
    PushToDevicesParams, PushResult,
)

_DEVICE_GROUP_ALL = "/config/devices/entry[@name='localhost.localdomain']/device-group"
_TEMPLATE_ALL = "/config/devices/entry[@name='localhost.localdomain']/template"
_DG_RULEBASE = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']/pre-rulebase/security/rules"


def _text(el, tag: str, default: str = "") -> str:
    node = el.find(tag) if el is not None else None
    return (node.text or default) if node is not None else default


@chat.function(
    "list_device_groups",
    "List device groups configured on the connected Panorama -- Panorama's grouping mechanism for pushing shared policy to a set of managed firewalls.",
    action_type="read",
    data_model=DeviceGroupList,
)
async def list_device_groups(ctx, params: ListDeviceGroupsParams) -> ActionResult:
    conn = await _authed_panorama(ctx, getattr(params, "connection_id", ""))
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _DEVICE_GROUP_ALL)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//device-group/entry"):
        name = entry.get("name", "")
        devices = entry.findall("devices/entry")
        items.append(DeviceGroup(id=name, title=name, device_count=len(devices)))
    return ActionResult.success(DeviceGroupList(title=f"{len(items)} device group(s)", items=items), summary="Device groups listed.")


@chat.function(
    "list_managed_devices",
    "List PAN-OS firewalls managed by the connected Panorama, with their connection status and software version.",
    action_type="read",
    data_model=ManagedDeviceList,
)
async def list_managed_devices(ctx, params: ListManagedDevicesParams) -> ActionResult:
    conn = await _authed_panorama(ctx, getattr(params, "connection_id", ""))
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.op_command(ctx, conn, "<show><devices><all></all></devices></show>")
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//devices/entry"):
        serial = entry.get("name", "") or _text(entry, "serial")
        connected = _text(entry, "connected") == "yes"
        items.append(ManagedDevice(
            id=serial, title=_text(entry, "hostname") or serial, serial=serial,
            connected=connected, sw_version=_text(entry, "sw-version"),
        ))
    return ActionResult.success(ManagedDeviceList(title=f"{len(items)} managed device(s)", items=items), summary="Managed devices listed.")


@chat.function(
    "get_managed_device",
    "Read one Panorama-managed firewall's status in full by serial number.",
    action_type="read",
    data_model=ManagedDevice,
)
async def get_managed_device(ctx, params: GetManagedDeviceParams) -> ActionResult:
    conn = await _authed_panorama(ctx, getattr(params, "connection_id", ""))
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.op_command(ctx, conn, "<show><devices><all></all></devices></show>")
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    for entry in root.findall(".//devices/entry"):
        serial = entry.get("name", "") or _text(entry, "serial")
        if serial == params.serial:
            return ActionResult.success(ManagedDevice(
                id=serial, title=_text(entry, "hostname") or serial, serial=serial,
                connected=_text(entry, "connected") == "yes", sw_version=_text(entry, "sw-version"),
            ), summary="Managed device retrieved.")
    return ActionResult.error(f"Managed device '{params.serial}' not found.")


@chat.function(
    "list_templates",
    "List configuration templates defined on the connected Panorama.",
    action_type="read",
    data_model=TemplateList,
)
async def list_templates(ctx, params: ListTemplatesParams) -> ActionResult:
    conn = await _authed_panorama(ctx, getattr(params, "connection_id", ""))
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _TEMPLATE_ALL)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = [Template(id=e.get("name", ""), title=e.get("name", "")) for e in root.findall(".//template/entry")]
    return ActionResult.success(TemplateList(title=f"{len(items)} template(s)", items=items), summary="Templates listed.")


@chat.function(
    "list_panorama_security_rules",
    "List pre-rulebase security rules for one device group on the connected Panorama.",
    action_type="read",
    data_model=PanoramaSecurityRuleList,
)
async def list_panorama_security_rules(ctx, params: ListPanoramaSecurityRulesParams) -> ActionResult:
    conn = await _authed_panorama(ctx, getattr(params, "connection_id", ""))
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _DG_RULEBASE.format(dg=params.device_group))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//rules/entry"):
        name = entry.get("name", "")
        items.append(PanoramaSecurityRule(
            id=name, title=name, action=_text(entry, "action"),
            disabled=_text(entry, "disabled") == "yes",
        ))
    return ActionResult.success(PanoramaSecurityRuleList(title=f"{len(items)} security rule(s) in '{params.device_group}'", items=items), summary="Panorama security rules listed.")


@chat.function(
    "push_to_devices",
    "Push the connected Panorama's pending configuration to a device group's managed firewalls -- same idea as commit_config on PAN-OS, but fans out to a whole fleet. Firewalls in the device group won't see policy changes until this runs.",
    action_type="write",
    chain_callable=True,
    data_model=PushResult,
    event="palo-alto-networks-connector.push_to_devices",
    effects=["update:resource"],
)
async def push_to_devices(ctx, params: PushToDevicesParams) -> ActionResult:
    conn = await _authed_panorama(ctx, getattr(params, "connection_id", ""))
    if isinstance(conn, ActionResult):
        return conn
    desc = f"<description>{params.description}</description>" if params.description else ""
    cmd = (
        "<commit-all><shared-policy>"
        f"<device-group><entry name=\"{params.device_group}\"/></device-group>"
        f"{desc}"
        "</shared-policy></commit-all>"
    )
    try:
        root = await pc.commit(ctx, conn, cmd)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    job_node = root.find(".//job")
    job_id = (job_node.text or "") if job_node is not None else ""
    return ActionResult.success(PushResult(
        id=job_id or "push", title=f"Push job {job_id}" if job_id else "Push submitted",
        job_id=job_id, status="pending",
    ), summary="Push to devices done.")
