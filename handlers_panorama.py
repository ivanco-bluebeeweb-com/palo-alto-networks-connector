"""Chat functions for Panorama (fleet management): device groups, managed
devices, templates, per-device-group security rules, push. Built on
pan_client.py / schemas.py, following the same shape as Fortinet
Connector's handlers_fortimanager.py.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import pan_client as pc
from app import chat
from handlers_connection import _authed_panorama
from schemas import (
    ListDeviceGroupsParams, DeviceGroup, DeviceGroupList,
    ListManagedDevicesParams, ManagedDevice, ManagedDeviceList,
    GetManagedDeviceParams,
    ListTemplatesParams, Template, TemplateList,
    ListPanoramaSecurityRulesParams, PanoramaSecurityRule, PanoramaSecurityRuleList,
    PushToDevicesParams, PushResult,
)


@chat.function(
    "list_device_groups",
    "List device groups configured on the connected Panorama.",
    action_type="read",
    data_model=DeviceGroupList,
)
async def list_device_groups(ctx, params: ListDeviceGroupsParams) -> ActionResult:
    conn = await _authed_panorama(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, "/config/devices/entry/device-group")
    except pc.ClientFail as e:
        return ActionResult(success=False, error=e.message())
    items = []
    for entry in root.findall(".//device-group/entry"):
        name = entry.get("name", "")
        devices = entry.findall("./devices/entry")
        items.append(DeviceGroup(id=name, title=name, device_count=len(devices)))
    return ActionResult(success=True, data=DeviceGroupList(title=f"{len(items)} device group(s)", items=items))


@chat.function(
    "list_managed_devices",
    "List FortiGate-equivalent PAN-OS devices managed by the connected Panorama.",
    action_type="read",
    data_model=ManagedDeviceList,
)
async def list_managed_devices(ctx, params: ListManagedDevicesParams) -> ActionResult:
    conn = await _authed_panorama(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.op_command(ctx, conn, "<show><devices><all></all></devices></show>")
    except pc.ClientFail as e:
        return ActionResult(success=False, error=e.message())
    items = []
    for entry in root.findall(".//devices/entry"):
        serial = entry.get("name", "") or (entry.findtext("serial") or "")
        hostname = entry.findtext("hostname", "")
        connected = (entry.findtext("connected", "no") == "yes")
        sw_version = entry.findtext("sw-version", "")
        items.append(ManagedDevice(id=serial, title=hostname or serial, serial=serial, connected=connected, sw_version=sw_version))
    return ActionResult(success=True, data=ManagedDeviceList(title=f"{len(items)} managed device(s)", items=items))


@chat.function(
    "get_managed_device",
    "Read one Panorama-managed PAN-OS device in full by serial number.",
    action_type="read",
    data_model=ManagedDevice,
)
async def get_managed_device(ctx, params: GetManagedDeviceParams) -> ActionResult:
    conn = await _authed_panorama(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.op_command(ctx, conn, "<show><devices><all></all></devices></show>")
    except pc.ClientFail as e:
        return ActionResult(success=False, error=e.message())
    for entry in root.findall(".//devices/entry"):
        serial = entry.get("name", "") or (entry.findtext("serial") or "")
        if serial == params.serial:
            hostname = entry.findtext("hostname", "")
            connected = (entry.findtext("connected", "no") == "yes")
            sw_version = entry.findtext("sw-version", "")
            return ActionResult(success=True, data=ManagedDevice(id=serial, title=hostname or serial, serial=serial, connected=connected, sw_version=sw_version))
    return ActionResult(success=False, error=f"Managed device with serial '{params.serial}' not found.")


@chat.function(
    "list_templates",
    "List configuration templates defined on the connected Panorama.",
    action_type="read",
    data_model=TemplateList,
)
async def list_templates(ctx, params: ListTemplatesParams) -> ActionResult:
    conn = await _authed_panorama(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, "/config/devices/entry/template")
    except pc.ClientFail as e:
        return ActionResult(success=False, error=e.message())
    items = [Template(id=e.get("name", ""), title=e.get("name", "")) for e in root.findall(".//template/entry")]
    return ActionResult(success=True, data=TemplateList(title=f"{len(items)} template(s)", items=items))


@chat.function(
    "list_panorama_security_rules",
    "List security (pre/post) rules configured for a Panorama device group.",
    action_type="read",
    data_model=PanoramaSecurityRuleList,
)
async def list_panorama_security_rules(ctx, params: ListPanoramaSecurityRulesParams) -> ActionResult:
    conn = await _authed_panorama(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    xpath = f"/config/devices/entry/device-group/entry[@name='{params.device_group}']/pre-rulebase/security/rules"
    try:
        root = await pc.config_get(ctx, conn, xpath)
    except pc.ClientFail as e:
        return ActionResult(success=False, error=e.message())
    items = []
    for entry in root.findall(".//rules/entry"):
        name = entry.get("name", "")
        action = entry.findtext("action", "")
        disabled = entry.findtext("disabled", "no") == "yes"
        items.append(PanoramaSecurityRule(id=name, title=name, action=action, disabled=disabled))
    return ActionResult(success=True, data=PanoramaSecurityRuleList(title=f"{len(items)} rule(s) in '{params.device_group}'", items=items))


@chat.function(
    "push_to_devices",
    "Push a Panorama device group's configuration out to its managed devices -- same as the 'Push' button in the Panorama web UI.",
    action_type="write",
    data_model=PushResult,
)
async def push_to_devices(ctx, params: PushToDevicesParams) -> ActionResult:
    conn = await _authed_panorama(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    cmd = (
        f"<commit-all><shared-policy><device-group><entry name='{params.device_group}'/></device-group>"
        f"{'<description>' + params.description + '</description>' if params.description else ''}"
        f"</shared-policy></commit-all>"
    )
    try:
        root = await pc.commit(ctx, conn, cmd)
    except pc.ClientFail as e:
        return ActionResult(success=False, error=e.message())
    job_id = root.findtext(".//job", "") or ""
    return ActionResult(success=True, data=PushResult(id=job_id, title=f"Push job {job_id}", job_id=job_id, status="pending"))
