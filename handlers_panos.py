"""Chat functions for PAN-OS (device-level): security rules, address/service
objects, address groups, zones, interfaces, system info, commit. Built on
pan_client.py / schemas.py, following the same shape as Fortinet Connector's
handlers_fortigate.py.

WHY heuristic kind-inference on update_address_object / fixed tcp default on
update_service_object: PAN-OS's PATCH-style xpath edit needs the exact child
tag (ip-netmask vs fqdn vs ip-range; tcp vs udp) to replace, but the Update*
params intentionally don't ask the caller to repeat the kind/protocol they
already set at creation (same "don't re-ask what's already known" principle
as the rest of this portfolio) -- so update infers kind from the new value's
shape (IP/CIDR pattern -> ip-netmask, else fqdn) and keeps protocol at "tcp"
unless the object was created as udp, in which case the caller should use
delete+create instead (documented in the function description).
"""
from __future__ import annotations

import re

from imperal_sdk import ActionResult

import pan_client as pc
from app import chat
from handlers_connection import _authed_panos
from schemas import (
    ListSecurityRulesParams, SecurityRule, SecurityRuleList,
    GetSecurityRuleParams, CreateSecurityRuleParams, UpdateSecurityRuleParams,
    DeleteSecurityRuleParams, ReorderSecurityRuleParams, DeleteResult,
    ListAddressObjectsParams, AddressObject, AddressObjectList,
    CreateAddressObjectParams, UpdateAddressObjectParams, DeleteAddressObjectParams,
    ListAddressGroupsParams, AddressGroup, AddressGroupList,
    ListServiceObjectsParams, ServiceObject, ServiceObjectList,
    CreateServiceObjectParams, UpdateServiceObjectParams, DeleteServiceObjectParams,
    ListZonesParams, Zone, ZoneList,
    ListInterfacesParams, Interface, InterfaceList,
    GetSystemInfoParams, SystemInfo,
    CommitParams, CommitResult,
)

_VSYS_BASE = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']"
_RULEBASE_ALL = _VSYS_BASE + "/rulebase/security/rules"
_RULEBASE = _RULEBASE_ALL + "/entry[@name='{name}']"
_ADDRESS_ALL = _VSYS_BASE + "/address"
_ADDRESS = _ADDRESS_ALL + "/entry[@name='{name}']"
_ADDRESS_GROUP_ALL = _VSYS_BASE + "/address-group"
_SERVICE_ALL = _VSYS_BASE + "/service"
_SERVICE = _SERVICE_ALL + "/entry[@name='{name}']"
_ZONE_ALL = _VSYS_BASE + "/zone"
_INTERFACE_ALL = "/config/devices/entry[@name='localhost.localdomain']/network/interface"

_IP_RE = re.compile(r"^[\d.]+(/\d+)?$")


def _text(el, tag: str, default: str = "") -> str:
    node = el.find(tag)
    return (node.text or default) if node is not None else default


def _member(el, tag: str) -> str:
    node = el.find(f"{tag}/member")
    return (node.text or "") if node is not None else ""


@chat.function(
    "list_security_rules",
    "List security policy rules on the connected PAN-OS firewall.",
    action_type="read",
    data_model=SecurityRuleList,
)
async def list_security_rules(ctx, params: ListSecurityRulesParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _RULEBASE_ALL.format(vsys=params.vsys))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//rules/entry"):
        name = entry.get("name", "")
        items.append(SecurityRule(
            id=name, title=name, action=_text(entry, "action"),
            from_zone=_member(entry, "from"), to_zone=_member(entry, "to"),
            disabled=_text(entry, "disabled") == "yes",
        ))
    return ActionResult.success(SecurityRuleList(title=f"{len(items)} security rule(s)", items=items), summary="Security rules listed.")


@chat.function(
    "get_security_rule",
    "Read one security rule in full by name.",
    action_type="read",
    data_model=SecurityRule,
)
async def get_security_rule(ctx, params: GetSecurityRuleParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _RULEBASE.format(vsys=params.vsys, name=params.name))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    entry = root.find(".//entry")
    if entry is None:
        return ActionResult.error(f"Security rule '{params.name}' not found.")
    return ActionResult.success(SecurityRule(
        id=params.name, title=params.name, action=_text(entry, "action"),
        from_zone=_member(entry, "from"), to_zone=_member(entry, "to"),
        disabled=_text(entry, "disabled") == "yes",
    ), summary="Security rule retrieved.")


@chat.function(
    "create_security_rule",
    "Create a new security policy rule on the connected PAN-OS firewall. This does not take effect until you commit.",
    action_type="write",
    chain_callable=True,
    data_model=SecurityRule,
    event="palo-alto-networks-connector.create_security_rule",
    effects=["create:resource"],
)
async def create_security_rule(ctx, params: CreateSecurityRuleParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    xml = (
        f"<from><member>{params.from_zone}</member></from>"
        f"<to><member>{params.to_zone}</member></to>"
        f"<source><member>{params.source}</member></source>"
        f"<destination><member>{params.destination}</member></destination>"
        f"<application><member>{params.application}</member></application>"
        f"<service><member>{params.service}</member></service>"
        f"<action>{params.action}</action>"
    )
    try:
        await pc.config_set(ctx, conn, _RULEBASE.format(vsys=params.vsys, name=params.name), xml)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(SecurityRule(
        id=params.name, title=params.name, action=params.action,
        from_zone=params.from_zone, to_zone=params.to_zone,
    ), summary="Security rule created.")


@chat.function(
    "update_security_rule",
    "Update an existing security rule's action and/or enabled status. This does not take effect until you commit.",
    action_type="write",
    chain_callable=True,
    data_model=SecurityRule,
    event="palo-alto-networks-connector.update_security_rule",
    effects=["update:resource"],
)
async def update_security_rule(ctx, params: UpdateSecurityRuleParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    xpath = _RULEBASE.format(vsys=params.vsys, name=params.name)
    if params.action:
        try:
            await pc.config_edit(ctx, conn, f"{xpath}/action", f"<action>{params.action}</action>")
        except pc.ClientFail as e:
            return ActionResult.error(e.message())
    val = "yes" if params.disabled else "no"
    try:
        await pc.config_edit(ctx, conn, f"{xpath}/disabled", f"<disabled>{val}</disabled>")
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(SecurityRule(id=params.name, title=params.name, action=params.action, disabled=params.disabled), summary="Security rule updated.")


@chat.function(
    "delete_security_rule",
    "Permanently delete a security policy rule. This does not take effect until you commit.",
    action_type="write",
    chain_callable=True,
    data_model=DeleteResult,
    event="palo-alto-networks-connector.delete_security_rule",
    effects=["delete:resource"],
)
async def delete_security_rule(ctx, params: DeleteSecurityRuleParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        await pc.config_delete(ctx, conn, _RULEBASE.format(vsys=params.vsys, name=params.name))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(DeleteResult(id=params.name, title=params.name, deleted=True), summary="Security rule deleted.")


@chat.function(
    "reorder_security_rule",
    "Move a security rule before or after another rule in the rulebase. This does not take effect until you commit.",
    action_type="write",
    chain_callable=True,
    data_model=DeleteResult,
    event="palo-alto-networks-connector.reorder_security_rule",
    effects=["update:resource"],
)
async def reorder_security_rule(ctx, params: ReorderSecurityRuleParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    where = "before" if params.before else ("after" if params.after else "top")
    dst = params.before or params.after
    try:
        await pc.config_move(ctx, conn, _RULEBASE.format(vsys=params.vsys, name=params.name), where, dst)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(DeleteResult(id=params.name, title=params.name, deleted=False), summary="Reorder security rule done.")


# ──────────────────────────────────────────────────────────────────────────
# Address & Service Objects
# ──────────────────────────────────────────────────────────────────────────

@chat.function(
    "list_address_objects",
    "List address objects (IP/CIDR/range/FQDN) defined on the connected PAN-OS firewall.",
    action_type="read",
    data_model=AddressObjectList,
)
async def list_address_objects(ctx, params: ListAddressObjectsParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _ADDRESS_ALL.format(vsys=params.vsys))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//address/entry"):
        name = entry.get("name", "")
        kind, value = "", ""
        for t in ("ip-netmask", "ip-range", "fqdn"):
            node = entry.find(t)
            if node is not None:
                kind, value = t, (node.text or "")
                break
        items.append(AddressObject(id=name, title=name, value=value, kind=kind))
    return ActionResult.success(AddressObjectList(title=f"{len(items)} address object(s)", items=items), summary="Address objects listed.")


@chat.function(
    "create_address_object",
    "Create a new address object (ip-netmask, ip-range, or fqdn). This does not take effect until you commit.",
    action_type="write",
    chain_callable=True,
    data_model=AddressObject,
    event="palo-alto-networks-connector.create_address_object",
    effects=["create:resource"],
)
async def create_address_object(ctx, params: CreateAddressObjectParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    xml = f"<{params.kind}>{params.value}</{params.kind}>"
    try:
        await pc.config_set(ctx, conn, _ADDRESS.format(vsys=params.vsys, name=params.name), xml)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(AddressObject(id=params.name, title=params.name, value=params.value, kind=params.kind), summary="Address object created.")


@chat.function(
    "update_address_object",
    "Update an existing address object's value. Infers ip-netmask vs fqdn from the new value's shape -- to change ip-range/fqdn use delete+create instead. This does not take effect until you commit.",
    action_type="write",
    chain_callable=True,
    data_model=AddressObject,
    event="palo-alto-networks-connector.update_address_object",
    effects=["update:resource"],
)
async def update_address_object(ctx, params: UpdateAddressObjectParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    kind = "ip-netmask" if _IP_RE.match(params.value) else "fqdn"
    xml = f"<{kind}>{params.value}</{kind}>"
    try:
        await pc.config_edit(ctx, conn, _ADDRESS.format(vsys=params.vsys, name=params.name), xml)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(AddressObject(id=params.name, title=params.name, value=params.value, kind=kind), summary="Address object updated.")


@chat.function(
    "delete_address_object",
    "Permanently delete an address object by name. This does not take effect until you commit.",
    action_type="write",
    chain_callable=True,
    data_model=DeleteResult,
    event="palo-alto-networks-connector.delete_address_object",
    effects=["delete:resource"],
)
async def delete_address_object(ctx, params: DeleteAddressObjectParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        await pc.config_delete(ctx, conn, _ADDRESS.format(vsys=params.vsys, name=params.name))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(DeleteResult(id=params.name, title=params.name, deleted=True), summary="Address object deleted.")


@chat.function(
    "list_address_groups",
    "List address groups (named collections of address objects) defined on the connected PAN-OS firewall.",
    action_type="read",
    data_model=AddressGroupList,
)
async def list_address_groups(ctx, params: ListAddressGroupsParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _ADDRESS_GROUP_ALL.format(vsys=params.vsys))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//address-group/entry"):
        name = entry.get("name", "")
        static = entry.find("static")
        count = len(static.findall("member")) if static is not None else 0
        items.append(AddressGroup(id=name, title=name, member_count=count))
    return ActionResult.success(AddressGroupList(title=f"{len(items)} address group(s)", items=items), summary="Address groups listed.")


@chat.function(
    "list_service_objects",
    "List service (port) objects defined on the connected PAN-OS firewall.",
    action_type="read",
    data_model=ServiceObjectList,
)
async def list_service_objects(ctx, params: ListServiceObjectsParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _SERVICE_ALL.format(vsys=params.vsys))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//service/entry"):
        name = entry.get("name", "")
        proto = "tcp" if entry.find("protocol/tcp") is not None else ("udp" if entry.find("protocol/udp") is not None else "")
        port_el = entry.find(f"protocol/{proto}/port") if proto else None
        items.append(ServiceObject(id=name, title=name, protocol=proto, port=port_el.text if port_el is not None else ""))
    return ActionResult.success(ServiceObjectList(title=f"{len(items)} service object(s)", items=items), summary="Service objects listed.")


@chat.function(
    "create_service_object",
    "Create a new service (port) object on the connected PAN-OS firewall.",
    action_type="write",
    data_model=ServiceObject,
)
async def create_service_object(ctx, params: CreateServiceObjectParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    xml = f"<entry name='{params.name}'><protocol><{params.protocol}><port>{params.port}</port></{params.protocol}></protocol></entry>"
    try:
        await pc.config_set(ctx, conn, _SERVICE.format(vsys=params.vsys, name=params.name), xml)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(ServiceObject(id=params.name, title=params.name, protocol=params.protocol, port=params.port), summary="Service object created.")


@chat.function(
    "update_service_object",
    "Update a service object's port range. To change protocol, delete and recreate instead.",
    action_type="write",
    data_model=ServiceObject,
)
async def update_service_object(ctx, params: UpdateServiceObjectParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    xml = f"<port>{params.port}</port>"
    xpath = f"{_SERVICE.format(vsys=params.vsys, name=params.name)}/protocol/tcp"
    try:
        await pc.config_edit(ctx, conn, xpath, xml)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(ServiceObject(id=params.name, title=params.name, protocol="tcp", port=params.port), summary="Service object updated.")


@chat.function(
    "delete_service_object",
    "Permanently delete a service object by name.",
    action_type="write",
    data_model=DeleteResult,
)
async def delete_service_object(ctx, params: DeleteServiceObjectParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        await pc.config_delete(ctx, conn, _SERVICE.format(vsys=params.vsys, name=params.name))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    return ActionResult.success(DeleteResult(id=params.name, title=params.name, deleted=True), summary="Service object deleted.")

# ──────────────────────────────────────────────────────────────────────────
# Zones, Interfaces, System, Commit
# ──────────────────────────────────────────────────────────────────────────

@chat.function(
    "list_zones",
    "List security zones configured on the connected PAN-OS firewall.",
    action_type="read",
    data_model=ZoneList,
)
async def list_zones(ctx, params: ListZonesParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _ZONE_ALL.format(vsys=params.vsys))
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//zone/entry"):
        name = entry.get("name", "")
        network = entry.find("network")
        mode = ""
        if network is not None:
            for m in ("layer3", "layer2", "virtual-wire", "tap"):
                if network.find(m) is not None:
                    mode = m
                    break
        items.append(Zone(id=name, title=name, mode=mode))
    return ActionResult.success(ZoneList(title=f"{len(items)} zone(s)", items=items), summary="Zones listed.")


@chat.function(
    "list_interfaces",
    "List network interfaces configured on the connected PAN-OS firewall.",
    action_type="read",
    data_model=InterfaceList,
)
async def list_interfaces(ctx, params: ListInterfacesParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.config_get(ctx, conn, _INTERFACE_ALL)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    items = []
    for entry in root.findall(".//entry"):
        name = entry.get("name", "")
        if not name:
            continue
        ip_node = entry.find(".//ip/entry")
        ip = ip_node.get("name", "") if ip_node is not None else ""
        items.append(Interface(id=name, title=name, ip=ip))
    return ActionResult.success(InterfaceList(title=f"{len(items)} interface(s)", items=items), summary="Interfaces listed.")


@chat.function(
    "get_system_status",
    "Read the connected PAN-OS firewall's own system status: hostname, model, serial, software version, uptime.",
    action_type="read",
    data_model=SystemInfo,
)
async def get_system_status(ctx, params: GetSystemInfoParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.op_command(ctx, conn, "<show><system><info></info></system></show>")
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    info = root.find(".//system")
    if info is None:
        return ActionResult.error("Unexpected response reading system status.")
    return ActionResult.success(SystemInfo(
        id="system_status", title=_text(info, "hostname"),
        hostname=_text(info, "hostname"), model=_text(info, "model"),
        serial=_text(info, "serial"), sw_version=_text(info, "sw-version"),
        uptime=_text(info, "uptime"),
    ), summary="System status retrieved.")


@chat.function(
    "commit_config",
    "Commit the connected PAN-OS firewall's pending configuration changes so they take effect. Firewall config edits (security rules, address/service objects) sit uncommitted until this runs -- same explicit-commit convention as ZIA's activate_zia_changes.",
    action_type="write",
    chain_callable=True,
    data_model=CommitResult,
    event="palo-alto-networks-connector.commit_config",
    effects=["update:resource"],
)
async def commit_config(ctx, params: CommitParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    try:
        root = await pc.commit(ctx, conn)
    except pc.ClientFail as e:
        return ActionResult.error(e.message())
    job_node = root.find(".//job")
    job_id = (job_node.text or "") if job_node is not None else ""
    return ActionResult.success(CommitResult(
        id=job_id or "commit", title=f"Commit job {job_id}" if job_id else "Commit submitted",
        job_id=job_id, status="pending",
    ), summary="Commit config done.")
