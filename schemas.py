"""Pydantic params models + SDL entity contracts for Palo Alto Networks
Connector. Module-scope params models per V17 federal invariant, same shape
as Fortinet Connector's schemas.py.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from imperal_sdk import sdl


class NoParams(BaseModel):
    """Explicit empty params model -- V17 disallows untyped handlers."""
    pass


# ──────────────────────────────────────────────────────────────────────────
# Connection
# ──────────────────────────────────────────────────────────────────────────


class ConnectPanosParams(BaseModel):
    host: str = Field(..., description="PAN-OS firewall base URL, e.g. 'https://fw01.company.com'.")
    username: str = Field(..., description="PAN-OS administrator username (used once to obtain an API key via keygen).")
    password: str = Field(..., description="PAN-OS administrator password (used once, not stored).")
    label: str = Field("", description="Optional friendly name for this PAN-OS connection.")


class ConnectPanoramaParams(BaseModel):
    host: str = Field(..., description="Panorama base URL, e.g. 'https://panorama.company.com'.")
    username: str = Field(..., description="Panorama administrator username (used once to obtain an API key via keygen).")
    password: str = Field(..., description="Panorama administrator password (used once, not stored).")
    label: str = Field("", description="Optional friendly name for this Panorama connection.")


class ProviderConnection(sdl.Entity):
    id: str = ""
    title: str = ""
    kind: str = ""  # "panos" | "panorama"
    connected: bool = False
    detail: str = ""


class ProviderConnectionList(sdl.Entity):
    id: str = "connection_list"
    title: str = ""
    items: list[ProviderConnection] = Field(default_factory=list)


class DisconnectParams(BaseModel):
    connection_id: str = Field(..., description="Connection id to disconnect, from list_connections.")


class DeleteResult(sdl.Entity):
    id: str = ""
    title: str = ""
    deleted: bool = False


class _PanosScoped(BaseModel):
    connection_id: str = Field("", description="Which connected PAN-OS firewall to use. Omit if only one is connected.")


class _PanoramaScoped(BaseModel):
    connection_id: str = Field("", description="Which connected Panorama to use. Omit if only one is connected.")


# ──────────────────────────────────────────────────────────────────────────
# PAN-OS -- Security Rules
# ──────────────────────────────────────────────────────────────────────────


class ListSecurityRulesParams(_PanosScoped):
    vsys: str = Field("vsys1", description="Virtual system to read rules from. Defaults to 'vsys1'.")


class SecurityRule(sdl.Entity):
    id: str = ""
    title: str = ""
    action: str = ""  # "allow" | "deny" | "drop"
    from_zone: str = ""
    to_zone: str = ""
    disabled: bool = False


class SecurityRuleList(sdl.Entity):
    id: str = "security_rule_list"
    title: str = ""
    items: list[SecurityRule] = Field(default_factory=list)


class GetSecurityRuleParams(_PanosScoped):
    name: str = Field(..., description="Security rule name, from list_security_rules.")
    vsys: str = Field("vsys1", description="Virtual system the rule lives in.")


class CreateSecurityRuleParams(_PanosScoped):
    name: str = Field(..., description="New security rule name.")
    action: str = Field("allow", description="allow, deny, or drop.")
    from_zone: str = Field("any", description="Source zone name.")
    to_zone: str = Field("any", description="Destination zone name.")
    source: str = Field("any", description="Source address/object name.")
    destination: str = Field("any", description="Destination address/object name.")
    application: str = Field("any", description="Application name.")
    service: str = Field("application-default", description="Service name.")
    vsys: str = Field("vsys1", description="Virtual system to create the rule in.")


class UpdateSecurityRuleParams(_PanosScoped):
    name: str = Field(..., description="Security rule name to update.")
    action: str = Field("", description="New action, if changing.")
    disabled: bool = Field(False, description="Whether to disable the rule.")
    vsys: str = Field("vsys1", description="Virtual system the rule lives in.")


class DeleteSecurityRuleParams(_PanosScoped):
    name: str = Field(..., description="Security rule name to permanently delete.")
    vsys: str = Field("vsys1", description="Virtual system the rule lives in.")


class ReorderSecurityRuleParams(_PanosScoped):
    name: str = Field(..., description="Security rule name to move.")
    before: str = Field("", description="Move this rule to just before this other rule name.")
    after: str = Field("", description="Move this rule to just after this other rule name.")
    vsys: str = Field("vsys1", description="Virtual system the rule lives in.")


# ──────────────────────────────────────────────────────────────────────────
# PAN-OS -- Address / Service Objects, Zones, Interfaces, System
# ──────────────────────────────────────────────────────────────────────────


class ListAddressObjectsParams(_PanosScoped):
    vsys: str = Field("vsys1", description="Virtual system to read objects from.")


class AddressObject(sdl.Entity):
    id: str = ""
    title: str = ""
    value: str = ""
    kind: str = ""  # "ip-netmask" | "ip-range" | "fqdn"


class AddressObjectList(sdl.Entity):
    id: str = "address_object_list"
    title: str = ""
    items: list[AddressObject] = Field(default_factory=list)


class CreateAddressObjectParams(_PanosScoped):
    name: str = Field(..., description="New address object name.")
    value: str = Field(..., description="Value, e.g. '10.0.0.0/24' or 'host.example.com'.")
    kind: str = Field("ip-netmask", description="ip-netmask, ip-range, or fqdn.")
    vsys: str = Field("vsys1", description="Virtual system to create the object in.")


class UpdateAddressObjectParams(_PanosScoped):
    name: str = Field(..., description="Address object name to update.")
    value: str = Field(..., description="New value.")
    vsys: str = Field("vsys1", description="Virtual system the object lives in.")


class DeleteAddressObjectParams(_PanosScoped):
    name: str = Field(..., description="Address object name to permanently delete.")
    vsys: str = Field("vsys1", description="Virtual system the object lives in.")


class ListAddressGroupsParams(_PanosScoped):
    vsys: str = Field("vsys1", description="Virtual system to read groups from.")


class AddressGroup(sdl.Entity):
    id: str = ""
    title: str = ""
    member_count: int = 0


class AddressGroupList(sdl.Entity):
    id: str = "address_group_list"
    title: str = ""
    items: list[AddressGroup] = Field(default_factory=list)


class ListServiceObjectsParams(_PanosScoped):
    vsys: str = Field("vsys1", description="Virtual system to read services from.")


class ServiceObject(sdl.Entity):
    id: str = ""
    title: str = ""
    protocol: str = ""
    port: str = ""


class ServiceObjectList(sdl.Entity):
    id: str = "service_object_list"
    title: str = ""
    items: list[ServiceObject] = Field(default_factory=list)


class CreateServiceObjectParams(_PanosScoped):
    name: str = Field(..., description="New service object name.")
    protocol: str = Field("tcp", description="tcp or udp.")
    port: str = Field(..., description="Destination port(s), e.g. '443' or '8000-8010'.")
    vsys: str = Field("vsys1", description="Virtual system to create the service in.")


class UpdateServiceObjectParams(_PanosScoped):
    name: str = Field(..., description="Service object name to update.")
    port: str = Field(..., description="New destination port(s).")
    vsys: str = Field("vsys1", description="Virtual system the service lives in.")


class DeleteServiceObjectParams(_PanosScoped):
    name: str = Field(..., description="Service object name to permanently delete.")
    vsys: str = Field("vsys1", description="Virtual system the service lives in.")


class ListZonesParams(_PanosScoped):
    vsys: str = Field("vsys1", description="Virtual system to read zones from.")


class Zone(sdl.Entity):
    id: str = ""
    title: str = ""
    mode: str = ""  # "layer3" | "layer2" | "virtual-wire" | "tap"


class ZoneList(sdl.Entity):
    id: str = "zone_list"
    title: str = ""
    items: list[Zone] = Field(default_factory=list)


class ListInterfacesParams(_PanosScoped):
    pass


class Interface(sdl.Entity):
    id: str = ""
    title: str = ""
    zone: str = ""
    ip: str = ""


class InterfaceList(sdl.Entity):
    id: str = "interface_list"
    title: str = ""
    items: list[Interface] = Field(default_factory=list)


class GetSystemInfoParams(_PanosScoped):
    pass


class SystemInfo(sdl.Entity):
    id: str = "system_info"
    title: str = ""
    sw_version: str = ""
    serial: str = ""
    model: str = ""
    uptime: str = ""


class CommitParams(_PanosScoped):
    description: str = Field("", description="Optional commit description/comment.")


class CommitResult(sdl.Entity):
    id: str = ""
    title: str = ""
    job_id: str = ""
    status: str = ""


# ──────────────────────────────────────────────────────────────────────────
# Panorama -- Device Groups, Managed Devices, Templates, Push
# ──────────────────────────────────────────────────────────────────────────


class ListDeviceGroupsParams(_PanoramaScoped):
    pass


class DeviceGroup(sdl.Entity):
    id: str = ""
    title: str = ""
    device_count: int = 0


class DeviceGroupList(sdl.Entity):
    id: str = "device_group_list"
    title: str = ""
    items: list[DeviceGroup] = Field(default_factory=list)


class ListManagedDevicesParams(_PanoramaScoped):
    pass


class ManagedDevice(sdl.Entity):
    id: str = ""
    title: str = ""
    serial: str = ""
    connected: bool = False
    sw_version: str = ""


class ManagedDeviceList(sdl.Entity):
    id: str = "managed_device_list"
    title: str = ""
    items: list[ManagedDevice] = Field(default_factory=list)


class GetManagedDeviceParams(_PanoramaScoped):
    serial: str = Field(..., description="Managed device serial number, from list_managed_devices.")


class ListTemplatesParams(_PanoramaScoped):
    pass


class Template(sdl.Entity):
    id: str = ""
    title: str = ""


class TemplateList(sdl.Entity):
    id: str = "template_list"
    title: str = ""
    items: list[Template] = Field(default_factory=list)


class ListPanoramaSecurityRulesParams(_PanoramaScoped):
    device_group: str = Field(..., description="Device group name, from list_device_groups.")


class PanoramaSecurityRule(sdl.Entity):
    id: str = ""
    title: str = ""
    action: str = ""
    disabled: bool = False


class PanoramaSecurityRuleList(sdl.Entity):
    id: str = "panorama_security_rule_list"
    title: str = ""
    items: list[PanoramaSecurityRule] = Field(default_factory=list)


class PushToDevicesParams(_PanoramaScoped):
    device_group: str = Field(..., description="Device group name to push configuration to.")
    description: str = Field("", description="Optional push description/comment.")


class PushResult(sdl.Entity):
    id: str = ""
    title: str = ""
    job_id: str = ""
    status: str = ""


# ──────────────────────────────────────────────────────────────────────────
# Bulk + Audit
# ──────────────────────────────────────────────────────────────────────────


class BulkSecurityRuleActionParams(_PanosScoped):
    names: list[str] = Field(..., description="Security rule names to act on.")
    disabled: bool = Field(..., description="Whether to disable (true) or enable (false) each rule.")
    vsys: str = Field("vsys1", description="Virtual system the rules live in.")


class BulkActionOutcome(sdl.Entity):
    id: str = ""
    ok: bool = False
    error: str = ""


class BulkActionResult(sdl.Entity):
    id: str = "bulk_action_result"
    title: str = ""
    items: list[BulkActionOutcome] = Field(default_factory=list)


class AuditPanwEstateParams(BaseModel):
    pass


class AuditFinding(sdl.Entity):
    id: str = ""
    severity: str = ""  # "info" | "warning" | "critical"
    message: str = ""


class AuditReport(sdl.Entity):
    id: str = "audit_report"
    title: str = ""
    findings: list[AuditFinding] = Field(default_factory=list)
