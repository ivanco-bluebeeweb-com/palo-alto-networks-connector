"""Palo Alto Networks Connector -- center panels: base overview + PAN-OS/
Panorama overlay panels, per UI_COMPONENT_PLAN.md §1.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
import handlers_connection as h
import handlers_panos as pn
import handlers_panorama as pm
from schemas import (
    ListSecurityRulesParams, ListAddressObjectsParams,
    ListDeviceGroupsParams, ListManagedDevicesParams,
)


def _status_badge(status: str) -> ui.UINode:
    s = (status or "").lower()
    color = "success" if s in ("enable", "online", "up", "connected", "yes") else ("error" if s in ("disable", "offline", "down", "no") else "default")
    return ui.Badge(label=status or "unknown", color=color)


@ext.panel("panw_center", slot="center")
async def panw_center(ctx, **kwargs) -> ui.UINode:
    """Base (non-overlay) center panel -- rendered before any sidebar item is
    clicked, per UI_INTERFACE_STANDARD.md's mandatory base-center-panel rule."""
    result = await h.list_connections(ctx, h.NoParams())
    items = result.data.items if result.success and result.data else []
    if not items:
        return ui.Empty(message="Connect a PAN-OS firewall or Panorama first.", icon="Shield")
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("Palo Alto Networks", variant="heading"),
        ui.Text(
            "Ask Webbee to list security rules, address/service objects, zones, interfaces, device groups, managed devices, or run a health audit.",
            variant="caption",
        ),
    ])


@ext.panel("panw_panos_overview", slot="center", center_overlay=True)
async def panw_panos_overview(ctx, **kwargs) -> ui.UINode:
    rules_res = await pn.list_security_rules(ctx, ListSecurityRulesParams())
    addr_res = await pn.list_address_objects(ctx, ListAddressObjectsParams())
    rules = rules_res.data.items if rules_res.success and rules_res.data else []
    addrs = addr_res.data.items if addr_res.success and addr_res.data else []

    rule_rows: list[ui.UINode] = []
    for r in rules[:20]:
        rule_rows.append(ui.Stack(direction="h", gap=2, align="center", children=[
            ui.Text(r.title, variant="body"),
            _status_badge(r.action),
            _status_badge("disable" if r.disabled else "enable"),
        ]))

    return ui.Stack(direction="v", gap=4, align="stretch", children=[
        ui.Text("PAN-OS Security Rules", variant="heading"),
        ui.Stats(children=[
            ui.Stat(label="Security rules", value=str(len(rules))),
            ui.Stat(label="Address objects", value=str(len(addrs))),
        ]),
        ui.Divider(),
        ui.Stack(direction="v", gap=2, align="stretch", children=rule_rows) if rule_rows else ui.Empty(message="No security rules found.", icon="Shield"),
    ])


@ext.panel("panw_panorama_overview", slot="center", center_overlay=True)
async def panw_panorama_overview(ctx, **kwargs) -> ui.UINode:
    dg_res = await pm.list_device_groups(ctx, ListDeviceGroupsParams())
    dev_res = await pm.list_managed_devices(ctx, ListManagedDevicesParams())
    groups = dg_res.data.items if dg_res.success and dg_res.data else []
    devices = dev_res.data.items if dev_res.success and dev_res.data else []

    device_rows: list[ui.UINode] = []
    for d in devices[:20]:
        device_rows.append(ui.Stack(direction="h", gap=2, align="center", children=[
            ui.Text(d.title, variant="body"),
            ui.Text(d.sw_version, variant="caption"),
            _status_badge("connected" if d.connected else "offline"),
        ]))

    return ui.Stack(direction="v", gap=4, align="stretch", children=[
        ui.Text("Panorama Overview", variant="heading"),
        ui.Stats(children=[
            ui.Stat(label="Device groups", value=str(len(groups))),
            ui.Stat(label="Managed devices", value=str(len(devices))),
        ]),
        ui.Divider(),
        ui.Stack(direction="v", gap=2, align="stretch", children=device_rows) if device_rows else ui.Empty(message="No managed devices found.", icon="Server"),
    ])
