"""Chat functions for Palo Alto Networks Connector -- bulk operations and a
combined estate health audit (Tier 3 value-add), same shape as Fortinet
Connector's handlers_bulk_audit.py.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import pan_client as pc
from app import chat
from handlers_connection import _authed_panos, _load_connections
from schemas import (
    BulkSecurityRuleActionParams, BulkActionOutcome, BulkActionResult,
    AuditPanwEstateParams, AuditFinding, AuditReport,
)


@chat.function(
    "bulk_security_rule_action",
    "Enable or disable several PAN-OS security rules in one call, by explicit rule names. Continues past per-item failures and reports each outcome, same convention as every other bulk_* tool in the portfolio.",
    action_type="write",
)
async def bulk_security_rule_action(ctx, params: BulkSecurityRuleActionParams) -> ActionResult:
    conn = await _authed_panos(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    xpath_tpl = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{params.vsys}']/rulebase/security/rules/entry[@name='{{name}}']/disabled"
    items: list[BulkActionOutcome] = []
    for name in params.names:
        xpath = xpath_tpl.format(name=name)
        value = "yes" if params.disabled else "no"
        try:
            await pc.config_edit(ctx, conn, xpath, f"<disabled>{value}</disabled>")
            items.append(BulkActionOutcome(id=name, ok=True))
        except pc.ClientFail as e:
            items.append(BulkActionOutcome(id=name, ok=False, error=e.message()))
    return ActionResult.success(BulkActionResult(title="Bulk security rule status change", items=items), summary="Bulk security rule action done.")


@chat.function(
    "audit_panw_estate",
    "Run a read-only health audit across all connected PAN-OS/Panorama connections: disabled security rules with broad 'any' source/destination, offline Panorama-managed devices, and rules with no logging configured. Same convention as Fortinet Connector's audit_fortinet_estate.",
    action_type="read",
    data_model=AuditReport,
)
async def audit_panw_estate(ctx, params: AuditPanwEstateParams) -> ActionResult:
    findings: list[AuditFinding] = []
    connections = await _load_connections(ctx)
    panos_conns = [c for c in connections if c.get("kind") == "panos"]
    panorama_conns = [c for c in connections if c.get("kind") == "panorama"]

    if not connections:
        return ActionResult.error("No PAN-OS or Panorama connections are set up yet.")

    for conn in panos_conns:
        try:
            root = await pc.config_get(ctx, conn, "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules")
        except pc.ClientFail as e:
            findings.append(AuditFinding(id=f"panos-{conn.get('id')}-error", severity="warning", message=f"Could not read rules on '{conn.get('title')}': {e.message()}"))
            continue
        for entry in root.findall(".//rules/entry"):
            name = entry.get("name", "")
            src = [m.text for m in entry.findall("./source/member")]
            dst = [m.text for m in entry.findall("./destination/member")]
            action = entry.findtext("action", "")
            log_end = entry.findtext("log-end", "no")
            if action == "allow" and "any" in src and "any" in dst:
                findings.append(AuditFinding(id=f"{conn.get('id')}-{name}-anyany", severity="critical", message=f"'{name}' on '{conn.get('title')}' allows any-source to any-destination."))
            if action == "allow" and log_end != "yes":
                findings.append(AuditFinding(id=f"{conn.get('id')}-{name}-nolog", severity="info", message=f"'{name}' on '{conn.get('title')}' has logging disabled at session end."))

    for conn in panorama_conns:
        try:
            root = await pc.op_command(ctx, conn, "<show><devices><all></all></devices></show>")
        except pc.ClientFail as e:
            findings.append(AuditFinding(id=f"panorama-{conn.get('id')}-error", severity="warning", message=f"Could not read managed devices on '{conn.get('title')}': {e.message()}"))
            continue
        for entry in root.findall(".//devices/entry"):
            hostname = entry.findtext("hostname", "") or entry.get("name", "")
            connected = entry.findtext("connected", "no") == "yes"
            if not connected:
                findings.append(AuditFinding(id=f"{conn.get('id')}-{hostname}-offline", severity="warning", message=f"Managed device '{hostname}' on '{conn.get('title')}' is offline."))

    return ActionResult.success(AuditReport(title=f"{len(findings)} finding(s) across {len(connections)} connection(s)", findings=findings), summary="Panw estate audit ready.")
