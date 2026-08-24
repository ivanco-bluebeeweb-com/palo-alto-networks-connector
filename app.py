"""Palo Alto Networks Connector -- app + extension setup.

Two independent BYOK auth surfaces under one product umbrella, same
convention as Fortinet Connector's FortiGate/FortiManager/FortiSASE split:
  - PAN-OS firewall: direct device management (security rules, objects,
    interfaces, system info).
  - Panorama: centralized fleet management (device groups, managed
    devices, templates, commit/push).

Both use the same XML API keygen exchange (username+password -> API key,
stored, not the password). See PREPARATION.md for the full why.
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "palo-alto-networks-connector",
    version="0.1.0",
    display_name="Palo Alto Networks",
    icon="icon.svg",
    description=(
        "Connect your own PAN-OS firewall(s) and/or Panorama management "
        "server to manage security rules, address/service objects, zones, "
        "interfaces, device groups, managed devices, templates, and commit/ "
        "push operations from Imperal -- plus bulk operations and a "
        "Palo Alto estate health audit. Uses your own PAN-OS/Panorama "
        "credentials, exchanged once for an API key via the standard "
        "keygen endpoint -- nothing is hosted or proxied by Imperal beyond "
        "the request itself."
    ),
)

ext.secret("panw_connections", description="Stored PAN-OS/Panorama connection credentials (JSON array)")

chat = ChatExtension(
    ext,
    tool_name="panw",
    description="Manage PAN-OS firewalls and Panorama: security rules, objects, device groups, commits.",
)
