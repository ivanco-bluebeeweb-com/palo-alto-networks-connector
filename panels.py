"""Panel UI -- connections list/connect forms (PAN-OS + Panorama, two
independent sections) + navigation.

SIDEBAR CONTENT -- NO CARDS ANYWHERE, per ~/UI_INTERFACE_STANDARD.md's
"left sidebar, no decorated cards" rule (same convention as Fortinet
Connector's / Cisco Secure Access Connector's panels.py). Every section is
a plain ui.Stack, sections separated by ui.Divider() -- no Card border/
background/shadow anywhere in this slot. Disconnect lives only in the
"App settings" screen (panels_settings.py). The one secondary "App
settings" button is always the LAST element at the bottom of the sidebar.

PER ~/UI_INTERFACE_STANDARD.md (2026-08-21 addendum): every Input carries
its own visible label (rendered here as a sibling ui.Text caption, since
ui.Input/ui.Password/ui.Select take no label= kwarg), the placeholder text
is always contextually specific to what's being entered, the connect
form's container is stretched full-width, and its content fills that
width. The "How do I set this up?" walkthrough lives ONLY in the help
panel below -- never duplicated as static sidebar text.

Implements UI_COMPONENT_PLAN.md §1 exactly (built alongside that plan,
not after -- APP_PREPARATION_STANDARD.md §9).
"""
from __future__ import annotations

from imperal_sdk import ui

import handlers_connection as h
from app import ext


def _connect_help_panel_body() -> ui.UINode:
    return ui.Stack(direction="v", gap=3, children=[
        ui.Text("PAN-OS firewall:", variant="body"),
        ui.Text("1. Sign in to your firewall's web admin."),
        ui.Text("2. Use an administrator account with XML API access."),
        ui.Text("3. Enter host + username + password below -- the connector exchanges them once for an API key via the standard keygen endpoint and stores only the key."),
        ui.Divider(),
        ui.Text("Panorama:", variant="body"),
        ui.Text("1. Sign in to your Panorama management server."),
        ui.Text("2. Use an administrator account with XML API access."),
        ui.Text("3. Enter host + username + password below -- same keygen exchange."),
        ui.Divider(),
        ui.Alert(
            title="Two independent connections",
            message=(
                "PAN-OS and Panorama are separate management surfaces with "
                "separate credentials. Connect either one, or both -- "
                "neither is required for the other to work."
            ),
            type="info",
        ),
    ])


@ext.panel("panw_connect_help", slot="center", center_overlay=True)
async def panw_connect_help_panel(ctx) -> ui.UINode:
    return ui.Stack(direction="v", gap=4, align="stretch", children=[
        ui.Text("Connecting Palo Alto Networks", variant="heading"),
        _connect_help_panel_body(),
    ])


def _panos_form() -> ui.UINode:
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("PAN-OS firewall", variant="body"),
        ui.Stack(direction="v", gap=1, children=[
            ui.Text("Host", variant="caption"),
            ui.Input(param_name="host", placeholder="https://fw01.company.com"),
        ]),
        ui.Stack(direction="v", gap=1, children=[
            ui.Text("Username", variant="caption"),
            ui.Input(param_name="username", placeholder="admin"),
        ]),
        ui.Stack(direction="v", gap=1, children=[
            ui.Text("Password", variant="caption"),
            ui.Password(param_name="password", placeholder="Administrator password"),
        ]),
        ui.Stack(direction="v", gap=1, children=[
            ui.Text("Label (optional)", variant="caption"),
            ui.Input(param_name="label", placeholder="e.g. HQ Firewall"),
        ]),
        ui.Button("Connect PAN-OS", on_click=ui.Call("connect_panos", {
            "host": "{{host}}", "username": "{{username}}", "password": "{{password}}", "label": "{{label}}",
        })),
    ])


def _panorama_form() -> ui.UINode:
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("Panorama", variant="body"),
        ui.Stack(direction="v", gap=1, children=[
            ui.Text("Host", variant="caption"),
            ui.Input(param_name="host2", placeholder="https://panorama.company.com"),
        ]),
        ui.Stack(direction="v", gap=1, children=[
            ui.Text("Username", variant="caption"),
            ui.Input(param_name="username2", placeholder="admin"),
        ]),
        ui.Stack(direction="v", gap=1, children=[
            ui.Text("Password", variant="caption"),
            ui.Password(param_name="password2", placeholder="Administrator password"),
        ]),
        ui.Stack(direction="v", gap=1, children=[
            ui.Text("Label (optional)", variant="caption"),
            ui.Input(param_name="label2", placeholder="e.g. Main Panorama"),
        ]),
        ui.Button("Connect Panorama", on_click=ui.Call("connect_panorama", {
            "host": "{{host2}}", "username": "{{username2}}", "password": "{{password2}}", "label": "{{label2}}",
        })),
    ])


@ext.panel("panw_sidebar", slot="left")
async def panw_sidebar(ctx) -> ui.UINode:
    result = await h.list_connections(ctx, h.NoParams())
    items = result.data.items if result.success and result.data else []

    children: list[ui.UINode] = [ui.Text("Palo Alto Networks", variant="heading")]

    if items:
        for c in items:
            children.append(ui.Text(f"{c.title} ({c.kind})", variant="body"))
        children.append(ui.Divider())
        children.append(ui.ListItem(label="Security Rules", on_click=ui.Call("__panel__panw_panos_overview")))
        children.append(ui.ListItem(label="Panorama Overview", on_click=ui.Call("__panel__panw_panorama_overview")))
        children.append(ui.ListItem(label="Health Audit", on_click=ui.Call("audit_panw_estate", {})))
        children.append(ui.Divider())

    children.append(ui.Stack(direction="v", gap=4, align="stretch", children=[
        _panos_form(),
        ui.Divider(),
        _panorama_form(),
        ui.Button("How do I set this up?", variant="ghost", size="sm", on_click=ui.Call("__panel__panw_connect_help")),
    ]))

    children.append(ui.Divider())
    children.append(ui.Button(
        "App settings", variant="ghost", size="sm",
        on_click=ui.Call("__panel__panw_settings"),
    ))

    return ui.Stack(direction="v", gap=3, align="stretch", children=children)
