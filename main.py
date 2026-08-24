"""Entrypoint for the web-kernel and CLI tools (imperal validate/build).

Sets up sys.path, purges stale module cache, then imports ext/chat and all
handler modules so their decorators register on the same Extension instance
-- same pattern as Fortinet Connector's / Cisco Secure Access Connector's
main.py.
"""

import os
import sys

_EXT_DIR = os.path.dirname(os.path.abspath(__file__))
if _EXT_DIR not in sys.path:
    sys.path.insert(0, _EXT_DIR)

_LOCAL = (
    "app", "schemas", "pan_client",
    "handlers_connection", "handlers_panos", "handlers_panorama",
    "handlers_bulk_audit",
    "panels", "panels_center", "panels_settings",
)
for _mod in _LOCAL:
    sys.modules.pop(_mod, None)

from app import ext, chat  # noqa: E402,F401
import handlers_connection  # noqa: E402,F401
import handlers_panos  # noqa: E402,F401
import handlers_panorama  # noqa: E402,F401
import handlers_bulk_audit  # noqa: E402,F401
import panels  # noqa: E402,F401
import panels_center  # noqa: E402,F401
import panels_settings  # noqa: E402,F401
