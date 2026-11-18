"""Diagnostics download (Settings > Devices & services > pfSense > Download).

Meant to be attached to bug reports, so it carries health and shape, not the
network: credentials, the URL, identifiers, IPs and MACs are redacted, and
poll data is summarized as counts rather than dumped.
"""

from __future__ import annotations

import re
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import (
    CONF_API_KEY,
    CONF_FIRMWARE_BACKUP_PASSWORD,
    COORDINATOR,
    DOMAIN,
    HEALTH,
)

TO_REDACT = {
    CONF_API_KEY,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_URL,
    CONF_FIRMWARE_BACKUP_PASSWORD,
    "name",
}

_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_URL = re.compile(r"https?://[^\s'\"]+")


def _scrub(value: Any) -> Any:
    """Strip addresses from free-text error messages, recursively."""
    if isinstance(value, str):
        value = _URL.sub("<url>", value)
        value = _MAC.sub("<mac>", value)
        return _IPV4.sub("<ip>", value)
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _count(value: Any) -> int | None:
    return len(value) if isinstance(value, (list, dict)) else None


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return redacted diagnostics for a config entry."""
    data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
    coordinator = data.get(COORDINATOR)
    health = data.get(HEALTH)
    state = (coordinator.data if coordinator else None) or {}
    firmware = state.get("host_firmware_version") or {}
    telemetry = state.get("telemetry") or {}

    return {
        "entry": {
            "version": entry.version,
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": async_redact_data(dict(entry.options), TO_REDACT),
        },
        "health": _scrub(health.as_dict()) if health else None,
        "firewall": {
            "platform": firmware.get("platform"),
            "version": (firmware.get("firmware") or {}).get("version"),
            "base": firmware.get("base"),
            "patch": firmware.get("patch"),
        },
        "counts": {
            "interfaces": _count(telemetry.get("interfaces")),
            "gateways": _count(telemetry.get("gateways")),
            "openvpn_servers": _count((telemetry.get("openvpn") or {}).get("servers")),
            "services": _count(state.get("services")),
            "dhcp_leases": _count(state.get("dhcp_leases")),
            "arp_table": _count(state.get("arp_table")),
            "firewall_rules": _count(state.get("firewall_rules")),
            "nat_port_forward_rules": _count(state.get("nat_port_forward_rules")),
            "nat_outbound_rules": _count(state.get("nat_outbound_rules")),
            "carp_interfaces": _count(state.get("carp_interfaces")),
        },
        "services": [
            {"name": s.get("name"), "status": s.get("status")}
            for s in state.get("services") or []
            if isinstance(s, dict)
        ],
        "poll_state_keys": sorted(state),
    }
