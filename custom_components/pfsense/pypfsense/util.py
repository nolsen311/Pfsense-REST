"""Backend-agnostic helpers."""

from __future__ import annotations

import ipaddress
import re


def dict_get(data: dict, path: str, default=None):
    """Traverse a nested dict/list by a dotted path. Numeric segments index lists."""
    result = data
    try:
        for key in re.split(r"\.", path):
            key = int(key) if key.isnumeric() else key
            result = result[key]
    except (KeyError, IndexError, TypeError):
        return default
    return result


def _shq(value: str) -> str:
    """Minimal shell single-quote escaping for command_prompt payloads."""
    return "'" + str(value).replace("'", "'\\''") + "'"


def _as_network(value: str):
    """Parse ``value`` as an IPv4/IPv6 host or CIDR, or ``None``."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _states_prefix(net) -> str | None:
    """Return the string every ``firewall/state`` endpoint in ``net`` starts with.

    Returns ``None`` when ``net`` can't be expressed as such a prefix. States
    render endpoints as ``ip:port`` (IPv4), so a host becomes ``"ip:"`` and an
    octet-aligned network becomes its leading octets plus a dot.
    """
    if net.version != 4:
        return None
    if net.prefixlen == 32:
        return f"{net.network_address}:"
    if net.prefixlen in (8, 16, 24):
        octets = str(net.network_address).split(".")
        return ".".join(octets[: net.prefixlen // 8]) + "."
    return None


def _expand_alias_networks(aliases: list[dict], name: str, _depth: int = 3) -> list:
    """Flatten a host/network alias (following nested aliases) to networks."""
    if _depth <= 0:
        return []
    target = next((a for a in aliases if a.get("name") == name), None)
    if target is None or target.get("type") not in ("host", "network"):
        return []
    found: list = []
    for entry in target.get("address") or []:
        entry = str(entry).strip()
        if not entry or entry.startswith("!"):
            continue
        net = _as_network(entry)
        if net is not None:
            found.append(net)
        else:  # a nested alias reference
            found.extend(_expand_alias_networks(aliases, entry, _depth - 1))
    return found


def _flatten_params(params: dict | None) -> dict | None:
    """Aiohttp needs str values; drop ``None`` and stringify the rest."""
    if not params:
        return None
    return {k: str(v) for k, v in params.items() if v is not None}
