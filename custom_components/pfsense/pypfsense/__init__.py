"""Async client for the pfSense REST API v2 (pfSense-pkg-RESTAPI >= 2.10).

This replaces the previous XML-RPC / ``exec_php`` client entirely. Every call is a
JSON HTTP request against ``/api/v2``. One of three pfRest auth schemes is used
per client: an ``x-api-key`` header, HTTP Basic, or a Bearer JWT the client mints
from ``POST /api/v2/auth/jwt`` (with Basic) and refreshes on expiry.

The response envelope for every endpoint is::

    {"code": 200, "status": "ok", "response_id": "SUCCESS", "message": "", "data": ...}

``_request`` unwraps ``data`` and raises a typed exception for any non-2xx ``code``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import logging
import re
from typing import Any, ClassVar
from urllib.parse import urlparse

import aiohttp

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
API_BASE = "/api/v2"

AUTH_API_KEY = "api_key"
AUTH_BASIC = "basic"
AUTH_JWT = "jwt"
_JWT_MINT_PATH = "/auth/jwt"


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


class PfSenseError(Exception):
    """Base error for all pfSense REST API failures."""


class PfSenseConnectionError(PfSenseError):
    """Network-level failure: DNS, refused connection, TLS, timeout."""


class PfSenseAuthError(PfSenseError):
    """HTTP 401 - the API key is missing or invalid."""


class PfSensePrivilegeError(PfSenseError):
    """HTTP 403 - the key's user lacks privileges for this endpoint."""


class PfSenseNotFoundError(PfSenseError):
    """HTTP 404 - endpoint or resource does not exist (or wrong port / package missing)."""


class PfSenseAPIError(PfSenseError):
    """Any other non-2xx response. Carries ``code`` / ``response_id`` / ``message``."""

    def __init__(self, code: int, response_id: str, message: str) -> None:
        """Store the HTTP code, machine response id and human message."""
        self.code = code
        self.response_id = response_id
        self.message = message
        super().__init__(f"pfSense API {code} {response_id}: {message}")


class Client:
    """pfSense REST API v2 client.

    Parameters
    ----------
    url:
        Base URL of the API, e.g. ``https://pfsense.example:8444``. Any path is
        stripped; ``/api/v2`` is appended internally.
    session:
        Shared :class:`aiohttp.ClientSession`, normally
        ``homeassistant.helpers.aiohttp_client.async_get_clientsession(hass)``.
    auth_method:
        ``"api_key"`` (default), ``"basic"`` or ``"jwt"``.
    api_key:
        Value for the ``x-api-key`` header (System > REST API > Keys). Required
        for ``auth_method="api_key"``.
    username / password:
        A pfSense local user's credentials. Required for ``"basic"`` and
        ``"jwt"`` (the JWT is minted from them and refreshed on expiry).
    verify_ssl:
        Kept for parity with the old client; TLS verification is really governed
        by ``session``, so the caller should pick the session accordingly.
    """

    def __init__(
        self,
        url: str,
        session: aiohttp.ClientSession,
        *,
        auth_method: str = AUTH_API_KEY,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        """Store the base URL, aiohttp session and the chosen auth scheme."""
        parts = urlparse(url.rstrip("/"))
        self._base = f"{parts.scheme}://{parts.netloc}{API_BASE}"
        self._session = session
        self._verify_ssl = verify_ssl
        # Serialize write -> /apply sequences; concurrent applies race on-box.
        self._write_lock = asyncio.Lock()

        self._auth_method = auth_method
        self._api_key = api_key
        self._basic_header: str | None = None
        if auth_method in (AUTH_BASIC, AUTH_JWT):
            if not username or not password:
                raise PfSenseAuthError(
                    f"{auth_method} auth needs a username and password"
                )
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            self._basic_header = f"Basic {token}"
        elif auth_method == AUTH_API_KEY:
            if not api_key:
                raise PfSenseAuthError("api_key auth needs an API key")
        else:
            raise PfSenseAuthError(f"unknown auth method {auth_method!r}")

        self._jwt: str | None = None
        self._jwt_lock = asyncio.Lock()

    # ------------------------------------------------------------------ core

    async def _mint_jwt(self) -> None:
        """Exchange the stored Basic credentials for a fresh JWT."""
        data = await self._request(
            "POST", _JWT_MINT_PATH, payload={}, _auth_header=self._basic_header
        )
        token = (data or {}).get("token")
        if not token:
            raise PfSenseAuthError("auth/jwt did not return a token")
        self._jwt = token

    async def _ensure_jwt(self) -> None:
        if self._jwt is None:
            async with self._jwt_lock:
                if self._jwt is None:
                    await self._mint_jwt()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        payload: dict | None = None,
        _auth_header: str | None = None,
        _retried: bool = False,
    ) -> Any:
        """Perform a request and return the unwrapped ``data`` field."""
        url = f"{self._base}{path}"
        headers: dict[str, str] = {}

        if _auth_header is not None:
            headers["Authorization"] = _auth_header
        elif self._auth_method == AUTH_API_KEY:
            headers["x-api-key"] = self._api_key
        elif self._auth_method == AUTH_BASIC:
            headers["Authorization"] = self._basic_header
        elif self._auth_method == AUTH_JWT:
            await self._ensure_jwt()
            headers["Authorization"] = f"Bearer {self._jwt}"

        try:
            async with self._session.request(
                method,
                url,
                params=_flatten_params(params),
                json=payload,
                headers=headers or None,
                ssl=self._verify_ssl,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as resp:
                try:
                    body = await resp.json(content_type=None)
                except (aiohttp.ClientError, ValueError):
                    body = {}
                return self._unwrap(resp.status, body)
        except asyncio.TimeoutError as err:
            raise PfSenseConnectionError(f"timeout contacting {url}") from err
        except aiohttp.ClientError as err:
            raise PfSenseConnectionError(str(err)) from err
        except PfSenseAuthError:
            # A JWT can expire mid-session; mint a new one and retry once.
            if (
                self._auth_method == AUTH_JWT
                and _auth_header is None
                and not _retried
                and path != _JWT_MINT_PATH
            ):
                self._jwt = None  # forces a re-mint on the retry
                return await self._request(
                    method,
                    path,
                    params=params,
                    payload=payload,
                    _retried=True,
                )
            raise

    @staticmethod
    def _unwrap(http_status: int, body: dict) -> Any:
        code = body.get("code", http_status)
        if 200 <= code < 300:
            return body.get("data")

        response_id = body.get("response_id", "")
        message = body.get("message", "")
        if code == 401:
            raise PfSenseAuthError(message or "authentication failed")
        if code == 403:
            raise PfSensePrivilegeError(message or "insufficient privileges")
        if code == 404:
            raise PfSenseNotFoundError(message or "not found")
        raise PfSenseAPIError(code, response_id, message)

    async def _get(self, path: str, **params) -> Any:
        return await self._request("GET", path, params=params or None)

    async def _apply(self, area: str) -> None:
        """POST the area's /apply endpoint (firewall, routing, ...)."""
        await self._request("POST", f"/{area}/apply", payload={})

    # -------------------------------------------------------------- identity

    async def get_system_info(self) -> dict:
        """Hostname / domain / serial / netgate id / platform, old-client shape."""
        status, hostname = await asyncio.gather(
            self._get("/status/system"),
            self._get("/system/hostname"),
        )
        return {
            "hostname": hostname.get("hostname"),
            "domain": hostname.get("domain"),
            "serial": status.get("serial"),
            "netgate_device_id": status.get("netgate_id"),
            "platform": status.get("platform"),
        }

    async def get_host_firmware_version(self) -> dict:
        """Old-client shape: ``{"platform": ..., "firmware": {"version": ...}}``."""
        status, version = await asyncio.gather(
            self._get("/status/system"),
            self._get("/system/version"),
        )
        return {
            "platform": status.get("platform"),
            "firmware": {"version": version.get("version")},
            "base": version.get("base"),
            "patch": version.get("patch"),
            "buildtime": version.get("buildtime"),
        }

    async def get_firmware_update_info(self) -> dict | None:
        """No base-system update endpoint in REST v2. Kept as a graceful no-op.

        ``/system/packages`` (add-on packages) 500s when no packages are
        installed, so it is not a safe substitute here.
        """
        return None

    async def get_dns_servers(self) -> list[str]:
        """Return the configured system DNS servers."""
        data = await self._get("/system/dns")
        return data.get("dnsserver", []) if isinstance(data, dict) else []

    # ------------------------------------------------------------ telemetry

    async def get_telemetry(self) -> dict:
        """Rebuild the legacy ``telemetry`` dict from decomposed status endpoints.

        Keeps the nested shape ``sensor.py`` and ``__init__.py`` depend on:
        ``interfaces.{name}.{counter}``, ``gateways.{name}.{prop}``,
        ``openvpn.servers.{vpnid}.{prop}``, ``cpu.*``, ``system.*``, ``wan_ip``.
        """
        (
            system,
            interfaces,
            gateways,
            ovpn_servers,
            gateways_detail,
        ) = await asyncio.gather(
            self._get("/status/system"),
            self._get("/status/interfaces"),
            self._get("/status/gateways"),
            self._get("/status/openvpn/servers"),
            self.get_gateways_detail(),
        )
        return _build_telemetry(
            system, interfaces, gateways, ovpn_servers, gateways_detail
        )

    # ------------------------------------------------------------- services

    async def get_services(self) -> list[dict]:
        """Return the list of pfSense services and their status."""
        data = await self._get("/status/services")
        return data or []

    async def _service_action(self, service: dict, action: str) -> None:
        await self._request(
            "POST",
            "/status/service",
            payload={"id": service["id"], "action": action},
        )

    async def _find_service(self, service_name: str) -> dict | None:
        for svc in await self.get_services():
            if svc.get("name") == service_name:
                return svc
        return None

    async def start_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Start a pfSense service by name."""
        svc = service if isinstance(service, dict) and "id" in service else None
        svc = svc or await self._find_service(service_name)
        if svc:
            await self._service_action(svc, "start")

    async def stop_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Stop a pfSense service by name."""
        svc = service if isinstance(service, dict) and "id" in service else None
        svc = svc or await self._find_service(service_name)
        if svc:
            await self._service_action(svc, "stop")

    async def restart_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Restart a pfSense service by name."""
        svc = service if isinstance(service, dict) and "id" in service else None
        svc = svc or await self._find_service(service_name)
        if svc:
            await self._service_action(svc, "restart")

    async def restart_service_if_running(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Restart a pfSense service only if it is currently running."""
        svc = service if isinstance(service, dict) and "id" in service else None
        svc = svc or await self._find_service(service_name)
        if svc and svc.get("status"):
            await self._service_action(svc, "restart")

    # ---------------------------------------------------------------- dhcp

    async def get_dhcp_leases(self, dns_lookups=None) -> list[dict]:
        """Return the current DHCP leases."""
        data = await self._get("/status/dhcp_server/leases")
        return data or []

    # ----------------------------------------------------------------- arp

    async def get_arp_table(self, resolve_hostnames: bool = False) -> list[dict]:
        """Return the ARP table entries."""
        data = await self._get("/diagnostics/arp_table")
        return data or []

    async def delete_arp_entry(self, ip: str) -> None:
        """Delete the ARP entry for an IP address."""
        if not ip:
            return
        entry_id: Any = ip
        # The endpoint may not accept an IP string; fall back to index lookup.
        for entry in await self.get_arp_table():
            if entry.get("ip_address") == ip:
                entry_id = entry.get("id", ip)
                break
        with contextlib.suppress(PfSenseNotFoundError):
            await self._request(
                "DELETE", "/diagnostics/arp_table/entry", params={"id": entry_id}
            )

    # ------------------------------------------------------------ gateways

    async def get_gateways_detail(self) -> dict:
        """Config-side gateway data keyed by name (weight / interface / default)."""
        gateways, default = await asyncio.gather(
            self._get("/routing/gateways"),
            self._get("/routing/gateway/default"),
        )
        default_names = set()
        if isinstance(default, dict):
            default_names = {
                default.get("defaultgw4"),
                default.get("defaultgw6"),
            }
            default_names.discard(None)
        out = {}
        for gw in gateways or []:
            name = gw.get("name")
            gw = dict(gw)
            gw["isdefaultgw"] = name in default_names
            out[name] = gw
        return out

    async def set_default_gateway(self, gateway: str, ip_version: str = "4") -> None:
        """Set the default IPv4 or IPv6 gateway and apply routing."""
        key = "defaultgw6" if "6" in str(ip_version) else "defaultgw4"
        async with self._write_lock:
            await self._request(
                "PATCH", "/routing/gateway/default", payload={key: gateway}
            )
            await self._apply("routing")

    # -------------------------------------------------------- firewall rules

    async def get_filter_rules(self) -> list[dict]:
        """Return the firewall filter rules."""
        data = await self._get("/firewall/rules")
        return data or []

    async def get_nat_port_forward_rules(self) -> list[dict]:
        """Return the NAT port-forward rules."""
        data = await self._get("/firewall/nat/port_forwards")
        return data or []

    async def get_nat_outbound_rules(self) -> list[dict]:
        """Return the NAT outbound mappings."""
        data = await self._get("/firewall/nat/outbound/mappings")
        return data or []

    # pfSense's own webConfigurator stores content-less config elements
    # (``<statetype></statetype>``) that the REST API surfaces as empty strings.
    # A PATCH re-validates the whole rule object, so those empty-but-required
    # fields make an otherwise unrelated toggle fail with
    # ``FIELD_EMPTY_NOT_ALLOWED``. Re-send them with the value pfSense would
    # have defaulted to, which is a no-op for the rule's behaviour.
    _RULE_REQUIRED_DEFAULTS: ClassVar[dict[str, dict[str, str]]] = {
        "/firewall/rule": {"statetype": "keep state"},
    }

    async def _set_rule_disabled(
        self, path: str, rules: list[dict], match_key: str, match_value, disabled: bool
    ) -> None:
        for rule in rules:
            if str(rule.get(match_key)) != str(match_value):
                continue
            if bool(rule.get("disabled")) == disabled:
                return
            payload = {"id": rule["id"], "disabled": disabled}
            payload.update(
                {
                    field: fallback
                    for field, fallback in self._RULE_REQUIRED_DEFAULTS.get(
                        path, {}
                    ).items()
                    if not rule.get(field)
                }
            )
            async with self._write_lock:
                await self._request("PATCH", path, payload=payload)
                await self._apply("firewall")
            return

    async def enable_filter_rule_by_tracker(self, tracker) -> None:
        """Enable the firewall rule with the given tracker id."""
        await self._set_rule_disabled(
            "/firewall/rule", await self.get_filter_rules(), "tracker", tracker, False
        )

    async def disable_filter_rule_by_tracker(self, tracker) -> None:
        """Disable the firewall rule with the given tracker id."""
        await self._set_rule_disabled(
            "/firewall/rule", await self.get_filter_rules(), "tracker", tracker, True
        )

    async def enable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        """Enable the NAT port-forward rule with the given created_time."""
        await self._set_rule_disabled(
            "/firewall/nat/port_forward",
            await self.get_nat_port_forward_rules(),
            "created_time",
            created_time,
            False,
        )

    async def disable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        """Disable the NAT port-forward rule with the given created_time."""
        await self._set_rule_disabled(
            "/firewall/nat/port_forward",
            await self.get_nat_port_forward_rules(),
            "created_time",
            created_time,
            True,
        )

    async def enable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        """Enable the NAT outbound mapping with the given created_time."""
        await self._set_rule_disabled(
            "/firewall/nat/outbound/mapping",
            await self.get_nat_outbound_rules(),
            "created_time",
            created_time,
            False,
        )

    async def disable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        """Disable the NAT outbound mapping with the given created_time."""
        await self._set_rule_disabled(
            "/firewall/nat/outbound/mapping",
            await self.get_nat_outbound_rules(),
            "created_time",
            created_time,
            True,
        )

    # -------------------------------------------------------------- aliases

    async def update_alias_address(
        self,
        alias_name: str,
        address: str,
        action: str = "add",
        kill_states: bool = True,
    ) -> None:
        """Add or remove an address in a firewall alias and apply."""
        aliases = await self._get("/firewall/aliases") or []
        target = next((a for a in aliases if a.get("name") == alias_name), None)

        if target is None:
            if action != "add":
                return
            payload = {
                "name": alias_name,
                "type": "host",
                "descr": "Managed automatically by Home Assistant",
                "address": [address],
                "detail": ["Added via HASS"],
            }
            async with self._write_lock:
                await self._request("POST", "/firewall/alias", payload=payload)
                await self._apply("firewall")
        else:
            addresses = list(target.get("address") or [])
            details = list(target.get("detail") or [])
            while len(details) < len(addresses):
                details.append("")

            if action == "add" and address not in addresses:
                addresses.append(address)
                details.append("Added via HASS")
            elif action == "remove" and address in addresses:
                idx = addresses.index(address)
                addresses.pop(idx)
                if idx < len(details):
                    details.pop(idx)
            else:
                return

            async with self._write_lock:
                await self._request(
                    "PATCH",
                    "/firewall/alias",
                    payload={
                        "id": target["id"],
                        "address": addresses,
                        "detail": details,
                    },
                )
                await self._apply("firewall")

        if kill_states and address:
            await self.kill_states(address)

    # ----------------------------------------------------------- carp / vip

    async def get_carp_status(self) -> bool:
        """Return True when CARP is enabled and not in maintenance mode."""
        data = await self._get("/status/carp")
        if not isinstance(data, dict):
            return False
        return bool(data.get("enable")) and not data.get("maintenance_mode")

    async def get_carp_interfaces(self) -> list[dict]:
        """Return the CARP virtual IPs with their status."""
        data = await self._get("/firewall/virtual_ips") or []
        carp = []
        for vip in data:
            if vip.get("mode") != "carp":
                continue
            vip = dict(vip)
            vip["status"] = vip.get("carp_status")
            carp.append(vip)
        return carp

    # --------------------------------------------------------- state table

    async def reset_state_table(self) -> None:
        """Flush the entire firewall state table."""
        await self._request("DELETE", "/firewall/states", params={"limit": 0})

    async def kill_states(self, source: str, destination: str | None = None) -> None:
        """Kill states for a source (and optional destination) via pfctl."""
        cmd = f"/sbin/pfctl -k {_shq(source)}"
        if destination:
            cmd += f" -k {_shq(destination)}"
        await self.exec_command(cmd)

    async def kill_states_for_rule(self, rule: dict) -> None:
        """Drop state-table entries for the hosts/networks a rule matches on.

        Used when a rule switch is toggled so existing connections don't keep
        flowing under the old ruleset. REST-only, best effort: this uses the
        ``DELETE /firewall/states`` prefix filter, so rule endpoints it can't
        turn into an IPv4 host / octet-aligned CIDR prefix -- ``any``,
        ``(self)``, interface macros (``wan:ip``), negated aliases, non
        octet-aligned networks (e.g. ``/25``), IPv6 -- are skipped rather than
        falling back to ``pfctl``.
        """
        prefixes: set[str] = set()
        for net in await self._rule_match_networks(rule):
            prefix = _states_prefix(net)
            if prefix:
                prefixes.add(prefix)
        if not prefixes:
            return

        async with self._write_lock:
            for prefix in prefixes:
                for field in ("source", "destination"):
                    with contextlib.suppress(PfSenseAPIError):
                        await self._request(
                            "DELETE",
                            "/firewall/states",
                            params={f"{field}__startswith": prefix, "limit": 0},
                        )

    async def _rule_match_networks(self, rule: dict) -> list:
        """Concrete ``ip_network`` objects for a rule's source + destination."""
        out: list = []
        aliases: list[dict] | None = None
        for side in ("source", "destination"):
            value = rule.get(side)
            if not isinstance(value, str):
                continue
            value = value.strip()
            if not value or value.startswith("!") or value in ("any", "(self)"):
                continue
            if ":" in value:  # interface address macros, e.g. ``wan:ip``
                continue
            net = _as_network(value)
            if net is not None:
                out.append(net)
                continue
            # Otherwise treat it as an alias name and expand it.
            if aliases is None:
                aliases = await self._get("/firewall/aliases") or []
            out.extend(_expand_alias_networks(aliases, value))
        return out

    # ------------------------------------------------------- system control

    async def system_reboot(self, type: str = "normal") -> None:
        """Reboot the firewall."""
        # The connection drops as the box goes down -- that is success.
        with contextlib.suppress(PfSenseConnectionError):
            await self._request("POST", "/diagnostics/reboot", payload={})

    async def system_halt(self) -> None:
        """Halt (power off) the firewall."""
        # The connection drops as the box goes down -- that is success.
        with contextlib.suppress(PfSenseConnectionError):
            await self._request("POST", "/diagnostics/halt_system", payload={})

    # ------------------------------------------------------------------ wol

    async def send_wol(self, interface: str, mac: str) -> None:
        """Send a Wake-on-LAN magic packet on an interface."""
        await self._request(
            "POST",
            "/services/wake_on_lan/send",
            payload={"interface": interface, "mac_addr": mac},
        )

    # -------------------------------------------------------------- exec_*

    async def exec_command(self, command: str, background: bool = False) -> str:
        """Run a shell command via the diagnostics endpoint and return its output."""
        if background:
            command = f"{command} &"
        data = await self._request(
            "POST", "/diagnostics/command_prompt", payload={"command": command}
        )
        return data.get("output", "") if isinstance(data, dict) else ""


# ---------------------------------------------------------------- helpers


def client_from_config(
    url: str,
    session: aiohttp.ClientSession,
    data: dict,
    verify_ssl: bool,
) -> Client:
    """Build a :class:`Client` from a config-entry ``data`` mapping.

    Reads ``auth_method`` (default ``"api_key"``) and the credential keys
    (``api_key`` / ``username`` / ``password``). Shared by the integration
    setup and the config flow so the auth branching lives in one place.
    """
    method = data.get("auth_method", AUTH_API_KEY)
    return Client(
        url,
        session,
        auth_method=method,
        api_key=data.get("api_key"),
        username=data.get("username"),
        password=data.get("password"),
        verify_ssl=verify_ssl,
    )


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


_INTERFACE_RATE_PROPS = (
    "inbytes",
    "outbytes",
    "inbytespass",
    "outbytespass",
    "inpkts",
    "outpkts",
    "inpktspass",
    "outpktspass",
)


def _build_telemetry(
    system: dict,
    interfaces: list,
    gateways: list,
    ovpn_servers: list,
    gateways_detail: dict | None = None,
) -> dict:
    system = system or {}
    load = system.get("cpu_load_avg") or [None, None, None]

    telemetry: dict = {
        "wan_ip": "Disconnected",
        "cpu": {
            "used_percent": system.get("cpu_usage"),
            "count": system.get("cpu_count"),
            "model": system.get("cpu_model"),
        },
        "memory": {
            "used_percent": system.get("mem_usage"),
            "swap_used_percent": system.get("swap_usage"),
        },
        "mbuf": {"used_percent": system.get("mbuf_usage")},
        "system": {
            "uptime": system.get("uptime"),
            "temp": system.get("temp_c"),
            "load_average": {
                "one_minute": load[0] if len(load) > 0 else None,
                "five_minute": load[1] if len(load) > 1 else None,
                "fifteen_minute": load[2] if len(load) > 2 else None,
            },
        },
        "disk_used_percent": system.get("disk_usage"),
        "filesystems": [],
        "interfaces": {},
        "gateways": {},
        "gateways_detail": gateways_detail or {},
        "openvpn": {"servers": {}},
    }

    for iface in interfaces or []:
        name = iface.get("name")
        if not name:
            continue
        entry = dict(iface)
        entry["ifname"] = name
        entry["descr"] = iface.get("descr", name)
        telemetry["interfaces"][name] = entry
        if name == "wan":
            telemetry["wan_ip"] = iface.get("ipaddr") or "Disconnected"

    for gw in gateways or []:
        name = gw.get("name")
        if name:
            telemetry["gateways"][name] = dict(gw)

    for server in ovpn_servers or []:
        vpnid = str(server.get("vpnid"))
        conns = server.get("conns") or []
        telemetry["openvpn"]["servers"][vpnid] = {
            "name": server.get("name"),
            "vpnid": server.get("vpnid"),
            "connected_client_count": len(conns),
            "total_bytes_recv": sum(c.get("bytes_recv", 0) for c in conns),
            "total_bytes_sent": sum(c.get("bytes_sent", 0) for c in conns),
        }

    return telemetry
