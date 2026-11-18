"""Async client for Netgate's official pfSense API (served by the Nexus controller).

Spec: https://github.com/Netgate/pfsense-api (``pfapi_openapi.yml``). The device
API is served directly by the firewall, usually ``https://<firewall>:8443/api``.

Authentication (verified on 26.07 hardware):

- ``POST /api/login`` with **base64-encoded** ``username`` / ``password``
  returns ``{"token", "user", "version", "alerts"}`` and sets the
  ``pfsense-refresh-token`` cookie (``Secure; HttpOnly;
  Path=/api/login/refresh``, 24 h).
- The token is a JWT used as ``Authorization: Bearer``. Its ``exp`` claim puts
  it **300 s** out; there is no ``iat``.
- ``POST /api/login/refresh {"username"}`` with the Bearer and the cookie
  returns a fresh 300 s token.
- An invalid, expired or missing session is **HTTP 400** (not 401) with
  ``errmsg`` ``"session invalid, reauthenticate (...)"``. Errors are
  ``{"errcode", "errlevel", "errmsg"}``, so they are classified from
  ``errmsg``, not just the status code.

The refresh cookie is handled by hand rather than by a cookie jar: aiohttp's
default jar ignores cookies from bare-IP hosts, which is how most firewalls
are addressed.

Failed logins count towards pfSense's login lockout, so a rejected login is
**latched**: the client raises it again without contacting the firewall until
it is rebuilt with new credentials (Home Assistant's reauth flow does that).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import ipaddress
import json
import logging
import time
from typing import Any
from urllib.parse import quote, urlparse

import aiohttp

from . import netgate_map
from .errors import (
    PfSenseAPIError,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
    PfSenseUnsupportedError,
)
from .util import (
    NOTICES_COMMAND,
    _as_network,
    _expand_alias_networks,
    _shq,
    parse_notices,
    parse_pf_states,
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
API_PREFIX = "/api"
LOGIN_PATH = "/login"
REFRESH_PATH = "/login/refresh"
REFRESH_COOKIE = "pfsense-refresh-token"
# Refresh this long before the access token expires.
REFRESH_MARGIN = 60
# Responses several reads share within one poll are fetched once per window.
SHARED_TTL = 5.0
UPDATE_INFO_TTL = 3600.0
# While an upgrade is running, re-read the update status this often so the
# new version is noticed soon after the reboot.
DYNDNS_TTL = 300
UPDATE_INFO_TTL_UPGRADING = 60.0


class _SessionInvalid(PfSenseAuthError):
    """The access token was rejected; a refresh or re-login may fix it."""


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def _b64_text(value) -> str:
    """Decode a base64 text field, or return it unchanged if it isn't base64."""
    raw = str(value or "")
    try:
        return base64.b64decode(raw, validate=True).decode(errors="replace")
    except (binascii.Error, ValueError):
        return raw


def _token_expiry(token: str) -> float | None:
    """Return the JWT's ``exp`` (unverified; only used to schedule refreshes)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp")
    except (IndexError, ValueError, binascii.Error, AttributeError):
        return None
    return float(exp) if isinstance(exp, (int, float)) else None


def _raise_for(status: int, body: Any) -> None:
    """Raise the typed error for a non-2xx Netgate API response."""
    body = body if isinstance(body, dict) else {}
    message = str(body.get("errmsg") or "").strip()
    code = body.get("errcode")
    lowered = message.lower()

    if "session invalid" in lowered or "reauthenticate" in lowered:
        raise _SessionInvalid(message)
    if "invalid credentials" in lowered or status == 401:
        raise PfSenseAuthError(message or "authentication failed")
    if "unauthorized" in lowered or "not authorized" in lowered or status == 403:
        raise PfSensePrivilegeError(message or "insufficient privileges")
    if status == 404:
        raise PfSenseNotFoundError(message or "not found")
    raise PfSenseAPIError(
        status, str(code) if code is not None else "", message or "request failed"
    )


class NetgateClient:
    """Netgate official API (Nexus) client.

    Parameters
    ----------
    url:
        Base URL of the firewall's API, e.g. ``https://pfsense.example:8443``.
        Any path is stripped; ``/api`` is appended internally.
    session:
        Shared :class:`aiohttp.ClientSession`.
    username / password:
        A pfSense user in the ``admins`` group or the ``mim_*`` groups for the
        features used.
    verify_ssl:
        Whether to verify the API's TLS certificate.
    """

    def __init__(
        self,
        url: str,
        session: aiohttp.ClientSession,
        *,
        username: str | None,
        password: str | None,
        verify_ssl: bool = True,
    ) -> None:
        """Store the base URL, session and credentials; no I/O happens here."""
        if not username or not password:
            raise PfSenseAuthError("the Netgate API needs a username and password")
        parts = urlparse(url.rstrip("/"))
        self._base = f"{parts.scheme}://{parts.netloc}{API_PREFIX}"
        self._session = session
        self._verify_ssl = verify_ssl
        self._username = username
        self._password = password

        self._token: str | None = None
        self._token_exp: float | None = None
        self._refresh_cookie: str | None = None
        self._auth_lock = asyncio.Lock()
        self._login_error: PfSenseAuthError | PfSensePrivilegeError | None = None
        self._write_lock = asyncio.Lock()
        self._shared: dict[str, tuple[float, asyncio.Future]] = {}
        self._update_info: tuple[float, dict | None] | None = None
        self._upgrade_from: str | None = None
        self._packages: tuple[float, list[dict]] | None = None
        self._dyndns: tuple[float, list[dict]] | None = None
        self._certificates: tuple[float, list[dict]] | None = None
        self._package_upgrading: dict[str, str] = {}

    # ---------------------------------------------------------------- http

    async def _http(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        payload: Any = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[Any, aiohttp.ClientResponse]:
        """Send one request; return ``(json body, response)`` or raise typed."""
        url = f"{self._base}{path}"
        try:
            async with self._session.request(
                method,
                url,
                params=params,
                json=payload,
                headers=headers,
                ssl=self._verify_ssl,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as resp:
                try:
                    body = await resp.json(content_type=None)
                except (aiohttp.ClientError, ValueError):
                    body = None
                if not 200 <= resp.status < 300:
                    _raise_for(resp.status, body)
                return body, resp
        except TimeoutError as err:
            raise PfSenseConnectionError(f"timeout contacting {url}") from err
        except aiohttp.ClientError as err:
            raise PfSenseConnectionError(str(err)) from err

    # ---------------------------------------------------------------- auth

    def _adopt(self, body: Any, resp: aiohttp.ClientResponse) -> None:
        token = body.get("token") if isinstance(body, dict) else None
        if not token:
            raise PfSenseAuthError("the Netgate API login returned no token")
        self._token = token
        self._token_exp = _token_expiry(token)
        cookie = resp.cookies.get(REFRESH_COOKIE)
        if cookie is not None and cookie.value:
            self._refresh_cookie = cookie.value

    async def _login(self) -> None:
        if self._login_error is not None:
            raise self._login_error
        try:
            body, resp = await self._http(
                "POST",
                LOGIN_PATH,
                payload={
                    "username": _b64(self._username),
                    "password": _b64(self._password),
                },
            )
        except (PfSenseAuthError, PfSensePrivilegeError) as err:
            # Do not retry: repeated failures lock the source address out.
            self._login_error = (
                PfSenseAuthError(str(err)) if isinstance(err, _SessionInvalid) else err
            )
            raise self._login_error from err
        self._adopt(body, resp)

    async def _refresh(self) -> bool:
        """Swap the token for a new one; False if a full login is needed."""
        if not (self._token and self._refresh_cookie):
            return False
        try:
            body, resp = await self._http(
                "POST",
                REFRESH_PATH,
                payload={"username": self._username},
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Cookie": f"{REFRESH_COOKIE}={self._refresh_cookie}",
                },
            )
            self._adopt(body, resp)
        except (PfSenseAuthError, PfSenseAPIError) as err:
            _LOGGER.debug("Netgate API token refresh failed (%s); logging in", err)
            return False
        return True

    def _token_fresh(self) -> bool:
        if self._token is None:
            return False
        if self._token_exp is None:
            return True  # unknown lifetime: use it until it is rejected
        return self._token_exp - time.time() > REFRESH_MARGIN

    async def _ensure_token(self, stale: str | None = None) -> str:
        """Return a usable access token, refreshing or logging in as needed.

        ``stale`` is a token the API just rejected; it is dropped unless another
        request has already replaced it.
        """
        async with self._auth_lock:
            if stale is not None and self._token == stale:
                self._token_exp = 0.0
            if not self._token_fresh() and not await self._refresh():
                self._token = self._token_exp = self._refresh_cookie = None
                await self._login()
            assert self._token is not None
            return self._token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        payload: Any = None,
    ) -> Any:
        """Authenticated request; one retry after a rejected session."""
        token = await self._ensure_token()
        try:
            body, _ = await self._http(
                method,
                path,
                params=params,
                payload=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
        except _SessionInvalid:
            token = await self._ensure_token(stale=token)
            try:
                body, _ = await self._http(
                    method,
                    path,
                    params=params,
                    payload=payload,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except _SessionInvalid as err:
                raise PfSenseAuthError(str(err)) from err
        return body

    async def _get(self, path: str, **params) -> Any:
        return await self._request("GET", path, params=params or None)

    async def _get_shared(self, path: str) -> Any:
        """GET ``path`` once for every caller within ``SHARED_TTL`` seconds.

        Several backend methods read the same endpoint (``/system/status``
        feeds identity, firmware and telemetry) and the poll runs them
        concurrently.
        """
        now = time.monotonic()
        cached = self._shared.get(path)
        if cached is not None and now - cached[0] < SHARED_TTL:
            future = cached[1]
        else:
            future = asyncio.ensure_future(self._get(path))
            self._shared[path] = (now, future)
            future.add_done_callback(self._forget_failed(path, future))
        return await asyncio.shield(future)

    def _forget_failed(self, path: str, future: asyncio.Future):
        def callback(done: asyncio.Future) -> None:
            if (done.cancelled() or done.exception() is not None) and (
                self._shared.get(path, (0, None))[1] is future
            ):
                self._shared.pop(path, None)

        return callback

    # ------------------------------------------------------------ identity

    async def _status(self) -> dict:
        body = await self._get_shared("/system/status")
        return (body or {}).get("status") or {}

    @staticmethod
    def _platform(status: dict) -> str | None:
        """``"Netgate 6100"``: the vendor + model string pfrest reports.

        Falls back to the product name (``"pfSense"``) on hardware that has no
        vendor/model, so the HA device model is the same on either backend.
        """
        vendor, machine = status.get("vndr"), status.get("machine")
        if vendor and machine:
            return f"{vendor} {machine}"
        return status.get("prod")

    async def get_system_info(self) -> dict:
        """Hostname / domain / serial / netgate id / platform.

        ``ndi`` is the same Netgate device id pfrest reports as ``netgate_id``
        (verified on hardware), so entities keep their unique ids. The Nexus
        API exposes no serial number; nothing in the integration reads it.
        """
        status, setup = await asyncio.gather(
            self._status(), self._get_shared("/system/setup")
        )
        setup = setup or {}
        hostname = setup.get("hostname")
        domain = setup.get("domain")
        if not hostname and status.get("host"):
            hostname, _, domain = str(status["host"]).partition(".")
        return {
            "hostname": hostname,
            "domain": domain,
            "serial": None,
            "netgate_device_id": status.get("ndi"),
            "platform": self._platform(status),
        }

    async def get_host_firmware_version(self) -> dict:
        """Same shape as pfrest, parsed from ``osver``.

        ``osver`` looks like ``"26.07-RELEASE - 20260807-1926"``; base and
        patch come from the version (``26.07.1`` -> base ``26.07``, patch ``1``).
        """
        status = await self._status()
        version, _, buildtime = str(status.get("osver") or "").partition(" - ")
        version = version.strip() or None
        number = (version or "").split("-", 1)[0]
        pieces = number.split(".")
        base = ".".join(pieces[:2]) or None
        patch = pieces[2] if len(pieces) > 2 else "0"
        return {
            "platform": self._platform(status),
            "firmware": {"version": version},
            "base": base,
            "patch": patch if base else None,
            "buildtime": buildtime.strip() or None,
        }

    # -------------------------------------------------------------- reads

    async def _monitoring(self, dataset: str) -> dict[str, float]:
        """Latest value per series of a ``system`` monitoring dataset.

        The API's minimum resolution is 60 s, so each value is the average of
        the most recent minute.
        """
        now = int(time.time())
        body = await self._request(
            "POST",
            "/system/monitoring",
            payload={
                "scope": "system",
                "dataset": dataset,
                "start_time_unix_seconds": now - 300,
                "end_time_unix_seconds": now,
                "resolution_seconds": 60,
            },
        )
        return netgate_map.monitoring_latest(body)

    async def _optional(self, coro) -> Any:
        """A telemetry part that must not fail the whole telemetry read."""
        try:
            return await coro
        except (PfSenseAPIError, PfSenseNotFoundError, PfSensePrivilegeError) as err:
            _LOGGER.debug("Netgate API telemetry part unavailable: %s", err)
            return None

    async def get_telemetry(self) -> dict:
        """The legacy ``telemetry`` dict (see :func:`netgate_map.build_telemetry`).

        Interface and gateway status are required; system resource series,
        controller stats (load average), gateway config and OpenVPN status
        degrade to empty values when missing.
        """
        (
            status,
            interfaces,
            gateways,
            detail,
            openvpn,
            processor,
            sensors,
            mbuf,
            stats,
        ) = await asyncio.gather(
            self._status(),
            self._get_shared("/system/interfaces/status"),
            self._get("/system/gateways/status"),
            self._optional(self.get_gateways_detail()),
            self._optional(self._get("/vpn/openvpn/status")),
            self._optional(self._monitoring("processor")),
            self._optional(self._monitoring("sensors")),
            self._optional(self._monitoring("mbuf")),
            self._optional(self._get("/controller/stats")),
        )
        return netgate_map.build_telemetry(
            status,
            interfaces,
            gateways,
            detail or {},
            openvpn,
            processor or {},
            sensors or {},
            mbuf or {},
            netgate_map.load_average(stats),
        )

    async def get_firmware_update_info(self) -> dict | None:
        """Base-system update status from ``/system/update``, cached for an hour.

        pfSense checks its package repository on its own schedule; this only
        reads the result, so there is no point asking every poll.
        """
        now = time.monotonic()
        ttl = UPDATE_INFO_TTL_UPGRADING if self._upgrade_from else UPDATE_INFO_TTL
        if self._update_info and now - self._update_info[0] < ttl:
            return self._update_info[1]
        info = netgate_map.firmware_update_info(await self._get("/system/update"))
        self._update_info = (now, info)
        installed = ((info or {}).get("base") or {}).get("installed_version")
        if self._upgrade_from and installed and installed != self._upgrade_from:
            self._upgrade_from = None  # the upgrade landed
        return info

    async def start_firmware_update(self) -> None:
        """Start a base-system upgrade on the current firmware branch.

        LIVE-CHECK (unverified on hardware): ``POST /system/update
        {"firmware_branch": ...}`` is taken from the spec. The box reboots
        during the upgrade, so a dropped connection counts as started. Until
        the installed version changes, the update status is re-read every
        minute instead of hourly.
        """
        body = await self._get("/system/update") or {}
        info = netgate_map.firmware_update_info(body)
        installed = ((info or {}).get("base") or {}).get("installed_version")
        branch = body.get("firmware_branch") or installed
        if not branch:
            raise PfSenseAPIError(
                0, "", "cannot determine the firmware branch to upgrade"
            )
        async with self._write_lock:
            with contextlib.suppress(PfSenseConnectionError):
                await self._request(
                    "POST", "/system/update", payload={"firmware_branch": branch}
                )
        self._upgrade_from = installed
        self._update_info = None

    async def get_installed_packages(self) -> list[dict]:
        """Add-on packages and their available updates, cached for an hour.

        While a package upgrade is pending, re-read every minute until its
        installed version changes.
        """
        now = time.monotonic()
        ttl = UPDATE_INFO_TTL_UPGRADING if self._package_upgrading else UPDATE_INFO_TTL
        if self._packages and now - self._packages[0] < ttl:
            return self._packages[1]
        packages = netgate_map.installed_packages(
            await self._get("/system/package/installed")
        )
        self._packages = (now, packages)
        for pkg in packages:
            if self._package_upgrading.get(pkg["name"]) not in (
                None,
                pkg["installed_version"],
            ):
                del self._package_upgrading[pkg["name"]]  # it landed
        return packages

    async def install_package_update(self, name: str) -> None:
        """Upgrade one installed package to its latest version.

        ``POST /system/package/install {"packages": [{"name": <pkg name>}]}``;
        the package is named as pfSense lists it (``pfSense-pkg-<name>``).
        """
        packages = await self.get_installed_packages()
        pkg = next((p for p in packages if p["name"] == name), None)
        if pkg is None:
            raise PfSenseNotFoundError(f"package {name!r} is not installed")
        async with self._write_lock:
            await self._request(
                "POST",
                "/system/package/install",
                payload={"packages": [{"name": pkg["package"]}]},
            )
        self._package_upgrading[name] = pkg["installed_version"]
        self._packages = None

    async def get_dyndns(self) -> list[dict]:
        """Dynamic DNS entries with their last update, cached for 5 minutes.

        The entry list comes from ``/services/dyndns`` (credentials dropped).
        The address and time of the last successful update come from
        pfSense's ``/conf/dyndns_*.cache`` files, read in one shell call.
        Without shell access the entries are still returned, with no address
        and ``cache_readable`` false.
        """
        now = time.monotonic()
        if self._dyndns and now - self._dyndns[0] < DYNDNS_TTL:
            return self._dyndns[1]
        entries = netgate_map.dyndns_entries(await self._get("/services/dyndns"))
        caches: dict[str, list[str]] = {}
        readable = False
        if entries:
            lines = []
            for entry in entries:
                path = netgate_map.dyndns_cache_file(entry)
                lines.append(
                    f"printf '%s\\t%s\\t%s\\n' {_shq(entry['id'])}"
                    f' "$(cat {_shq(path)} 2>/dev/null)"'
                    f' "$(cat {_shq(path.removesuffix(".cache") + "_v6.cache")} 2>/dev/null)"'
                )
            try:
                out = await self.exec_command("; ".join(lines))
            except (PfSensePrivilegeError, PfSenseNotFoundError) as err:
                _LOGGER.debug("Dynamic DNS cache unreadable: %s", err)
            else:
                readable = True
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) == 3:
                        caches[parts[0]] = parts[1:]
        for entry in entries:
            ipv4_text, ipv6_text = caches.get(entry["id"], ["", ""])
            ip, when = netgate_map.parse_dyndns_cache(ipv4_text)
            ipv6, when6 = netgate_map.parse_dyndns_cache(ipv6_text)
            stamps = [t for t in (when, when6) if t]
            entry.update(
                ip=ip,
                ipv6=ipv6,
                last_update=max(stamps) if stamps else None,
                cache_readable=readable,
            )
        self._dyndns = (now, entries)
        return entries

    async def get_certificates(self) -> list[dict]:
        """In-use and server certificates with their expiry, cached for an hour."""
        now = time.monotonic()
        if self._certificates and now - self._certificates[0] < UPDATE_INFO_TTL:
            return self._certificates[1]
        certs = netgate_map.certificates(await self._get("/system/certificates"))
        self._certificates = (now, certs)
        return certs

    async def get_state_table(self) -> dict:
        """State-table size and limit (``/diag/pfinfo``), no shell needed.

        pfinfo is ``pfctl -si`` / ``-sm`` text, base64-encoded. The
        ``system/states`` monitoring dataset adds 60 s averages of NAT states
        and source/destination IPs.
        """
        body, dataset = await asyncio.gather(
            self._get("/diag/pfinfo"), self._optional(self._monitoring("states"))
        )
        info = (body or {}).get("pfinfo") or {}
        try:
            table = parse_pf_states(
                _b64_text(info.get("info")), _b64_text(info.get("memory"))
            )
        except ValueError as err:
            raise PfSenseAPIError(0, "", f"unexpected pfinfo: {err}") from err
        dataset = dataset or {}
        table["nat_states"] = dataset.get("pfnat")
        table["source_ips"] = dataset.get("srcip")
        table["destination_ips"] = dataset.get("dstip")
        return table

    async def get_notices(self) -> dict:
        """Pending pfSense notices: ``{"count", "latest": [...]}`` (newest 3).

        Read through the shell with pfSense's PHP ``notices.inc``. Without
        shell access, or once PHP is gone, this reports unsupported instead
        of a privilege or API error.
        """
        try:
            return parse_notices(await self.exec_command(NOTICES_COMMAND))
        except (PfSensePrivilegeError, PfSenseNotFoundError) as err:
            raise PfSenseUnsupportedError(f"notices need shell access: {err}") from err
        except ValueError as err:
            raise PfSenseUnsupportedError(f"notices unavailable: {err}") from err

    async def get_dns_servers(self) -> list[str]:
        """System DNS servers from ``/system/setup``."""
        return netgate_map.dns_servers(await self._get_shared("/system/setup"))

    async def get_services(self) -> list[dict]:
        """Services and whether each is running."""
        return netgate_map.services(await self._get_shared("/services/status"))

    async def get_dhcp_leases(self, dns_lookups=None) -> list[dict]:
        """IPv4 DHCP leases."""
        return netgate_map.dhcp_leases(await self._get("/services/dhcp/leases"))

    async def get_arp_table(self, resolve_hostnames: bool = False) -> list[dict]:
        """The ARP table."""
        return netgate_map.arp_table(await self._get("/diag/arp"))

    async def get_gateways_detail(self) -> dict:
        """Gateway configuration keyed by name."""
        return netgate_map.gateways_detail(await self._get_shared("/system/gateways"))

    async def get_filter_rules(self) -> list[dict]:
        """User filter rules across every interface, group and floating.

        Nexus lists rules per interface. The rules listing leaves out disabled
        interfaces (whose rules pfrest still returns), so the interface
        identities come from interface status too, plus the groups from the
        listing and ``floating``. One GET each, run concurrently; an
        interface that errors is skipped rather than failing every rule.
        """
        listing, status = await asyncio.gather(
            self._get("/firewall/rules/interface"),
            self._get_shared("/system/interfaces/status"),
        )
        interfaces = (status or {}).get("interfaces") or []
        mappings = ((listing or {}).get("interface_mappings") or {}).values()
        idents = [
            *(
                str(i["identity"])
                for i in interfaces
                if isinstance(i, dict) and i.get("identity")
            ),
            *(
                str(m["ident"])
                for m in mappings
                if isinstance(m, dict) and m.get("ident")
            ),
            "floating",
        ]
        idents = list(dict.fromkeys(idents))

        results = await asyncio.gather(
            *(
                self._get(f"/firewall/rules/interface/{quote(i, safe='')}")
                for i in idents
            ),
            return_exceptions=True,
        )
        bodies: dict[str, Any] = {}
        for ident, result in zip(idents, results, strict=True):
            if isinstance(result, (PfSenseAPIError, PfSenseNotFoundError)):
                _LOGGER.debug("Netgate API: no rules for %s: %s", ident, result)
            elif isinstance(result, BaseException):
                raise result
            else:
                bodies[ident] = result
        if not bodies:
            raise PfSenseAPIError(0, "", "no interface returned firewall rules")
        return netgate_map.filter_rules(bodies)

    async def get_nat_port_forward_rules(self) -> list[dict]:
        """NAT port-forward rules."""
        return netgate_map.nat_port_forwards(
            await self._get("/firewall/nat/port-forward")
        )

    async def get_nat_outbound_rules(self) -> list[dict]:
        """Manual NAT outbound rules."""
        return netgate_map.nat_outbound(await self._get("/firewall/nat/outbound"))

    async def get_carp_status(self) -> bool:
        """True when CARP is enabled and not in maintenance mode."""
        return netgate_map.carp_enabled(await self._get_shared("/services/carp/status"))

    async def get_carp_interfaces(self) -> list[dict]:
        """CARP virtual IPs with their current status."""
        vips, status = await asyncio.gather(
            self._get("/firewall/virtualip"),
            self._get_shared("/services/carp/status"),
        )
        return netgate_map.carp_interfaces(vips, status)

    # ------------------------------------------------------------- writes
    #
    # Each write takes ``_write_lock``, so a change and its apply are never
    # interleaved with another write. Changes are staged by pfSense ("dirty
    # subsystems") until ``POST /system/config/dirty {"apply": true}``.

    # FwRuleToggle ``value``: ``true`` disables, ``false`` enables (verified
    # on 26.07 for a filter rule). The toggle applies the filter itself, so
    # nothing is left dirty; ``_apply_pending`` is kept as a harmless no-op
    # in case another subsystem needs it.
    _TOGGLE_VALUE_DISABLES = True

    async def _apply_pending(self) -> None:
        """Apply every pending (dirty) subsystem change."""
        await self._request("POST", "/system/config/dirty", payload={"apply": True})

    async def _toggle(self, path: str, rule: dict | None, disabled: bool) -> None:
        if rule is None:
            raise PfSenseNotFoundError("rule not found")
        if bool(rule.get("disabled")) == disabled:
            return
        value = disabled if self._TOGGLE_VALUE_DISABLES else not disabled
        async with self._write_lock:
            await self._request("POST", path, payload={"value": value})
            await self._apply_pending()

    async def _filter_rule(self, tracker) -> dict | None:
        return next(
            (
                r
                for r in await self.get_filter_rules()
                if str(r.get("tracker")) == str(tracker)
            ),
            None,
        )

    async def _set_filter_rule(self, tracker, disabled: bool) -> None:
        rule = await self._filter_rule(tracker)
        path = None
        if rule is not None:
            iface = quote(str(rule["interface"]), safe="")
            path = f"/firewall/rules/interface/{iface}/toggle/{quote(str(rule['id']), safe='')}"
        await self._toggle(path or "", rule, disabled)

    async def enable_filter_rule_by_tracker(self, tracker) -> None:
        """Enable the filter rule with this tracker."""
        await self._set_filter_rule(tracker, False)

    async def disable_filter_rule_by_tracker(self, tracker) -> None:
        """Disable the filter rule with this tracker."""
        await self._set_filter_rule(tracker, True)

    async def _set_nat_rule(self, kind: str, created_time, disabled: bool) -> None:
        rules = (
            await self.get_nat_port_forward_rules()
            if kind == "port-forward"
            else await self.get_nat_outbound_rules()
        )
        rule = next(
            (r for r in rules if str(r.get("created_time")) == str(created_time)), None
        )
        path = (
            f"/firewall/nat/{kind}/toggle/{quote(str(rule['id']), safe='')}"
            if rule is not None
            else ""
        )
        await self._toggle(path, rule, disabled)

    async def enable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        """Enable the port-forward rule created at ``created_time``."""
        await self._set_nat_rule("port-forward", created_time, False)

    async def disable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        """Disable the port-forward rule created at ``created_time``."""
        await self._set_nat_rule("port-forward", created_time, True)

    async def enable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        """Enable the outbound NAT rule created at ``created_time``."""
        await self._set_nat_rule("outbound", created_time, False)

    async def disable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        """Disable the outbound NAT rule created at ``created_time``."""
        await self._set_nat_rule("outbound", created_time, True)

    # ------------------------------------------------------------- aliases

    async def _aliases(self) -> list[dict]:
        body = await self._get("/aliases") or {}
        return [a for a in body.get("aliases") or [] if isinstance(a, dict)]

    async def update_alias_address(
        self,
        alias_name: str,
        address: str,
        action: str = "add",
        kill_states: bool = True,
    ) -> None:
        """Add or remove an address in a host/network alias, then apply.

        Nexus stores alias entries as ``targets`` (``{name: <address>,
        descr: <detail>}``); the ``address`` / ``detail`` strings are left
        empty and are ignored on write (verified on 26.07). A missing alias is
        created as a host alias on ``add``.
        """
        aliases = await self._aliases()
        target = next((a for a in aliases if a.get("name") == alias_name), None)
        entry = {"name": address, "descr": "Added via HASS"}
        if target is None:
            if action != "add":
                return
            payload = {
                "name": alias_name,
                "type": "host",
                "descr": "Managed automatically by Home Assistant",
                "targets": [entry],
            }
            async with self._write_lock:
                await self._request("PUT", "/aliases", payload=payload)
                await self._apply_pending()
        else:
            targets = [t for t in target.get("targets") or [] if isinstance(t, dict)]
            present = any(t.get("name") == address for t in targets)
            if action == "add" and not present:
                targets.append(entry)
            elif action == "remove" and present:
                targets = [t for t in targets if t.get("name") != address]
            else:
                return
            payload = {
                key: target[key]
                for key in ("name", "type", "descr", "tags", "updatefreq")
                if key in target
            }
            payload["targets"] = targets
            alias_id = quote(str(target.get("id")), safe="")
            async with self._write_lock:
                await self._request("POST", f"/aliases/{alias_id}", payload=payload)
                await self._apply_pending()
        if kill_states:
            await self.kill_states(address)

    # --------------------------------------------------------------- states

    async def reset_state_table(self) -> None:
        """Flush the whole state table (``pfctl -F states``)."""
        await self.exec_command("/sbin/pfctl -F states")

    async def kill_states(self, source: str, destination: str | None = None) -> None:
        """Kill states from ``source`` (optionally only to ``destination``).

        ``DELETE /diag/states`` needs ``srcip`` and ``dstip`` together, and
        its ``filter_str`` is a substring match (``10.0.0.1`` would also hit
        ``10.0.0.10``). So list the states mentioning ``source``, keep the
        exact matches, and delete each src/dst pair. A state is matched with
        ``source`` on either side, like ``pfctl -k``-based pfrest killing.
        """
        body = await self._request("GET", "/diag/states", params={"filter_str": source})
        pairs: set[tuple[str, str]] = set()
        for state in (body or {}).get("states") or []:
            if not isinstance(state, dict):
                continue
            src, dst = str(state.get("src") or ""), str(state.get("dst") or "")
            if source not in (src, dst) or not src or not dst:
                continue
            if destination and destination not in (src, dst):
                continue
            pairs.add((src, dst))
        for src, dst in sorted(pairs):
            with contextlib.suppress(PfSenseNotFoundError):
                await self._request(
                    "DELETE", "/diag/states", params={"srcip": src, "dstip": dst}
                )

    async def kill_states_for_rule(self, rule: dict) -> None:
        """Kill states of the single hosts a rule matches on (best effort).

        Host addresses and the host entries of aliases are used; networks,
        interface macros (``lan``, ``wanip``), ``any`` and negations are
        skipped, since state deletion works per IP.
        """
        hosts: set[str] = set()
        aliases: list[dict] | None = None
        for side in ("source", "destination"):
            spec = rule.get(side)
            if not isinstance(spec, dict) or spec.get("not") or spec.get("any"):
                continue
            value = str(spec.get("address") or "").strip()
            if not value:
                continue
            net = _as_network(value)
            if net is None:
                if aliases is None:
                    aliases = [
                        {
                            **a,
                            "address": [
                                str(t.get("name") or "")
                                for t in a.get("targets") or []
                                if isinstance(t, dict)
                            ],
                        }
                        for a in await self._aliases()
                    ]
                nets = _expand_alias_networks(aliases, value)
            else:
                nets = [net]
            hosts.update(str(n.network_address) for n in nets if n.num_addresses == 1)
        for ip in sorted(hosts):
            await self.kill_states(ip)

    async def delete_arp_entry(self, ip: str) -> None:
        """Delete one ARP entry (missing entries are ignored)."""
        if not ip:
            return
        with contextlib.suppress(PfSenseNotFoundError):
            await self._request("DELETE", f"/diag/arp/{quote(ip, safe='')}")

    # ------------------------------------------------------------- gateways

    async def set_default_gateway(self, gateway: str, ip_version: str = "4") -> None:
        """Make ``gateway`` the default IPv4/IPv6 gateway, then apply.

        Nexus sets defaults through a gateway update carrying ``defaults``.
        LIVE-CHECK: the gateway id is assumed to be its list index.
        """
        body = await self._get("/system/gateways") or {}
        gateways = [g for g in body.get("gateways") or [] if isinstance(g, dict)]
        index = next(
            (i for i, g in enumerate(gateways) if g.get("name") == gateway), None
        )
        if index is None:
            raise PfSenseNotFoundError(f"gateway {gateway!r} not found")
        key = "defaultgw6" if "6" in str(ip_version) else "defaultgw4"
        defaults = dict(body.get("defaults") or {})
        if defaults.get(key) == gateway:
            return
        defaults[key] = gateway
        payload = {**gateways[index], "defaults": defaults}
        async with self._write_lock:
            await self._request("PUT", f"/system/gateways/{index}", payload=payload)
            await self._apply_pending()

    # ------------------------------------------------------ system control

    async def system_reboot(self, type: str = "normal") -> None:
        """Reboot the firewall (``fsck`` reboots with a filesystem check)."""
        action = "rebootfsck" if type == "fsck" else "reboot"
        # The connection drops as the box goes down; that is success.
        with contextlib.suppress(PfSenseConnectionError):
            await self._request("POST", "/diag/control", payload={"action": action})

    async def system_halt(self) -> None:
        """Halt (power off) the firewall."""
        with contextlib.suppress(PfSenseConnectionError):
            await self._request("POST", "/diag/control", payload={"action": "halt"})

    # ------------------------------------------------------ shell-backed
    #
    # Nexus has no endpoint for generic service control or Wake-on-LAN, so
    # these run pfSense's own tools through ``POST /diag/cmd/shell`` (which
    # needs the shell privilege). ``pfSsh.php`` is PHP, so service control
    # here shares pfrest's PHP dependency until Netgate adds an endpoint.

    async def exec_command(self, command: str, background: bool = False) -> str:
        """Run a shell command and return its output."""
        if background:
            command = f"nohup {command} >/dev/null 2>&1 &"
        body = await self._request(
            "POST",
            "/diag/cmd/shell",
            payload={"cmd": _b64(command), "timeout": 60},
        )
        raw = str(body.get("response") or "") if isinstance(body, dict) else ""
        # The response is base64 (verified on 26.07); fall back to raw text.
        try:
            return base64.b64decode(raw, validate=True).decode(errors="replace")
        except (binascii.Error, ValueError):
            return raw

    async def _service_command(
        self, service_name: str, service: dict | None, action: str
    ) -> None:
        args = ["svc", action, service_name]
        # LIVE-CHECK: OpenVPN instances take ``<mode> <vpnid>``.
        if (
            service_name == "openvpn"
            and isinstance(service, dict)
            and service.get("vpnid")
        ):
            args += [str(service.get("mode") or "server"), str(service["vpnid"])]
        await self.exec_command(
            "/usr/local/sbin/pfSsh.php playback " + " ".join(_shq(a) for a in args)
        )

    async def start_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Start a service."""
        await self._service_command(service_name, service, "start")

    async def stop_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Stop a service."""
        await self._service_command(service_name, service, "stop")

    async def restart_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Restart a service."""
        await self._service_command(service_name, service, "restart")

    async def restart_service_if_running(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Restart a service only if it is running."""
        svc = next(
            (s for s in await self.get_services() if s.get("name") == service_name),
            None,
        )
        if svc and svc.get("status"):
            await self._service_command(service_name, service or svc, "restart")

    async def send_wol(self, interface: str, mac: str) -> None:
        """Send a Wake-on-LAN packet to the interface's broadcast address."""
        body = await self._get_shared("/system/interfaces/status") or {}
        iface = next(
            (
                i
                for i in body.get("interfaces") or []
                if isinstance(i, dict)
                and interface in (i.get("identity"), i.get("assigned_name"))
            ),
            None,
        )
        if iface is None or not iface.get("ip_address") or not iface.get("subnet_mask"):
            raise PfSenseNotFoundError(f"no IPv4 address on interface {interface!r}")
        network = ipaddress.ip_network(
            f"{iface['ip_address']}/{iface['subnet_mask']}", strict=False
        )
        await self.exec_command(
            f"/usr/local/bin/wol -i {_shq(str(network.broadcast_address))} {_shq(mac)}"
        )
