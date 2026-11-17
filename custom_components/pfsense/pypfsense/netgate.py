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
import json
import logging
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from .errors import (
    PfSenseAPIError,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
    PfSenseUnsupportedError,
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


class _SessionInvalid(PfSenseAuthError):
    """The access token was rejected; a refresh or re-login may fix it."""


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


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

    # ----------------------------------------- not wired up yet (phase 2+)
    #
    # Each raises PfSenseUnsupportedError so the poll records the capability
    # as "unsupported" instead of failing. Phases 2-5 of the migration plan
    # (issue #11) replace these with real implementations.

    @staticmethod
    def _not_yet(name: str) -> PfSenseUnsupportedError:
        return PfSenseUnsupportedError(
            f"{name} is not implemented for the Netgate API backend yet"
        )

    async def get_firmware_update_info(self) -> dict | None:
        """Not implemented yet."""
        raise self._not_yet("get_firmware_update_info")

    async def get_dns_servers(self) -> list[str]:
        """Not implemented yet."""
        raise self._not_yet("get_dns_servers")

    async def get_telemetry(self) -> dict:
        """Not implemented yet."""
        raise self._not_yet("get_telemetry")

    async def get_services(self) -> list[dict]:
        """Not implemented yet."""
        raise self._not_yet("get_services")

    async def start_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Not implemented yet."""
        raise self._not_yet("start_service")

    async def stop_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Not implemented yet."""
        raise self._not_yet("stop_service")

    async def restart_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Not implemented yet."""
        raise self._not_yet("restart_service")

    async def restart_service_if_running(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Not implemented yet."""
        raise self._not_yet("restart_service_if_running")

    async def get_dhcp_leases(self, dns_lookups=None) -> list[dict]:
        """Not implemented yet."""
        raise self._not_yet("get_dhcp_leases")

    async def get_arp_table(self, resolve_hostnames: bool = False) -> list[dict]:
        """Not implemented yet."""
        raise self._not_yet("get_arp_table")

    async def delete_arp_entry(self, ip: str) -> None:
        """Not implemented yet."""
        raise self._not_yet("delete_arp_entry")

    async def get_gateways_detail(self) -> dict:
        """Not implemented yet."""
        raise self._not_yet("get_gateways_detail")

    async def set_default_gateway(self, gateway: str, ip_version: str = "4") -> None:
        """Not implemented yet."""
        raise self._not_yet("set_default_gateway")

    async def get_filter_rules(self) -> list[dict]:
        """Not implemented yet."""
        raise self._not_yet("get_filter_rules")

    async def get_nat_port_forward_rules(self) -> list[dict]:
        """Not implemented yet."""
        raise self._not_yet("get_nat_port_forward_rules")

    async def get_nat_outbound_rules(self) -> list[dict]:
        """Not implemented yet."""
        raise self._not_yet("get_nat_outbound_rules")

    async def enable_filter_rule_by_tracker(self, tracker) -> None:
        """Not implemented yet."""
        raise self._not_yet("enable_filter_rule_by_tracker")

    async def disable_filter_rule_by_tracker(self, tracker) -> None:
        """Not implemented yet."""
        raise self._not_yet("disable_filter_rule_by_tracker")

    async def enable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        """Not implemented yet."""
        raise self._not_yet("enable_nat_port_forward_rule_by_created_time")

    async def disable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        """Not implemented yet."""
        raise self._not_yet("disable_nat_port_forward_rule_by_created_time")

    async def enable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        """Not implemented yet."""
        raise self._not_yet("enable_nat_outbound_rule_by_created_time")

    async def disable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        """Not implemented yet."""
        raise self._not_yet("disable_nat_outbound_rule_by_created_time")

    async def update_alias_address(
        self,
        alias_name: str,
        address: str,
        action: str = "add",
        kill_states: bool = True,
    ) -> None:
        """Not implemented yet."""
        raise self._not_yet("update_alias_address")

    async def get_carp_status(self) -> bool:
        """Not implemented yet."""
        raise self._not_yet("get_carp_status")

    async def get_carp_interfaces(self) -> list[dict]:
        """Not implemented yet."""
        raise self._not_yet("get_carp_interfaces")

    async def reset_state_table(self) -> None:
        """Not implemented yet."""
        raise self._not_yet("reset_state_table")

    async def kill_states(self, source: str, destination: str | None = None) -> None:
        """Not implemented yet."""
        raise self._not_yet("kill_states")

    async def kill_states_for_rule(self, rule: dict) -> None:
        """Not implemented yet."""
        raise self._not_yet("kill_states_for_rule")

    async def system_reboot(self, type: str = "normal") -> None:
        """Not implemented yet."""
        raise self._not_yet("system_reboot")

    async def system_halt(self) -> None:
        """Not implemented yet."""
        raise self._not_yet("system_halt")

    async def send_wol(self, interface: str, mac: str) -> None:
        """Not implemented yet."""
        raise self._not_yet("send_wol")

    async def exec_command(self, command: str, background: bool = False) -> Any:
        """Not implemented yet."""
        raise self._not_yet("exec_command")
