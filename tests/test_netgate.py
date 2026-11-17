"""Unit tests for the Netgate official API (Nexus) client."""

import asyncio
import base64
import json
import time

import aiohttp
from aioresponses import aioresponses
import pytest

from custom_components.pfsense.pypfsense import (
    NetgateClient,
    PfSenseAPIError,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
    PfSenseUnsupportedError,
)
from custom_components.pfsense.pypfsense.netgate import (
    REFRESH_COOKIE,
    REFRESH_MARGIN,
    _token_expiry,
)

BASE = "https://pf.example:8443"
API = f"{BASE}/api"
LOGIN = f"{API}/login"
REFRESH = f"{API}/login/refresh"
STATUS = f"{API}/system/status"
SETUP = f"{API}/system/setup"

# Shapes as returned by 26.07-RELEASE (values made up).
STATUS_BODY = {
    "status": {
        "host": "router.example.lan",
        "ndi": "abc123def456",
        "prod": "pfSense",
        "osver": "26.07.1-RELEASE - 20260807-1926",
        "vndr": "Netgate",
        "machine": "6100",
    },
    "timestamp": 1794943508389,
}
SETUP_BODY = {"hostname": "router", "domain": "example.lan", "timezone": "UTC"}


def _jwt(exp: float | None, tag: str = "a") -> str:
    def part(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    claims = {"username": "ha", "tag": tag}
    if exp is not None:
        claims["exp"] = int(exp)
    return f"{part({'alg': 'HS256'})}.{part(claims)}.sig"


def _login_ok(m, token: str, cookie: str = "refresh-1", repeat: bool = False):
    m.post(
        LOGIN,
        payload={"token": token, "user": "ha", "version": "1.0", "alerts": []},
        headers={
            "Set-Cookie": f"{REFRESH_COOKIE}={cookie}; Path=/api/login/refresh; "
            "Secure; HttpOnly"
        },
        repeat=repeat,
    )


def _calls(m, method: str, url: str) -> list:
    return [
        call
        for (verb, req_url), calls in m.requests.items()
        if verb == method and str(req_url).split("?")[0] == url
        for call in calls
    ]


def _err(msg: str, code: int = 400) -> dict:
    return {"errcode": code, "errlevel": None, "errmsg": msg}


@pytest.fixture
async def session():
    """A real aiohttp session (requests are intercepted by aioresponses)."""
    async with aiohttp.ClientSession() as s:
        yield s


def _client(session) -> NetgateClient:
    return NetgateClient(
        BASE + "/ignored/path", session, username="ha", password="s3cret"
    )


def test_requires_credentials(session) -> None:
    """A client without credentials is an auth error, not a crash later."""
    with pytest.raises(PfSenseAuthError):
        NetgateClient(BASE, session, username="", password="x")


def test_token_expiry_parsing() -> None:
    """``exp`` is read from the JWT payload; junk tokens give None."""
    assert _token_expiry(_jwt(1_800_000_000)) == 1_800_000_000
    assert _token_expiry(_jwt(None)) is None
    assert _token_expiry("not-a-jwt") is None
    assert _token_expiry("a.!!!.c") is None


async def test_login_then_identity(session) -> None:
    """One login (base64 creds), Bearer on reads, /system/status fetched once."""
    token = _jwt(time.time() + 300)
    client = _client(session)
    with aioresponses() as m:
        _login_ok(m, token)
        m.get(STATUS, payload=STATUS_BODY)
        m.get(SETUP, payload=SETUP_BODY)

        info = await client.get_system_info()
        firmware = await client.get_host_firmware_version()

        login = _calls(m, "POST", LOGIN)
        assert len(login) == 1
        assert login[0].kwargs["json"] == {
            "username": base64.b64encode(b"ha").decode(),
            "password": base64.b64encode(b"s3cret").decode(),
        }
        status_calls = _calls(m, "GET", STATUS)
        assert len(status_calls) == 1  # shared between the two methods
        assert status_calls[0].kwargs["headers"]["Authorization"] == f"Bearer {token}"

    assert info == {
        "hostname": "router",
        "domain": "example.lan",
        "serial": None,
        "netgate_device_id": "abc123def456",
        "platform": "Netgate 6100",
    }
    assert firmware == {
        "platform": "Netgate 6100",
        "firmware": {"version": "26.07.1-RELEASE"},
        "base": "26.07",
        "patch": "1",
        "buildtime": "20260807-1926",
    }


async def test_hostname_falls_back_to_status_host(session) -> None:
    """Without /system/setup data, ``host`` (the FQDN) is split."""
    client = _client(session)
    with aioresponses() as m:
        _login_ok(m, _jwt(time.time() + 300))
        m.get(STATUS, payload=STATUS_BODY)
        m.get(SETUP, payload={})
        info = await client.get_system_info()
    assert (info["hostname"], info["domain"]) == ("router", "example.lan")


async def test_refresh_before_expiry(session) -> None:
    """A token near expiry is refreshed with Bearer + cookie, without a login."""
    old = _jwt(time.time() + REFRESH_MARGIN - 5, "old")
    new = _jwt(time.time() + 300, "new")
    client = _client(session)
    with aioresponses() as m:
        _login_ok(m, old, cookie="refresh-1")
        m.post(REFRESH, payload={"token": new, "user": "ha", "version": "1.0"})
        m.get(STATUS, payload=STATUS_BODY, repeat=True)

        await client._get("/system/status")  # logs in (token already near expiry)
        await client._get("/system/status")  # refreshes

        refresh = _calls(m, "POST", REFRESH)
        assert len(refresh) == 1
        headers = refresh[0].kwargs["headers"]
        assert headers["Authorization"] == f"Bearer {old}"
        assert headers["Cookie"] == f"{REFRESH_COOKIE}=refresh-1"
        assert refresh[0].kwargs["json"] == {"username": "ha"}
        assert len(_calls(m, "POST", LOGIN)) == 1
        last = _calls(m, "GET", STATUS)[-1]
        assert last.kwargs["headers"]["Authorization"] == f"Bearer {new}"


async def test_failed_refresh_logs_in_again(session) -> None:
    """When the refresh cookie has expired, the client logs in afresh."""
    old = _jwt(time.time() + 10, "old")
    new = _jwt(time.time() + 300, "new")
    client = _client(session)
    with aioresponses() as m:
        _login_ok(m, old)
        m.post(REFRESH, status=400, payload=_err("refresh token expired"))
        _login_ok(m, new)
        m.get(STATUS, payload=STATUS_BODY, repeat=True)

        await client._get("/system/status")
        await client._get("/system/status")

        assert len(_calls(m, "POST", LOGIN)) == 2
        last = _calls(m, "GET", STATUS)[-1]
        assert last.kwargs["headers"]["Authorization"] == f"Bearer {new}"


async def test_rejected_session_is_retried_once(session) -> None:
    """HTTP 400 "session invalid" renews the token and retries the request."""
    first = _jwt(time.time() + 300, "first")
    second = _jwt(time.time() + 300, "second")
    client = _client(session)
    with aioresponses() as m:
        _login_ok(m, first)
        m.get(
            STATUS,
            status=400,
            payload=_err("session invalid, reauthenticate (token is expired)"),
        )
        m.post(REFRESH, payload={"token": second})
        m.get(STATUS, payload=STATUS_BODY)

        body = await client._get("/system/status")

    assert body == STATUS_BODY


async def test_session_rejected_twice_is_auth_error(session) -> None:
    """If even a fresh token is rejected, surface an auth error."""
    client = _client(session)
    with aioresponses() as m:
        _login_ok(m, _jwt(time.time() + 300), repeat=True)
        m.post(REFRESH, status=400, payload=_err("nope"), repeat=True)
        m.get(
            STATUS,
            status=400,
            payload=_err("session invalid, reauthenticate (bad)"),
            repeat=True,
        )
        with pytest.raises(PfSenseAuthError):
            await client._get("/system/status")


async def test_invalid_credentials_are_latched(session) -> None:
    """A rejected login is not retried: repeated failures trigger lockout."""
    client = _client(session)
    with aioresponses() as m:
        m.post(LOGIN, status=400, payload=_err("invalid credentials"), repeat=True)

        with pytest.raises(PfSenseAuthError):
            await client.get_system_info()
        with pytest.raises(PfSenseAuthError):
            await client.get_host_firmware_version()

        assert len(_calls(m, "POST", LOGIN)) == 1


async def test_concurrent_reads_share_one_login(session) -> None:
    """The poll's concurrent reads wait for one login instead of each logging in."""
    client = _client(session)
    with aioresponses() as m:
        m.post(LOGIN, status=400, payload=_err("invalid credentials"), repeat=True)
        results = await asyncio.gather(
            *(client._get("/system/status") for _ in range(8)),
            return_exceptions=True,
        )
        assert all(isinstance(r, PfSenseAuthError) for r in results)
        assert len(_calls(m, "POST", LOGIN)) == 1


async def test_unauthorized_login_is_privilege_error(session) -> None:
    """A user without API group membership is a privilege problem."""
    client = _client(session)
    with aioresponses() as m:
        m.post(LOGIN, status=400, payload=_err("unauthorized login"))
        with pytest.raises(PfSensePrivilegeError):
            await client._get("/system/status")


@pytest.mark.parametrize(
    ("status", "body", "error"),
    [
        (404, None, PfSenseNotFoundError),
        (403, _err("forbidden", 403), PfSensePrivilegeError),
        (500, _err("internal error", 500), PfSenseAPIError),
        (400, _err("bad request body"), PfSenseAPIError),
    ],
)
async def test_error_mapping(session, status, body, error) -> None:
    """Errors are typed from errmsg first, then the HTTP status."""
    client = _client(session)
    with aioresponses() as m:
        _login_ok(m, _jwt(time.time() + 300))
        if body is None:
            m.get(STATUS, status=status, body="<html>not found</html>")
        else:
            m.get(STATUS, status=status, payload=body)
        with pytest.raises(error):
            await client._get("/system/status")


async def test_wrong_port_login_404_is_not_found(session) -> None:
    """Pointing at a port without the API (e.g. the web GUI) is a 404 on login."""
    client = _client(session)
    with aioresponses() as m:
        m.post(LOGIN, status=404, body="<html></html>")
        with pytest.raises(PfSenseNotFoundError):
            await client.get_system_info()


async def test_connection_error(session) -> None:
    """Network failures become PfSenseConnectionError."""
    client = _client(session)
    with aioresponses() as m:
        m.post(LOGIN, exception=aiohttp.ClientConnectionError("refused"))
        with pytest.raises(PfSenseConnectionError):
            await client.get_system_info()
    # A connection failure is not latched: the next poll may succeed.
    with aioresponses() as m:
        _login_ok(m, _jwt(time.time() + 300))
        m.get(STATUS, payload=STATUS_BODY)
        m.get(SETUP, payload=SETUP_BODY)
        assert (await client.get_system_info())["netgate_device_id"] == "abc123def456"


async def test_failed_shared_read_is_not_cached(session) -> None:
    """A failed shared GET is retried by the next caller, not replayed."""
    client = _client(session)
    with aioresponses() as m:
        _login_ok(m, _jwt(time.time() + 300))
        m.get(STATUS, status=500, payload=_err("boom", 500))
        m.get(STATUS, payload=STATUS_BODY)
        with pytest.raises(PfSenseAPIError):
            await client._status()
        assert (await client._status())["ndi"] == "abc123def456"


async def test_unimplemented_reads_are_unsupported(session) -> None:
    """Capabilities not wired up yet raise the 'unsupported' error, no I/O."""
    client = _client(session)
    with aioresponses() as m:
        with pytest.raises(PfSenseUnsupportedError):
            await client.get_telemetry()
        assert not m.requests


async def test_platform_falls_back_to_product(session) -> None:
    """Without vendor/model (e.g. a VM), the platform is the product name."""
    client = _client(session)
    body = {"status": {"ndi": "x", "prod": "pfSense", "osver": "26.07-RELEASE"}}
    with aioresponses() as m:
        _login_ok(m, _jwt(time.time() + 300))
        m.get(STATUS, payload=body)
        firmware = await client.get_host_firmware_version()
    assert firmware["platform"] == "pfSense"
    assert (firmware["base"], firmware["patch"]) == ("26.07", "0")
    assert firmware["buildtime"] is None
