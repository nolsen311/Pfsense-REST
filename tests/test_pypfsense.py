"""Unit tests for the async pfSense REST API v2 client."""

import re

import aiohttp
from aioresponses import aioresponses
import pytest

from custom_components.pfsense.pypfsense import (
    Client,
    PfSenseAPIError,
    PfSenseAuthError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
    _build_telemetry,
    dict_get,
)

BASE = "https://pf.example:8444"
API = f"{BASE}/api/v2"


def _envelope(data, code=200, status="ok", response_id="SUCCESS", message=""):
    return {
        "code": code,
        "status": status,
        "response_id": response_id,
        "message": message,
        "data": data,
    }


@pytest.fixture
async def client():
    async with aiohttp.ClientSession() as session:
        yield Client(BASE, "test-key", session, {"verify_ssl": False})


def test_dict_get():
    data = {"a": {"b": [{"c": 1}]}, "n": {2: "x"}}
    assert dict_get(data, "a.b.0.c") == 1
    assert dict_get(data, "n.2") == "x"
    assert dict_get(data, "a.missing", "d") == "d"
    assert dict_get(data, "a.b.9.c") is None


def test_base_url_strips_path():
    c = Client("https://pf.example:8444/ui/", "k", object())
    assert c._base == "https://pf.example:8444/api/v2"


async def test_request_unwraps_data(client):
    with aioresponses() as m:
        m.get(
            f"{API}/system/hostname",
            payload=_envelope({"hostname": "pf", "domain": "lan"}),
        )
        assert await client._get("/system/hostname") == {
            "hostname": "pf",
            "domain": "lan",
        }


@pytest.mark.parametrize(
    "code,exc",
    [
        (401, PfSenseAuthError),
        (403, PfSensePrivilegeError),
        (404, PfSenseNotFoundError),
        (500, PfSenseAPIError),
    ],
)
async def test_error_codes_map_to_exceptions(client, code, exc):
    with aioresponses() as m:
        m.get(
            f"{API}/system/hostname",
            status=code,
            payload=_envelope(
                [], code=code, status="err", response_id="X", message="nope"
            ),
        )
        with pytest.raises(exc):
            await client._get("/system/hostname")


async def test_get_system_info_merges_endpoints(client):
    with aioresponses() as m:
        m.get(
            f"{API}/status/system",
            payload=_envelope(
                {"platform": "Netgate 6100", "serial": "123", "netgate_id": "abc"}
            ),
        )
        m.get(
            f"{API}/system/hostname",
            payload=_envelope({"hostname": "pf", "domain": "lan"}),
        )
        info = await client.get_system_info()
    assert info == {
        "hostname": "pf",
        "domain": "lan",
        "serial": "123",
        "netgate_device_id": "abc",
        "platform": "Netgate 6100",
    }


async def test_carp_status_reduces_to_bool(client):
    with aioresponses() as m:
        m.get(
            f"{API}/status/carp",
            payload=_envelope({"enable": True, "maintenance_mode": False}),
        )
        assert await client.get_carp_status() is True
    with aioresponses() as m:
        m.get(
            f"{API}/status/carp",
            payload=_envelope({"enable": True, "maintenance_mode": True}),
        )
        assert await client.get_carp_status() is False


def _patch_body(m):
    return next(
        r
        for (method, url), reqs in m.requests.items()
        for r in reqs
        if method == "PATCH"
    ).kwargs["json"]


async def test_disable_filter_rule_patches_then_applies(client):
    rules = [
        {"id": 4, "tracker": 111, "disabled": False, "descr": "r"},
        {
            "id": 5,
            "tracker": 222,
            "disabled": False,
            "descr": "r2",
            "statetype": "keep state",
        },
    ]
    with aioresponses() as m:
        m.get(f"{API}/firewall/rules", payload=_envelope(rules))
        m.patch(f"{API}/firewall/rule", payload=_envelope({"id": 5, "disabled": True}))
        m.post(f"{API}/firewall/apply", payload=_envelope({"applied": True}))
        await client.disable_filter_rule_by_tracker(222)
        assert _patch_body(m) == {"id": 5, "disabled": True}


async def test_disable_filter_rule_backfills_empty_statetype(client):
    # pfSense's GUI writes ``<statetype></statetype>``; a bare disabled PATCH then
    # fails FIELD_EMPTY_NOT_ALLOWED, so the client re-sends the default.
    rules = [{"id": 5, "tracker": 222, "disabled": False, "statetype": ""}]
    with aioresponses() as m:
        m.get(f"{API}/firewall/rules", payload=_envelope(rules))
        m.patch(f"{API}/firewall/rule", payload=_envelope({"id": 5, "disabled": True}))
        m.post(f"{API}/firewall/apply", payload=_envelope({"applied": True}))
        await client.disable_filter_rule_by_tracker(222)
        assert _patch_body(m) == {
            "id": 5,
            "disabled": True,
            "statetype": "keep state",
        }


async def test_kill_states_for_rule_resolves_alias_to_prefix(client):
    rule = {"source": "kids", "destination": "any"}
    aliases = [{"name": "kids", "type": "network", "address": ["10.0.10.0/24"]}]
    with aioresponses() as m:
        m.get(f"{API}/firewall/aliases", payload=_envelope(aliases))
        m.delete(
            re.compile(rf"{re.escape(API)}/firewall/states.*"),
            payload=_envelope([]),
            repeat=True,
        )
        await client.kill_states_for_rule(rule)
        deletes = [
            str(url)
            for (method, url), reqs in m.requests.items()
            if method == "DELETE"
            for _ in reqs
        ]
    assert any("source__startswith=10.0.10." in u for u in deletes)
    assert any("destination__startswith=10.0.10." in u for u in deletes)


async def test_kill_states_for_rule_skips_unresolvable_endpoints(client):
    # ``any`` / ``(self)`` / a /25 network have no usable prefix -> no request.
    rule = {"source": "any", "destination": "(self)"}
    with aioresponses() as m:
        await client.kill_states_for_rule(rule)
        assert m.requests == {}


async def test_build_telemetry_shape():
    system = {
        "cpu_usage": 12.5,
        "cpu_count": 4,
        "mem_usage": 20,
        "swap_usage": None,
        "cpu_load_avg": [0.1, 0.2, 0.3],
        "temp_c": 50,
        "uptime": "1 Day",
    }
    interfaces = [
        {"name": "wan", "descr": "WAN", "ipaddr": "1.2.3.4", "inbytes": 10},
        {"name": "lan", "descr": "LAN", "inbytes": 5},
    ]
    gateways = [{"name": "WAN_DHCP", "delay": 1.2, "status": "online"}]
    ovpn = [{"vpnid": 1, "name": "S", "conns": [{"bytes_recv": 100, "bytes_sent": 50}]}]
    t = _build_telemetry(system, interfaces, gateways, ovpn)
    assert t["wan_ip"] == "1.2.3.4"
    assert t["cpu"]["used_percent"] == 12.5
    assert t["system"]["load_average"]["five_minute"] == 0.2
    assert t["interfaces"]["lan"]["ifname"] == "lan"
    assert t["gateways"]["WAN_DHCP"]["status"] == "online"
    assert t["openvpn"]["servers"]["1"]["connected_client_count"] == 1
    assert t["openvpn"]["servers"]["1"]["total_bytes_recv"] == 100
