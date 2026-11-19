"""Tests for the diagnostics parsers, client calls and response actions."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.pfsense.const import DOMAIN, PFSENSE_CLIENT
from custom_components.pfsense.pypfsense import (
    NetgateClient,
    PfSenseAPIError,
    PfSenseUnsupportedError,
    diag,
)
from custom_components.pfsense.services import ServiceRegistrar
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError

PING_OK = (
    "PING 1.1.1.1 (1.1.1.1): 56 data bytes\n"
    "64 bytes from 1.1.1.1: icmp_seq=0 ttl=56 time=13.201 ms\n"
    "64 bytes from 1.1.1.1: icmp_seq=1 ttl=56 time=14.398 ms\n"
    "64 bytes from 1.1.1.1: icmp_seq=2 ttl=56 time=14.037 ms\n\n"
    "--- 1.1.1.1 ping statistics ---\n"
    "3 packets transmitted, 3 packets received, 0.0% packet loss\n"
    "round-trip min/avg/max/stddev = 13.201/13.879/14.398/0.501 ms\n"
)
PING_LOST = (
    "PING 192.0.2.1 (192.0.2.1): 56 data bytes\n\n"
    "--- 192.0.2.1 ping statistics ---\n"
    "2 packets transmitted, 0 packets received, 100.0% packet loss\n"
)
TRACE = (
    "traceroute to 1.1.1.1 (1.1.1.1), 6 hops max, 40 byte packets\n"
    " 1  10.0.0.66  9.872 ms\n"
    "    10.0.0.67  10.342 ms\n"
    "    10.0.0.66  9.108 ms\n"
    " 2  198.51.100.1  8.732 ms  8.785 ms\n"
    " 3  * * *\n"
    " 4  1.1.1.1  13.910 ms  12.7 ms  13.0 ms\n"
)
TRACE_SILENT = (
    "traceroute to 1.1.1.1 (1.1.1.1), 2 hops max, 40 byte packets\n"
    " 1  * * *\n 2  * * *\n"
)
DNS = {
    "results": [
        {"type": "A", "data": "199.60.103.104"},
        {"type": "AAAA", "data": "::1"},
    ],
    "timings": [
        {"server": "127.0.0.1", "time": "7 msec"},
        {"server": "x", "time": "?"},
    ],
}


def test_parse_ping():
    """Counts, loss and times; an unreachable host has no times."""
    ok = diag.parse_ping("1.1.1.1", PING_OK)
    assert (ok["reachable"], ok["transmitted"], ok["received"]) == (True, 3, 3)
    assert ok["loss_percent"] == 0.0
    assert (ok["rtt_min_ms"], ok["rtt_avg_ms"], ok["rtt_max_ms"]) == (
        13.201,
        13.879,
        14.398,
    )
    lost = diag.parse_ping("192.0.2.1", PING_LOST)
    assert (lost["reachable"], lost["loss_percent"], lost["rtt_avg_ms"]) == (
        False,
        100.0,
        None,
    )
    assert diag.parse_ping("x", "")["transmitted"] is None


def test_parse_traceroute():
    """Continuation lines join their hop; '*' hops have no replies."""
    trace = diag.parse_traceroute("1.1.1.1", TRACE)
    assert trace["address"] == "1.1.1.1" and trace["reached"] is True
    assert [h["hop"] for h in trace["hops"]] == [1, 2, 3, 4]
    assert [r["address"] for r in trace["hops"][0]["replies"]] == [
        "10.0.0.66",
        "10.0.0.67",
        "10.0.0.66",
    ]
    assert trace["hops"][1]["replies"] == [
        {"address": "198.51.100.1", "rtt_ms": [8.732, 8.785]}
    ]
    assert trace["hops"][2]["replies"] == []
    assert trace["hops"][3]["replies"][0]["rtt_ms"] == [13.91, 12.7, 13.0]
    silent = diag.parse_traceroute("1.1.1.1", TRACE_SILENT)
    assert silent["reached"] is False and len(silent["hops"]) == 2


def test_parse_dns():
    """Records and per-server times in ms."""
    dns = diag.parse_dns("netgate.com", DNS)
    assert dns["resolved"] is True
    assert dns["records"][0] == {"type": "A", "data": "199.60.103.104"}
    assert dns["servers"] == [
        {"server": "127.0.0.1", "time_ms": 7.0},
        {"server": "x", "time_ms": None},
    ]
    assert diag.parse_dns("nope", {})["resolved"] is False


def _client():
    return NetgateClient(
        "https://pf.example:8443", object(), username="u", password="p"
    )


async def test_client_requests():
    """Request bodies match the API; traceroute always sends proto."""
    client = _client()
    client._request = AsyncMock(return_value={"results": PING_OK})
    result = await client.ping("1.1.1.1", count=50, source="wan")
    assert result["received"] == 3
    method, path = client._request.await_args.args
    assert (method, path) == ("POST", "/diag/ping")
    assert client._request.await_args.kwargs["payload"] == {
        "host": "1.1.1.1",
        "count": 20,
        "ipv6": False,
        "source_addr": "wan",
    }
    client._request = AsyncMock(return_value={"results": TRACE})
    await client.traceroute("1.1.1.1", max_hops=6, ipv6=True)
    payload = client._request.await_args.kwargs["payload"]
    assert payload == {"host": "1.1.1.1", "hops": 6, "proto": "ipv6", "src": "any"}


async def test_test_port_open_and_closed():
    """A refused connection is a result, other errors still raise."""
    client = _client()
    client._request = AsyncMock(
        return_value={
            "response": "Connection to 1.1.1.1 443 port [tcp/https] succeeded!\n"
        }
    )
    assert (await client.test_port("1.1.1.1", 443))["open"] is True
    client._request = AsyncMock(
        side_effect=PfSenseAPIError(
            400, "400", "connection to 1.1.1.1:81 failed (error executing command)"
        )
    )
    closed = await client.test_port("1.1.1.1", 81)
    assert closed["open"] is False and "failed" in closed["message"]
    client._request = AsyncMock(side_effect=PfSenseAPIError(400, "400", "invalid host"))
    with pytest.raises(PfSenseAPIError):
        await client.test_port("bad host", 81)


async def _register(hass, clients):
    hass.data[DOMAIN] = {eid: {PFSENSE_CLIENT: c} for eid, c in clients.items()}
    registrar = ServiceRegistrar(hass)
    registrar._register_diagnostics()


async def test_actions_return_results(hass: HomeAssistant):
    """With one firewall, no config_entry_id is needed."""
    client = MagicMock()
    client.ping = AsyncMock(return_value={"host": "1.1.1.1", "reachable": True})
    client.dns_lookup = AsyncMock(
        return_value={"host": "netgate.com", "resolved": True}
    )
    await _register(hass, {"only": client})
    result = await hass.services.async_call(
        DOMAIN,
        "ping",
        {"host": "1.1.1.1", "count": 2},
        blocking=True,
        return_response=True,
    )
    assert result == {"host": "1.1.1.1", "reachable": True}
    client.ping.assert_awaited_once_with("1.1.1.1", 2, None, False)
    result = await hass.services.async_call(
        DOMAIN,
        "dns_lookup",
        {"host": "netgate.com"},
        blocking=True,
        return_response=True,
    )
    assert result["resolved"] is True


async def test_actions_pick_the_firewall(hass: HomeAssistant):
    """Two firewalls need config_entry_id; pfrest reports unsupported."""
    one, two = MagicMock(), MagicMock()
    two.test_port = AsyncMock(return_value={"open": True})
    one.test_port = AsyncMock(side_effect=PfSenseUnsupportedError("Netgate API only"))
    await _register(hass, {"one": one, "two": two})
    with pytest.raises(ServiceValidationError, match="config_entry_id"):
        await hass.services.async_call(
            DOMAIN,
            "test_port",
            {"host": "h", "port": 22},
            blocking=True,
            return_response=True,
        )
    result = await hass.services.async_call(
        DOMAIN,
        "test_port",
        {"host": "h", "port": 22, "config_entry_id": "two"},
        blocking=True,
        return_response=True,
    )
    assert result == {"open": True}
    with pytest.raises(ServiceValidationError, match="Netgate API only"):
        await hass.services.async_call(
            DOMAIN,
            "test_port",
            {"host": "h", "port": 22, "config_entry_id": "one"},
            blocking=True,
            return_response=True,
        )


async def test_pf_tables_client():
    """Each listed table is read; entries in the path are URL-encoded."""
    client = _client()
    details = {
        "/diag/tables/sshguard": {"table_name": "sshguard", "entries": ["203.0.113.7"]},
        "/diag/tables/bogons": {"table_name": "bogons", "entries": ["0.0.0.0/8"]},
    }

    async def get(path, **params):
        if path == "/diag/tables":
            return {
                "tables": [{"table_name": "sshguard"}, {"table_name": "bogons"}, {}]
            }
        return details[path]

    client._get = get
    tables = await client.get_pf_tables()
    assert [(t["name"], t["count"]) for t in tables] == [("sshguard", 1), ("bogons", 1)]

    client._request = AsyncMock(return_value={"table_name": "bogons", "entries": []})
    after = await client.remove_pf_table_entry("bogons", "0.0.0.0/8")
    assert client._request.await_args.args == (
        "DELETE",
        "/diag/tables/bogons/0.0.0.0%2F8",
    )
    assert after["count"] == 0


async def test_remove_table_entry_action(hass: HomeAssistant):
    """A write: it runs with or without asking for the response."""
    client = MagicMock()
    client.remove_pf_table_entry = AsyncMock(
        return_value={"name": "sshguard", "count": 0}
    )
    await _register(hass, {"only": client})
    data = {"table": "sshguard", "entry": "203.0.113.7"}
    await hass.services.async_call(DOMAIN, "remove_table_entry", data, blocking=True)
    result = await hass.services.async_call(
        DOMAIN, "remove_table_entry", data, blocking=True, return_response=True
    )
    assert result == {"name": "sshguard", "count": 0}
    client.remove_pf_table_entry.assert_awaited_with("sshguard", "203.0.113.7")
