"""Netgate API writes: request shapes, idempotence and apply (no hardware)."""

import base64
import json
import time

import aiohttp
from aioresponses import aioresponses
import pytest

from custom_components.pfsense.pypfsense import (
    NetgateClient,
    PfSenseConnectionError,
    PfSenseNotFoundError,
)

BASE = "https://pf.example:8443"
API = f"{BASE}/api"
APPLY = f"{API}/system/config/dirty"


def _jwt() -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + 300}).encode()
    ).decode()
    return f"h.{payload.rstrip('=')}.s"


@pytest.fixture
async def client():
    """A Netgate client; every test mocks its own requests."""
    async with aiohttp.ClientSession() as session:
        yield NetgateClient(BASE, session, username="u", password="p")


def _calls(m, method: str, url: str) -> list:
    return [
        call
        for (verb, req_url), calls in m.requests.items()
        if verb == method and str(req_url).split("?")[0] == url
        for call in calls
    ]


def _all_calls(m) -> list[tuple[str, str]]:
    return [
        (verb, str(url)) for (verb, url), calls in m.requests.items() for _ in calls
    ]


def _rules_mocks(m, disabled: bool) -> None:
    m.post(f"{API}/login", payload={"token": _jwt()})
    m.get(f"{API}/firewall/rules/interface", payload={"interface_mappings": {}})
    m.get(
        f"{API}/system/interfaces/status", payload={"interfaces": [{"identity": "lan"}]}
    )
    m.get(
        f"{API}/firewall/rules/interface/lan",
        payload={
            "entries": [
                {
                    "rule": {
                        "id": "lan_1700000001",
                        "tracker": "1700000001",
                        "disabled": disabled,
                        "readonly": False,
                    }
                }
            ]
        },
        repeat=True,
    )
    m.get(
        f"{API}/firewall/rules/interface/floating", payload={"entries": []}, repeat=True
    )


async def test_disable_filter_rule_toggles_and_applies(client) -> None:
    """Disabling an enabled rule posts the toggle, then applies."""
    with aioresponses() as m:
        _rules_mocks(m, disabled=False)
        toggle = f"{API}/firewall/rules/interface/lan/toggle/lan_1700000001"
        m.post(toggle, payload={"result": "ok"})
        m.post(APPLY, payload={"dirty_subsystems": {}})

        await client.disable_filter_rule_by_tracker(1700000001)

        (call,) = _calls(m, "POST", toggle)
        assert call.kwargs["json"] == {"value": True}
        assert _calls(m, "POST", APPLY)[0].kwargs["json"] == {"apply": True}


async def test_enable_already_enabled_rule_is_a_no_op(client) -> None:
    """A rule already in the requested state is not toggled (toggle flips)."""
    with aioresponses() as m:
        _rules_mocks(m, disabled=False)
        await client.enable_filter_rule_by_tracker("1700000001")
        assert not [c for c in _all_calls(m) if "toggle" in c[1]]
        assert not _calls(m, "POST", APPLY)


async def test_enable_disabled_rule_sends_false(client) -> None:
    """Enabling sends value=false."""
    with aioresponses() as m:
        _rules_mocks(m, disabled=True)
        toggle = f"{API}/firewall/rules/interface/lan/toggle/lan_1700000001"
        m.post(toggle, payload={"result": "ok"})
        m.post(APPLY, payload={})
        await client.enable_filter_rule_by_tracker(1700000001)
        assert _calls(m, "POST", toggle)[0].kwargs["json"] == {"value": False}


async def test_unknown_rule_is_not_found(client) -> None:
    """Toggling a tracker that no longer exists raises, without writing."""
    with aioresponses() as m:
        _rules_mocks(m, disabled=False)
        with pytest.raises(PfSenseNotFoundError):
            await client.disable_filter_rule_by_tracker(42)
        assert not [c for c in _all_calls(m) if c[0] == "POST" and "login" not in c[1]]


async def test_nat_outbound_toggle(client) -> None:
    """NAT rules are found by created_time and toggled by id."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(
            f"{API}/firewall/nat/outbound",
            payload={"rules": [{"id": "3", "created": {"time": "1712345679"}}]},
        )
        m.post(f"{API}/firewall/nat/outbound/toggle/3", payload={"result": "ok"})
        m.post(APPLY, payload={})
        await client.disable_nat_outbound_rule_by_created_time(1712345679)
        call = _calls(m, "POST", f"{API}/firewall/nat/outbound/toggle/3")[0]
        assert call.kwargs["json"] == {"value": True}


def _states(*pairs: tuple[str, str]) -> dict:
    return {"states": [{"src": a, "dst": b, "proto": "tcp"} for a, b in pairs]}


async def test_alias_add_and_remove(client) -> None:
    """Entries are alias ``targets``; changes are applied."""
    alias = {
        "id": "4",
        "name": "blocked",
        "type": "host",
        "descr": "d",
        "address": "",
        "detail": "",
        "targets": [
            {"name": "10.0.0.1", "descr": "one", "updatefreq": ""},
            {"name": "10.0.0.2", "descr": "two", "updatefreq": ""},
        ],
        "display_values": ["x"],
    }
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(f"{API}/aliases", payload={"aliases": [alias]}, repeat=True)
        m.post(f"{API}/aliases/4", payload={"result": "ok"}, repeat=True)
        m.post(APPLY, payload={}, repeat=True)
        m.get(f"{API}/diag/states?filter_str=10.0.0.9", payload=_states())

        await client.update_alias_address("blocked", "10.0.0.9")
        await client.update_alias_address(
            "blocked", "10.0.0.1", "remove", kill_states=False
        )
        await client.update_alias_address("blocked", "10.0.0.2")  # already there

        first, second = _calls(m, "POST", f"{API}/aliases/4")
        assert first.kwargs["json"] == {
            "name": "blocked",
            "type": "host",
            "descr": "d",
            "targets": [
                {"name": "10.0.0.1", "descr": "one", "updatefreq": ""},
                {"name": "10.0.0.2", "descr": "two", "updatefreq": ""},
                {"name": "10.0.0.9", "descr": "Added via HASS"},
            ],
        }
        assert [t["name"] for t in second.kwargs["json"]["targets"]] == ["10.0.0.2"]
        assert len(_calls(m, "POST", APPLY)) == 2


async def test_alias_created_when_missing(client) -> None:
    """Adding to a missing alias creates a host alias holding the target."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(f"{API}/aliases", payload={"aliases": []})
        m.put(f"{API}/aliases", payload={"result": "ok"})
        m.post(APPLY, payload={})
        await client.update_alias_address("new", "10.0.0.5", kill_states=False)
        body = _calls(m, "PUT", f"{API}/aliases")[0].kwargs["json"]
        assert (body["name"], body["type"]) == ("new", "host")
        assert body["targets"] == [{"name": "10.0.0.5", "descr": "Added via HASS"}]


async def test_kill_states_exact_match_pairs(client) -> None:
    """States are listed, matched exactly (not by substring), deleted by pair."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(
            f"{API}/diag/states?filter_str=10.0.0.1",
            payload=_states(
                ("10.0.0.1", "1.1.1.1"),
                ("8.8.8.8", "10.0.0.1"),
                ("10.0.0.1", "1.1.1.1"),  # duplicate pair
                ("10.0.0.10", "1.1.1.1"),  # substring only: kept
            ),
        )
        m.delete(
            f"{API}/diag/states?dstip=1.1.1.1&srcip=10.0.0.1", payload={"result": "ok"}
        )
        m.delete(
            f"{API}/diag/states?dstip=10.0.0.1&srcip=8.8.8.8", payload={"result": "ok"}
        )
        await client.kill_states("10.0.0.1")
        deletes = sorted(c[1] for c in _all_calls(m) if c[0] == "DELETE")
    assert deletes == [
        f"{API}/diag/states?dstip=1.1.1.1&srcip=10.0.0.1",
        f"{API}/diag/states?dstip=10.0.0.1&srcip=8.8.8.8",
    ]


async def test_kill_states_with_destination(client) -> None:
    """A destination narrows the pairs."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(
            f"{API}/diag/states?filter_str=10.0.0.1",
            payload=_states(("10.0.0.1", "1.1.1.1"), ("10.0.0.1", "9.9.9.9")),
        )
        m.delete(
            f"{API}/diag/states?dstip=9.9.9.9&srcip=10.0.0.1", payload={"result": "ok"}
        )
        await client.kill_states("10.0.0.1", "9.9.9.9")
        assert len([c for c in _all_calls(m) if c[0] == "DELETE"]) == 1


async def test_kill_states_for_rule_hosts_only(client) -> None:
    """Host addresses and alias host targets are killed; networks skipped."""
    rule = {
        "source": {"address": "web_hosts", "not": False},
        "destination": {"address": "10.0.0.0/24"},
    }
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(
            f"{API}/aliases",
            payload={
                "aliases": [
                    {
                        "name": "web_hosts",
                        "type": "host",
                        "address": "",
                        "targets": [{"name": "10.0.0.7"}, {"name": "10.1.0.0/16"}],
                    }
                ]
            },
        )
        m.get(f"{API}/diag/states?filter_str=10.0.0.7", payload=_states())
        await client.kill_states_for_rule(rule)
        gets = [c[1] for c in _all_calls(m) if "diag/states" in c[1]]
    assert gets == [f"{API}/diag/states?filter_str=10.0.0.7"]


async def test_set_default_gateway(client) -> None:
    """The gateway is updated by index with new defaults; same value is a no-op."""
    body = {
        "defaults": {"defaultgw4": "WAN_DHCP", "defaultgw6": ""},
        "gateways": [{"name": "WAN_DHCP"}, {"name": "BACKUP", "weight": "1"}],
    }
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(f"{API}/system/gateways", payload=body, repeat=True)
        m.put(f"{API}/system/gateways/1", payload={"result": "ok"})
        m.post(APPLY, payload={})
        await client.set_default_gateway("WAN_DHCP")  # already default
        await client.set_default_gateway("BACKUP")
        (call,) = _calls(m, "PUT", f"{API}/system/gateways/1")
        assert call.kwargs["json"] == {
            "name": "BACKUP",
            "weight": "1",
            "defaults": {"defaultgw4": "BACKUP", "defaultgw6": ""},
        }
        with pytest.raises(PfSenseNotFoundError):
            await client.set_default_gateway("NOPE")


async def test_reboot_and_halt(client) -> None:
    """Control actions; a dropped connection counts as success."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.post(f"{API}/diag/control", payload={"result": "ok"})
        m.post(f"{API}/diag/control", exception=aiohttp.ServerDisconnectedError())
        await client.system_reboot("fsck")
        await client.system_halt()
        bodies = [c.kwargs["json"] for c in _calls(m, "POST", f"{API}/diag/control")]
        assert bodies == [{"action": "rebootfsck"}, {"action": "halt"}]


async def test_reboot_connection_error_is_success(client) -> None:
    """PfSenseConnectionError from the dropped request is swallowed."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.post(f"{API}/diag/control", exception=aiohttp.ClientConnectionError("bye"))
        await client.system_reboot()
    assert PfSenseConnectionError  # imported for clarity of the contract


async def test_shell_backed_actions(client) -> None:
    """exec, service control and WOL go through /diag/cmd/shell base64-encoded."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.post(
            f"{API}/diag/cmd/shell",
            payload={"response": base64.b64encode(b"done").decode()},
            repeat=True,
        )
        m.get(
            f"{API}/system/interfaces/status",
            payload={
                "interfaces": [
                    {
                        "identity": "lan",
                        "assigned_name": "LAN",
                        "ip_address": "10.0.13.1",
                        "subnet_mask": "255.254.0.0",
                    }
                ]
            },
        )
        m.get(
            f"{API}/services/status",
            payload={"services": [{"name": "unbound", "status": True}]},
        )

        assert await client.exec_command("uptime") == "done"
        await client.restart_service("unbound")
        await client.start_service(
            "openvpn", {"name": "openvpn", "vpnid": "2", "mode": "server"}
        )
        await client.restart_service_if_running("unbound")
        await client.send_wol("lan", "aa:bb:cc:00:00:01")

        cmds = [
            base64.b64decode(c.kwargs["json"]["cmd"]).decode()
            for c in _calls(m, "POST", f"{API}/diag/cmd/shell")
        ]
    assert cmds == [
        "uptime",
        "/usr/local/sbin/pfSsh.php playback 'svc' 'restart' 'unbound'",
        "/usr/local/sbin/pfSsh.php playback 'svc' 'start' 'openvpn' 'server' '2'",
        "/usr/local/sbin/pfSsh.php playback 'svc' 'restart' 'unbound'",
        "/usr/local/bin/wol -i '10.1.255.255' 'aa:bb:cc:00:00:01'",  # /15
    ]


async def test_delete_arp_entry_ignores_missing(client) -> None:
    """A missing ARP entry is not an error."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.delete(f"{API}/diag/arp/10.0.0.9", status=404, body="")
        await client.delete_arp_entry("10.0.0.9")
        await client.delete_arp_entry("")


async def test_state_table_reset_flushes_via_pfctl(client) -> None:
    """Reset runs ``pfctl -F states`` through the shell endpoint."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.post(f"{API}/diag/cmd/shell", payload={"response": ""})
        await client.reset_state_table()
        (call,) = _calls(m, "POST", f"{API}/diag/cmd/shell")
        assert base64.b64decode(call.kwargs["json"]["cmd"]) == b"/sbin/pfctl -F states"


async def test_exec_command_non_base64_response(client) -> None:
    """A plain-text response is returned as is."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.post(f"{API}/diag/cmd/shell", payload={"response": "not base64!"})
        assert await client.exec_command("x") == "not base64!"
