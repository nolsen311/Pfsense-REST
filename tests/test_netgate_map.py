"""Netgate API response mapping (shapes from a 26.07 box, values made up)."""

import base64
import json
import time

import aiohttp
from aioresponses import aioresponses
import pytest

from custom_components.pfsense.pypfsense import (
    NetgateClient,
    PfSenseAPIError,
    netgate_map as nm,
)

STATUS = {
    "host": "fw.example.lan",
    "ndi": "abc",
    "prod": "pfSense",
    "cores": 4,
    "cpu": "Intel(R) Atom(TM) CPU C3558 @ 2.20GHz",
    "ram": 8_000_000_000,
    "fram": 6_000_000_000,
    "swap": 0,
    "fswap": 0,
    "up": "83 days, 4 hours, 12 minutes",
}
INTERFACES = {
    "interfaces": [
        {
            "identity": "wan",
            "assigned_name": "WAN",
            "device": "igc3",
            "mac_address": "00:08:A2:00:00:01",
            "status": "up",
            "enabled": True,
            "ip_address": "203.0.113.7",
            "in_bytes": 1000,
            "in_bytes_pass": 900,
            "in_bytes_block": 100,
            "out_bytes": 500,
            "out_bytes_pass": 500,
            "in_packets": 10,
            "in_packets_pass": 9,
            "out_packets": 5,
            "out_packets_pass": 5,
            "in_errors": 0,
            "out_errors": 1,
            "collisions": 0,
        },
        {"identity": "opt2", "assigned_name": "DMZ", "status": "disabled"},
        {"assigned_name": "no identity"},
    ]
}
GATEWAYS = {
    "gateways": [
        {
            "name": "WAN_DHCP",
            "status": "Online",
            "delay": "14.995ms",
            "stddev": "3.523ms",
            "loss": "0.0%",
            "monitor": "203.0.113.1",
            "defaultgw": True,
        }
    ]
}


def test_number_parses_units() -> None:
    """Latency/loss strings and scientific notation become floats."""
    assert nm.number("14.995ms") == 14.995
    assert nm.number("0.0%") == 0.0
    assert nm.number("3.416e+04") == 34160.0
    assert nm.number(7) == 7.0
    assert nm.number("") is None
    assert nm.number(None) is None
    assert nm.number(True) is None


def test_monitoring_latest_takes_last_numeric_bucket() -> None:
    """One CSV row per series; the newest bucket may be empty."""
    body = {
        "dataseries": ["user", "nice", "system", "interrupt", "processes"],
        "data_format": "csv",
        "data": [
            "4.489,7.271,3,",
            "0,0,0,",
            "0.2649,0.7838,1.6,",
            "0.02,0.18,0.2,",
            "467,467,467,",
        ],
    }
    assert nm.monitoring_latest(body) == {
        "user": 3.0,
        "nice": 0.0,
        "system": 1.6,
        "interrupt": 0.2,
        "processes": 467.0,
    }
    assert nm.monitoring_latest({"dataseries": ["x"], "data": [",,"]}) == {}
    assert nm.monitoring_latest(None) == {}


def test_build_telemetry() -> None:
    """System figures, interfaces and gateways land under pfrest's keys."""
    t = nm.build_telemetry(
        STATUS,
        INTERFACES,
        GATEWAYS,
        {"WAN_DHCP": {"isdefaultgw": True}},
        {"servers": []},
        {"user": 3.0, "nice": 0.0, "system": 1.6, "interrupt": 0.2},
        {"thermal_tz0": 26.9, "cpu_0": 46.0, "cpu_1": 47.0},
        {"current": 34160, "cache": 0, "total": 34160, "max": 1_000_000},
    )
    assert t["cpu"] == {
        "used_percent": 4.8,
        "count": 4,
        "model": STATUS["cpu"],
    }
    assert t["memory"] == {"used_percent": 25.0, "swap_used_percent": None}
    assert t["mbuf"] == {"used_percent": 3.42}
    assert t["system"]["temp"] == 47.0  # hottest core, like pfrest
    assert t["system"]["uptime"] == STATUS["up"]
    assert t["system"]["load_average"] == {
        "one_minute": None,
        "five_minute": None,
        "fifteen_minute": None,
    }
    assert t["wan_ip"] == "203.0.113.7"

    wan = t["interfaces"]["wan"]
    assert set(t["interfaces"]) == {"wan", "opt2"}
    assert (wan["ifname"], wan["descr"], wan["hwif"]) == ("wan", "WAN", "igc3")
    assert wan["macaddr"] == "00:08:a2:00:00:01"
    assert (wan["inbytes"], wan["inbytespass"], wan["inbytesblock"]) == (1000, 900, 100)
    assert (wan["inpkts"], wan["outerrs"], wan["status"]) == (10, 1, "up")

    gw = t["gateways"]["WAN_DHCP"]
    assert gw["status"] == "online"
    assert (gw["delay"], gw["stddev"], gw["loss"]) == (14.995, 3.523, 0.0)
    assert gw["monitorip"] == "203.0.113.1"
    assert gw["srcip"] is None
    assert gw["substatus"] == "none"
    assert t["gateways_detail"] == {"WAN_DHCP": {"isdefaultgw": True}}


def test_build_telemetry_without_optional_parts() -> None:
    """Missing series and no WAN leave values empty rather than failing."""
    t = nm.build_telemetry({}, {"interfaces": []}, {}, {}, None, {}, {}, {})
    assert t["cpu"]["used_percent"] is None
    assert t["memory"]["used_percent"] is None
    assert t["mbuf"]["used_percent"] is None
    assert t["system"]["temp"] is None
    assert t["wan_ip"] == "Disconnected"
    assert (
        nm.build_telemetry({}, {}, {}, {}, None, {}, {"thermal_tz0": 30}, {})["system"][
            "temp"
        ]
        == 30
    )


def test_openvpn_servers() -> None:
    """Servers are keyed by vpnid with client counts and byte totals."""
    openvpn = {
        "servers": [
            {
                "vpnid": "1",
                "name": "road warrior",
                "conns": [
                    {"bytes_recv": 100, "bytes_sent": 10},
                    {"bytes_recv": "50", "bytes_sent": None},
                ],
            }
        ]
    }
    t = nm.build_telemetry({}, {}, {}, {}, openvpn, {}, {}, {})
    assert t["openvpn"]["servers"]["1"] == {
        "name": "road warrior",
        "vpnid": "1",
        "connected_client_count": 2,
        "total_bytes_recv": 150,
        "total_bytes_sent": 10,
    }


def test_gateways_detail() -> None:
    """Interface is the identity; default flag from either source."""
    body = {
        "defaults": {"defaultgw4": "WAN_DHCP", "defaultgw6": ""},
        "gateways": [
            {
                "name": "WAN_DHCP",
                "interface": "igc3",
                "interface_identity": "wan",
                "weight": "1",
                "gateway": "dynamic",
                "isdefaultgw": False,
            },
            {"name": "BACKUP", "interface_identity": "opt1", "isdefaultgw": False},
        ],
    }
    out = nm.gateways_detail(body)
    assert out["WAN_DHCP"]["interface"] == "wan"
    assert out["WAN_DHCP"]["isdefaultgw"] is True
    assert out["BACKUP"]["isdefaultgw"] is False
    assert nm.gateways_detail(None) == {}


def test_services_and_dns() -> None:
    """Services keep their fields; DNS servers become IP strings."""
    svcs = nm.services(
        {
            "services": [
                {"name": "unbound", "status": True, "vpnid": "", "description": "DNS"},
                {"name": "ntpd", "running": False},
            ]
        }
    )
    assert [(s["name"], s["status"]) for s in svcs] == [
        ("unbound", True),
        ("ntpd", False),
    ]
    assert nm.dns_servers(
        {"dnsservers": [{"ip": "1.1.1.1", "gw": "", "name": ""}, {"ip": ""}, "9.9.9.9"]}
    ) == ["1.1.1.1", "9.9.9.9"]
    assert nm.dns_servers({}) == []


def test_dhcp_leases() -> None:
    """Leases get pfrest's names; static reservations are 'static'."""
    leases = nm.dhcp_leases(
        {
            "v4leases": [
                {
                    "ip": "10.0.0.5",
                    "mac": "AA:BB:CC:00:00:01",
                    "host": "laptop",
                    "assigned_intf": "LAN",
                    "start": "2026/11/17 10:00:00",
                    "end": "2026/11/17 12:00:00",
                    "state": "active",
                    "type": "dynamic",
                    "online_status": "online",
                },
                {
                    "ip": "10.0.0.6",
                    "type": "static",
                    "state": "idle",
                    "online_status": "offline",
                },
            ]
        }
    )
    first, second = leases
    assert first["mac"] == "aa:bb:cc:00:00:01"
    assert (first["hostname"], first["if"], first["starts"]) == (
        "laptop",
        "LAN",
        "2026/11/17 10:00:00",
    )
    assert (first["active_status"], first["online_status"]) == ("active", "online")
    assert (second["active_status"], second["online_status"]) == ("static", "offline")


def test_arp_table() -> None:
    """ARP rows get ip_address/mac_address; unknown hostnames are '?'."""
    rows = nm.arp_table(
        {
            "arp": [
                {
                    "ip": "10.0.0.5",
                    "mac": "AA:BB:CC:00:00:01",
                    "interface": "LAN",
                    "dnsresolve": "laptop",
                    "expires": "Expires in 499 seconds",
                },
                {
                    "ip": "10.0.0.1",
                    "mac": "aa:bb:cc:00:00:02",
                    "dnsresolve": "",
                    "expires": "Permanent",
                },
            ]
        }
    )
    assert rows[0]["ip_address"] == "10.0.0.5"
    assert rows[0]["mac_address"] == "aa:bb:cc:00:00:01"
    assert rows[0]["hostname"] == "laptop"
    assert rows[0]["permanent"] is False
    assert (rows[1]["hostname"], rows[1]["permanent"]) == ("?", True)


def _rule(tracker, rid, **kw):
    return {
        "rule": {
            "tracker": tracker,
            "id": rid,
            "readonly": False,
            "disabled": False,
            **kw,
        }
    }


def test_filter_rules() -> None:
    """System rules dropped, floating de-duplicated, trackers as ints."""
    rules = nm.filter_rules(
        {
            "lan": {
                "entries": [
                    {"separator": {"id": "s1", "text": "--"}},
                    _rule("10000-10999", "", readonly=True),
                    _rule(
                        "1700000001", "lan_1700000001", descr="allow", interface="LAN"
                    ),
                    _rule("1700000002", "lan_1700000002", disabled=True),
                    _rule("1700000003", "lan_1700000003", associated_rule_id="nat_1"),
                ]
            },
            "floating": {"entries": [_rule("1700000009", "fl_1", floating=True)]},
            "wan": {"entries": [_rule("1700000009", "fl_1", floating=True)]},
        }
    )
    by_tracker = {r["tracker"]: r for r in rules}
    assert sorted(by_tracker) == [1700000001, 1700000002, 1700000003, 1700000009]
    assert by_tracker[1700000001]["interface"] == "lan"
    assert by_tracker[1700000001]["interface_name"] == "LAN"
    assert by_tracker[1700000002]["disabled"] is True
    assert by_tracker[1700000003]["associated_rule_id"] == "nat_1"
    assert by_tracker[1700000001]["associated_rule_id"] is None
    assert by_tracker[1700000009]["interface"] == "floating"


def test_nat_rules() -> None:
    """created.time becomes pfrest's int created_time; disabled defaults False."""
    pf = nm.nat_port_forwards(
        {
            "rules": [
                {
                    "rule": {
                        "id": "1",
                        "created": {"time": "1712345678"},
                        "disabled": True,
                    }
                },
                {"separator": {"id": "x"}},
            ]
        }
    )
    assert [(r["created_time"], r["disabled"]) for r in pf] == [(1712345678, True)]
    out = nm.nat_outbound(
        {
            "rules": [{"id": "o1", "created": {"time": "1712345679"}, "descr": "x"}],
            "automatic_rules": [{"id": "auto"}],
        }
    )
    assert [(r["created_time"], r["disabled"]) for r in out] == [(1712345679, False)]


def test_carp() -> None:
    """CARP state and VIPs with status matched by address; passwords dropped."""
    assert nm.carp_enabled({"enabled": True, "maintenancemode_enabled": False})
    assert not nm.carp_enabled({"enabled": True, "maintenancemode_enabled": True})
    assert not nm.carp_enabled(None)

    vips = {
        "virtualips": [
            {
                "mode": "carp",
                "uniqid": "u1",
                "interface": "lan",
                "vhid": "1",
                "advskew": "0",
                "advbase": "1",
                "subnet": "10.0.0.254/24",
                "descr": "gw",
                "password": "secret",
            },
            {"mode": "ipalias", "uniqid": "u2"},
        ]
    }
    status = {"vips": [{"virtual_ip": "10.0.0.254", "status": "master"}]}
    (vip,) = nm.carp_interfaces(vips, status)
    assert vip["uniqid"] == "u1"
    assert (vip["subnet"], vip["subnet_bits"], vip["type"]) == (
        "10.0.0.254",
        24,
        "single",
    )
    assert vip["status"] == "MASTER"
    assert "password" not in vip
    assert nm.carp_interfaces(vips, {})[0]["status"] is None


# ------------------------------------------------------------ client reads

BASE = "https://pf.example:8443"
API = f"{BASE}/api"


def _jwt() -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + 300}).encode()
    ).decode()
    return f"h.{payload.rstrip('=')}.s"


@pytest.fixture
async def client():
    """A logged-in-on-demand Netgate client."""
    async with aiohttp.ClientSession() as session:
        yield NetgateClient(BASE, session, username="u", password="p")


async def test_filter_rules_cover_disabled_interfaces_and_floating(client) -> None:
    """Rules come from status interfaces + listing groups + floating; errors skipped."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(
            f"{API}/firewall/rules/interface",
            payload={
                "interface_mappings": {
                    "LAN": {"ident": "lan"},
                    "G": {"ident": "LANGroup"},
                }
            },
        )
        m.get(
            f"{API}/system/interfaces/status",
            payload={"interfaces": [{"identity": "lan"}, {"identity": "opt2"}]},
        )
        m.get(
            f"{API}/firewall/rules/interface/lan",
            payload={"entries": [_rule("1", "lan_1")]},
        )
        m.get(
            f"{API}/firewall/rules/interface/opt2",
            payload={"entries": [_rule("2", "opt2_2")]},
        )
        m.get(
            f"{API}/firewall/rules/interface/LANGroup",
            status=400,
            payload={
                "errcode": 400,
                "errmsg": "failed to get device name: interface not found",
            },
        )
        m.get(
            f"{API}/firewall/rules/interface/floating",
            payload={"entries": [_rule("3", "f_3")]},
        )

        rules = await client.get_filter_rules()

    assert sorted((r["tracker"], r["interface"]) for r in rules) == [
        (1, "lan"),
        (2, "opt2"),
        (3, "floating"),
    ]


async def test_filter_rules_fail_when_no_interface_answers(client) -> None:
    """If every per-interface read fails, the capability fails."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(f"{API}/firewall/rules/interface", payload={})
        m.get(f"{API}/system/interfaces/status", payload={"interfaces": []})
        m.get(
            f"{API}/firewall/rules/interface/floating",
            status=500,
            payload={"errmsg": "x"},
        )
        with pytest.raises(PfSenseAPIError):
            await client.get_filter_rules()


async def test_telemetry_survives_missing_optional_parts(client) -> None:
    """Monitoring/OpenVPN/gateway-config failures leave values empty, not an error."""
    with aioresponses() as m:
        m.post(f"{API}/login", payload={"token": _jwt()})
        m.get(f"{API}/system/status", payload={"status": STATUS})
        m.get(f"{API}/system/interfaces/status", payload=INTERFACES)
        m.get(f"{API}/system/gateways/status", payload=GATEWAYS)
        m.get(f"{API}/system/gateways", status=403, payload={"errmsg": "forbidden"})
        m.get(f"{API}/vpn/openvpn/status", status=500, payload={"errmsg": "x"})
        m.get(f"{API}/controller/stats", status=403, payload={"errmsg": "forbidden"})
        m.post(
            f"{API}/system/monitoring",
            payload={"dataseries": ["user"], "data": ["5,"]},
            repeat=True,
        )
        t = await client.get_telemetry()
    assert t["interfaces"]["wan"]["inbytes"] == 1000
    assert t["gateways"]["WAN_DHCP"]["status"] == "online"
    assert t["gateways_detail"] == {}
    assert t["openvpn"] == {"servers": {}}
    assert t["cpu"]["used_percent"] == 5.0
    assert t["system"]["load_average"]["one_minute"] is None


def test_firmware_update_info() -> None:
    """``/system/update`` maps to the base shape the update entity reads."""
    body = {
        "firmware_branch": "26.07",
        "boot_env": "default_1",
        "curr_base_system": "26.07",
        "latest_base_system": "26.10",
        "update_check_error": "",
        "status_message": "Update available.",
        "messages": ["noise"],
    }
    assert nm.firmware_update_info(body) == {
        "base": {
            "installed_version": "26.07",
            "version": "26.10",
            "status_message": "Update available.",
            "check_error": None,
            "firmware_branch": "26.07",
            "boot_env": "default_1",
        }
    }
    assert nm.firmware_update_info({"status_message": "x"}) is None
    assert nm.firmware_update_info(None) is None


def test_load_average_from_controller_stats() -> None:
    """Newest sample is the 1-minute load; 5/15 are exponential averages."""
    assert nm.load_average({"cpu_load": [100] * 60}) == {
        "one_minute": 1.0,
        "five_minute": 1.0,
        "fifteen_minute": 1.0,
    }
    rising = nm.load_average({"cpu_load": [0] * 59 + [300]})
    assert rising["one_minute"] == 3.0
    assert 0 < rising["fifteen_minute"] < rising["five_minute"] < 3.0
    assert nm.load_average({"cpu_load": []}) is None
    assert nm.load_average(None) is None
    t = nm.build_telemetry({}, {}, {}, {}, None, {}, {}, {}, rising)
    assert t["system"]["load_average"] == rising
    t = nm.build_telemetry({}, {}, {}, {}, None, {}, {}, {})
    assert t["system"]["load_average"]["one_minute"] is None


def test_installed_packages() -> None:
    """Catalog ``version`` vs ``installed_version`` decides the update flag."""
    body = {
        "packages": [
            {
                "name": "pfSense-pkg-System_Patches",
                "internal_name": "System_Patches",
                "installed_version": "2.3.5_1",
                "available_version": "",
                "version": "2.3.6",
                "update_available": False,
                "category": "sysutils",
                "descr": "patches",
            },
            {
                "name": "pfSense-pkg-acme",
                "internal_name": "acme",
                "installed_version": "1.3.2",
                "version": "1.3.2",
            },
            {"name": "broken", "installed_version": ""},
        ]
    }
    patches, acme = nm.installed_packages(body)
    assert patches == {
        "name": "System_Patches",
        "package": "pfSense-pkg-System_Patches",
        "descr": "patches",
        "category": "sysutils",
        "installed_version": "2.3.5_1",
        "latest_version": "2.3.6",
        "update_available": True,
    }
    assert (acme["latest_version"], acme["update_available"]) == ("1.3.2", False)
    assert nm.installed_packages(None) == []


def test_ntp_status():
    """The selected peer gives offset/stratum; the pool placeholder is skipped."""
    body = {
        "enabled": True,
        "servers": [
            {
                "status": "Pool Placeholder",
                "server": "2.pfsense.pool.ntp.org",
                "refid": ".POOL.",
                "stratum": "16",
            },
            {
                "status": "Candidate",
                "server": "192.0.2.10",
                "refid": "x",
                "stratum": "2",
                "offset": "+0.838",
            },
            {
                "status": "Active Peer",
                "server": "192.0.2.20",
                "refid": "17.253.4.37",
                "stratum": "2",
                "offset": "+3.704",
                "delay": "29.716",
                "jitter": "1.009",
                "reach": "377",
            },
        ],
    }
    ntp = nm.ntp_status(body)
    assert ntp["synchronized"] is True
    assert (ntp["offset_ms"], ntp["stratum"]) == (3.704, 2)
    assert ntp["peer"]["server"] == "192.0.2.20"
    assert ntp["peer"]["delay_ms"] == 29.716
    assert [p["server"] for p in ntp["peers"]] == ["192.0.2.10", "192.0.2.20"]

    unsynced = nm.ntp_status({"enabled": True, "servers": body["servers"][:2]})
    assert unsynced["synchronized"] is False
    assert unsynced["offset_ms"] is None and unsynced["peer"] is None
    assert nm.ntp_status(None) == {
        "enabled": False,
        "synchronized": False,
        "peer": None,
        "offset_ms": None,
        "stratum": None,
        "peers": [],
    }


def test_certificates_keep_safe_fields_only():
    """In-use or server certs only; keys, CSRs and bodies are never copied."""
    body = {
        "certs": [
            {
                "refid": "a1",
                "descr": "GUI",
                "type": "server",
                "inuse": "",
                "ends": "2027-01-18 09:17:33 +0000 UTC",
                "starts": "2026-10-20 09:17:34 +0000 UTC",
                "prv": "SECRET",
                "crt": "BODY",
                "csr": "CSR",
                "can_renew": True,
            },
            {
                "refid": "b2",
                "descr": "vpn user",
                "type": "user",
                "inuse": "",
                "ends": "2027-01-01 00:00:00 +0000 UTC",
            },
            {
                "refid": "c3",
                "descr": "DNS",
                "type": "client",
                "inuse": "DNS Resolver",
                "ends": "2027-01-30 10:01:00 +0000 UTC",
            },
            {"refid": "d4", "descr": "bad", "type": "server", "ends": "not a date"},
        ]
    }
    certs = nm.certificates(body)
    assert [c["refid"] for c in certs] == ["a1", "c3"]
    assert certs[0]["expires"] == "2027-01-18T09:17:33+00:00"
    assert certs[1]["in_use"] == "DNS Resolver"
    flat = repr(certs)
    assert "SECRET" not in flat and "BODY" not in flat and "CSR" not in flat
