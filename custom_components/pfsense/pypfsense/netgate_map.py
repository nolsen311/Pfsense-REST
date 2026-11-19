"""Map Netgate API (Nexus) responses onto the shapes the integration consumes.

Every function here is pure: a raw response body in, the pfrest-compatible
structure out (see CLAUDE.md "Consumer contracts"). Field names were checked
against a live 26.07 box; where the box had no data (OpenVPN servers, CARP
VIPs, port forwards) they follow ``pfapi_openapi.yml`` and are marked
LIVE-CHECK.

Raw fields are kept alongside the mapped ones, so nothing Nexus reports is
lost to a consumer that wants it.
"""

from __future__ import annotations

from datetime import UTC, datetime
import math
import re
from typing import Any

_NUMBER = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")
# Filter rules Nexus generates itself (default block, bogons, ...).
_SYSTEM_TRACKER = re.compile(r"^\d+-\d+$")

# pfrest /status/interfaces field -> Nexus /system/interfaces/status field.
_INTERFACE_FIELDS = {
    "descr": "assigned_name",
    "hwif": "device",
    "macaddr": "mac_address",
    "mtu": "mtu",
    "enable": "enabled",
    "status": "status",
    "ipaddr": "ip_address",
    "subnet": "subnet_mask",
    "ipaddrv6": "ipv6_address",
    "subnetv6": "ipv6_subnet_mask",
    "linklocal": "ipv6_link_local",
    "media": "media",
    "gateway": "gateway",
    "gatewayv6": "ipv6_gateway",
    "dhcplink": "dhcplink",
    "inerrs": "in_errors",
    "outerrs": "out_errors",
    "collisions": "collisions",
    "inbytes": "in_bytes",
    "inbytespass": "in_bytes_pass",
    "inbytesblock": "in_bytes_block",
    "outbytes": "out_bytes",
    "outbytespass": "out_bytes_pass",
    "outbytesblock": "out_bytes_block",
    "inpkts": "in_packets",
    "inpktspass": "in_packets_pass",
    "inpktsblock": "in_packets_block",
    "outpkts": "out_packets",
    "outpktspass": "out_packets_pass",
    "outpktsblock": "out_packets_block",
}


def number(value: Any) -> float | None:
    """``"14.995ms"`` -> 14.995, ``"0.0%"`` -> 0.0, ``""``/None -> None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    match = _NUMBER.search(str(value or ""))
    return float(match.group()) if match else None


def _int_if_digits(value: Any) -> Any:
    text = str(value) if value is not None else ""
    return int(text) if text.isdigit() else value


def _mac(value: Any) -> Any:
    return value.lower() if isinstance(value, str) else value


def _items(body: Any, key: str) -> list:
    value = body.get(key) if isinstance(body, dict) else None
    return [i for i in value if isinstance(i, dict)] if isinstance(value, list) else []


# ----------------------------------------------------------------- telemetry


def monitoring_latest(body: Any) -> dict[str, float]:
    """Last value of each series in a ``POST /system/monitoring`` response.

    The response has ``dataseries`` (series names) and ``data``: one CSV row
    per series, one column per time bucket, oldest first. The newest bucket
    can still be empty, so the last *numeric* value is taken.
    """
    if not isinstance(body, dict):
        return {}
    latest: dict[str, float] = {}
    for name, row in zip(
        body.get("dataseries") or [], body.get("data") or [], strict=False
    ):
        for cell in reversed(str(row).split(",")):
            value = number(cell) if cell.strip() else None
            if value is not None:
                latest[str(name)] = value
                break
    return latest


def build_telemetry(
    status: dict,
    interfaces: Any,
    gateways: Any,
    gateways_detail: dict,
    openvpn: Any,
    processor: dict[str, float],
    sensors: dict[str, float],
    mbuf: dict[str, float],
    load: dict | None = None,
) -> dict:
    """The legacy ``telemetry`` dict, same keys as pfrest's ``_build_telemetry``.

    ``load`` comes from :func:`load_average`. Not available from Nexus: disk
    usage (left ``None``, so that sensor is unavailable).
    """
    status = status or {}
    cpu_parts = [processor.get(k) for k in ("user", "nice", "system", "interrupt")]
    cpu_used = (
        round(sum(v for v in cpu_parts if v is not None), 2)
        if any(v is not None for v in cpu_parts)
        else None
    )

    ram, free = number(status.get("ram")), number(status.get("fram"))
    mem_used = round(100 * (1 - free / ram), 1) if ram and free is not None else None
    swap, fswap = number(status.get("swap")), number(status.get("fswap"))
    swap_used = (
        round(100 * (1 - fswap / swap), 1) if swap and fswap is not None else None
    )

    mbuf_total, mbuf_max = mbuf.get("total"), mbuf.get("max")
    mbuf_used = (
        round(100 * mbuf_total / mbuf_max, 2)
        if mbuf_max and mbuf_total is not None
        else None
    )

    # pfrest reports the hottest core; thermal_tz0 is a cooler board sensor.
    cpu_temps = [v for k, v in sensors.items() if k.startswith("cpu_")]
    temp = max(cpu_temps) if cpu_temps else sensors.get("thermal_tz0")

    telemetry: dict = {
        "wan_ip": "Disconnected",
        "cpu": {
            "used_percent": cpu_used,
            "count": status.get("cores"),
            "model": status.get("cpu"),
        },
        "memory": {"used_percent": mem_used, "swap_used_percent": swap_used},
        "mbuf": {"used_percent": mbuf_used},
        "system": {
            "uptime": status.get("up"),
            "temp": temp,
            "load_average": load
            or {"one_minute": None, "five_minute": None, "fifteen_minute": None},
        },
        "disk_used_percent": None,
        "filesystems": [],
        "interfaces": {},
        "gateways": {},
        "gateways_detail": gateways_detail or {},
        "openvpn": {"servers": {}},
    }

    for iface in _items(interfaces, "interfaces"):
        name = iface.get("identity")
        if not name:
            continue
        entry = dict(iface)
        for ours, theirs in _INTERFACE_FIELDS.items():
            entry[ours] = iface.get(theirs)
        entry["name"] = entry["ifname"] = name
        entry["descr"] = iface.get("assigned_name") or name
        entry["macaddr"] = _mac(entry["macaddr"])
        telemetry["interfaces"][name] = entry
        if name == "wan":
            telemetry["wan_ip"] = iface.get("ip_address") or "Disconnected"

    for gw in _items(gateways, "gateways"):
        name = gw.get("name")
        if not name:
            continue
        entry = dict(gw)
        entry.update(
            {
                "status": str(gw.get("status") or "").lower() or None,
                "delay": number(gw.get("delay")),
                "stddev": number(gw.get("stddev")),
                "loss": number(gw.get("loss")),
                "monitorip": gw.get("monitor"),
                "srcip": gw.get("srcip"),
                "substatus": gw.get("substatus") or "none",
            }
        )
        telemetry["gateways"][name] = entry

    # LIVE-CHECK: no OpenVPN servers on the test box; shape per the spec
    # (OpenVPNActiveConn / OpenVPNConn).
    for server in _items(openvpn, "servers"):
        vpnid = server.get("vpnid")
        conns = [c for c in server.get("conns") or [] if isinstance(c, dict)]
        telemetry["openvpn"]["servers"][str(vpnid)] = {
            "name": server.get("name"),
            "vpnid": vpnid,
            "connected_client_count": len(conns),
            "total_bytes_recv": sum(number(c.get("bytes_recv")) or 0 for c in conns),
            "total_bytes_sent": sum(number(c.get("bytes_sent")) or 0 for c in conns),
        }

    return telemetry


def gateways_detail(body: Any) -> dict:
    """``/system/gateways`` keyed by name, with pfrest's ``isdefaultgw``/``interface``."""
    defaults = body.get("defaults") if isinstance(body, dict) else None
    defaults = defaults if isinstance(defaults, dict) else {}
    default_names = {defaults.get("defaultgw4"), defaults.get("defaultgw6")} - {
        None,
        "",
    }
    out = {}
    for gw in _items(body, "gateways"):
        name = gw.get("name")
        if not name:
            continue
        entry = dict(gw)
        entry["interface"] = gw.get("interface_identity") or gw.get("interface")
        entry["isdefaultgw"] = bool(gw.get("isdefaultgw")) or name in default_names
        out[name] = entry
    return out


# ------------------------------------------------------------------ services


def services(body: Any) -> list[dict]:
    """``/services/status``; already pfrest-shaped (``name``, ``status`` bool)."""
    out = []
    for svc in _items(body, "services"):
        entry = dict(svc)
        entry["status"] = bool(svc.get("status", svc.get("running")))
        out.append(entry)
    return out


def dns_servers(setup: Any) -> list[str]:
    """``/system/setup`` ``dnsservers`` (``[{ip, gw, name}]``) -> IP strings."""
    out = []
    items = setup.get("dnsservers") if isinstance(setup, dict) else None
    for item in items if isinstance(items, list) else []:
        ip = item.get("ip") if isinstance(item, dict) else item
        if ip:
            out.append(str(ip))
    return out


# ---------------------------------------------------------------- dhcp / arp


def dhcp_leases(body: Any) -> list[dict]:
    """``/services/dhcp/leases`` ``v4leases`` in pfrest's lease shape."""
    out = []
    for lease in _items(body, "v4leases"):
        entry = dict(lease)
        state = lease.get("state")
        entry.update(
            {
                "ip": lease.get("ip"),
                "mac": _mac(lease.get("mac")),
                "hostname": lease.get("host"),
                "if": lease.get("assigned_intf"),
                "starts": lease.get("start"),
                "ends": lease.get("end"),
                "active_status": "static" if lease.get("type") == "static" else state,
                "online_status": lease.get("online_status"),
                "descr": lease.get("descr"),
            }
        )
        out.append(entry)
    return out


def arp_table(body: Any) -> list[dict]:
    """``/diag/arp`` in pfrest's shape; ``dnsresolve`` stands in for hostname."""
    out = []
    for row in _items(body, "arp"):
        entry = dict(row)
        expires = row.get("expires")
        entry.update(
            {
                "ip_address": row.get("ip"),
                "mac_address": _mac(row.get("mac")),
                "hostname": row.get("dnsresolve") or "?",
                "permanent": str(expires).lower() == "permanent",
            }
        )
        out.append(entry)
    return out


# --------------------------------------------------------------------- rules


def filter_rules(bodies: dict[str, Any]) -> list[dict]:
    """Merge per-interface ``/firewall/rules/interface/{if}`` responses.

    ``bodies`` maps the interface identity (``lan``, ``opt1``, a group name,
    ...) to its response. Read-only system rules (tracker ``"10000-10999"``)
    are dropped; a rule listed under several interfaces (floating) is kept
    once. ``tracker`` becomes an int like pfrest's; ``interface`` is the
    identity.
    """
    out, seen = [], set()
    for ident, body in bodies.items():
        for item in _items(body, "entries"):
            rule = item.get("rule")
            if not isinstance(rule, dict):
                continue
            tracker = rule.get("tracker")
            if rule.get("readonly") or _SYSTEM_TRACKER.match(str(tracker or "")):
                continue
            key = rule.get("id") or tracker
            if key in seen:
                continue
            seen.add(key)
            entry = dict(rule)
            entry["tracker"] = _int_if_digits(tracker)
            entry["interface"] = ident
            entry["interface_name"] = rule.get("interface")
            entry["disabled"] = bool(rule.get("disabled"))
            entry["associated_rule_id"] = rule.get("associated_rule_id") or None
            out.append(entry)
    return out


def _nat_rule(rule: dict) -> dict:
    entry = dict(rule)
    created = rule.get("created") if isinstance(rule.get("created"), dict) else {}
    entry["created_time"] = _int_if_digits(created.get("time"))
    entry["disabled"] = bool(rule.get("disabled"))
    entry["associated_rule_id"] = rule.get("associated_rule_id") or None
    return entry


def nat_port_forwards(body: Any) -> list[dict]:
    """``/firewall/nat/port-forward`` ``rules[].rule``. LIVE-CHECK: none on the box."""
    return [
        _nat_rule(item["rule"])
        for item in _items(body, "rules")
        if isinstance(item.get("rule"), dict)
    ]


def nat_outbound(body: Any) -> list[dict]:
    """``/firewall/nat/outbound`` manual ``rules`` (automatic ones are skipped)."""
    return [_nat_rule(rule) for rule in _items(body, "rules")]


# ---------------------------------------------------------------------- carp


def carp_enabled(body: Any) -> bool:
    """``/services/carp/status``: enabled and not in maintenance mode."""
    if not isinstance(body, dict):
        return False
    return bool(body.get("enabled")) and not body.get("maintenancemode_enabled")


def carp_interfaces(vips: Any, carp_status: Any) -> list[dict]:
    """CARP VIPs from ``/firewall/virtualip`` with status from ``/services/carp/status``.

    LIVE-CHECK: no CARP VIPs on the test box. Status is matched on the VIP
    address; ``status`` is upper-cased so ``"MASTER"`` compares as pfrest's.
    """
    status_by_addr = {}
    for vip in _items(carp_status, "vips"):
        addr = str(vip.get("virtual_ip") or "").split("/", 1)[0]
        if addr:
            status_by_addr[addr] = vip.get("status")
    out = []
    for vip in _items(vips, "virtualips"):
        if vip.get("mode") != "carp":
            continue
        entry = {
            k: v for k, v in vip.items() if k not in ("password", "password_confirm")
        }
        address, _, bits = str(vip.get("subnet") or "").partition("/")
        status = status_by_addr.get(address)
        entry.update(
            {
                "subnet": address or None,
                "subnet_bits": _int_if_digits(bits or vip.get("subnet_bits")),
                "type": vip.get("type") or "single",
                "status": str(status).upper() if status else None,
            }
        )
        out.append(entry)
    return out


def firmware_update_info(body: Any) -> dict | None:
    """``/system/update`` → the ``{"base": {...}}`` shape ``update.py`` reads.

    ``version`` is the latest base system and ``installed_version`` the
    running one (both like ``"26.07"``). ``None`` when the box reports no
    versions at all.
    """
    if not isinstance(body, dict):
        return None
    installed = body.get("curr_base_system") or None
    latest = body.get("latest_base_system") or None
    if installed is None and latest is None:
        return None
    return {
        "base": {
            "installed_version": installed,
            "version": latest,
            "status_message": body.get("status_message") or None,
            "check_error": body.get("update_check_error") or None,
            "firmware_branch": body.get("firmware_branch") or None,
            "boot_env": body.get("boot_env") or None,
        }
    }


def _ewma(samples: list[float], minutes: int) -> float:
    alpha = 1 - math.exp(-1 / minutes)
    value = samples[0]
    for sample in samples[1:]:
        value += alpha * (sample - value)
    return value


def load_average(stats: Any) -> dict | None:
    """Load averages from ``/controller/stats`` ``cpu_load``.

    ``cpu_load`` is the last 60 one-minute load averages times 100, oldest first.
    The newest is the 1-minute value. The box keeps no 5/15-minute series,
    so those are exponential averages of the samples (the kernel's decay).
    On a live 26.07 box they were within ~0.03 of ``sysctl vm.loadavg``.
    """
    raw = stats.get("cpu_load") if isinstance(stats, dict) else None
    samples = [v / 100 for v in raw or [] if isinstance(v, (int, float))]
    if not samples:
        return None
    return {
        "one_minute": round(samples[-1], 2),
        "five_minute": round(_ewma(samples, 5), 2),
        "fifteen_minute": round(_ewma(samples, 15), 2),
    }


def installed_packages(body: Any) -> list[dict]:
    """``/system/package/installed`` → one dict per add-on package.

    Without ``remote_check`` (a 15 s repository query) ``update_available``
    and ``available_version`` stay empty, but ``version`` already holds the
    latest version from pfSense's cached catalog, so an update is
    ``version != installed_version``.
    """
    out = []
    for pkg in _items(body, "packages"):
        name = pkg.get("internal_name") or pkg.get("name")
        installed = pkg.get("installed_version") or None
        if not name or not installed:
            continue
        latest = pkg.get("available_version") or pkg.get("version") or installed
        out.append(
            {
                "name": name,
                "package": pkg.get("name") or name,
                "descr": pkg.get("descr") or None,
                "category": pkg.get("category") or None,
                "installed_version": installed,
                "latest_version": latest,
                "update_available": bool(pkg.get("update_available"))
                or latest != installed,
            }
        )
    return out


def dyndns_entries(body: Any) -> list[dict]:
    """``/services/dyndns`` → entries without credentials.

    ``username``/``password`` (and API tokens in ``updateurl``) are never
    copied. The API's own ``status``/``ip`` fields are empty on 26.07, so the
    last update comes from pfSense's cache files (:func:`dyndns_cache_file`).
    """
    out = []
    for entry in _items(body, "dyndnses"):
        if entry.get("id") in (None, "") or not entry.get("type"):
            continue
        host = str(entry.get("host") or "")
        domain = str(entry.get("domainname") or "")
        out.append(
            {
                "id": str(entry["id"]),
                "type": entry["type"],
                "interface": entry.get("interface") or None,
                "hostname": f"{host}.{domain}" if domain else host,
                "description": entry.get("descr") or None,
                "enabled": bool(entry.get("enable")),
            }
        )
    return out


def dyndns_cache_file(entry: dict) -> str:
    """PfSense's cache path for an entry: ``dyndns_<if><type>'<host>'<id>.cache``.

    The host is wrapped in quotes because pfSense builds the name with
    ``escapeshellarg`` (``dyndns.class``); the IPv6 cache is the same name
    ending ``<id>_v6.cache``, written by the ``*-v6`` provider types.
    """
    return (
        f"/conf/dyndns_{entry['interface'] or ''}{entry['type']}"
        f"'{entry['hostname']}'{entry['id']}.cache"
    )


def parse_dyndns_cache(text: str) -> tuple[str | None, int | None]:
    """``"<ip>|<unix time>"`` → ``(ip, time)``; ``(None, None)`` if empty."""
    ip, _, stamp = (text or "").strip().partition("|")
    ip = ip.strip() or None
    try:
        when = int(stamp.strip()) if stamp.strip() else None
    except ValueError:
        when = None
    return ip, when


# ntpq's tally codes as pfSense labels them; these two mean "selected".
_NTP_SELECTED = {"Active Peer", "PPS Peer"}


def _ntp_float(value: Any) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _ntp_int(value: Any) -> int | None:
    number = _ntp_float(value)
    return int(number) if number is not None else None


def ntp_status(body: Any) -> dict:
    """``/services/ntp/status`` → sync state and the selected peer.

    Times are milliseconds, as ntpq prints them. ``peer`` is ``None`` while
    nothing is selected (just started, or every source unreachable).
    """
    data = body if isinstance(body, dict) else {}
    peers = [
        {
            "server": p.get("server") or None,
            "status": p.get("status") or None,
            "refid": p.get("refid") or None,
            "stratum": _ntp_int(p.get("stratum")),
            "offset_ms": _ntp_float(p.get("offset")),
            "delay_ms": _ntp_float(p.get("delay")),
            "jitter_ms": _ntp_float(p.get("jitter")),
            "reach": p.get("reach") or None,
        }
        for p in _items(data, "servers")
        if p.get("refid") != ".POOL."
    ]
    peer = next((p for p in peers if p["status"] in _NTP_SELECTED), None)
    return {
        "enabled": bool(data.get("enabled")),
        "synchronized": peer is not None,
        "peer": peer,
        "offset_ms": peer["offset_ms"] if peer else None,
        "stratum": peer["stratum"] if peer else None,
        "peers": peers,
    }


def _cert_time(value: Any) -> str | None:
    """``"2027-01-18 09:17:33 +0000 UTC"`` → ISO 8601, or ``None``."""
    text = str(value or "").strip().removesuffix(" UTC").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S %z").isoformat()
    except ValueError:
        return None


def certificates(body: Any) -> list[dict]:
    """``/system/certificates`` → in-use and server certificates, safe fields only.

    The API returns each certificate's private key (``prv``), CSR and body;
    none of that is copied. Client/user certificates (VPN users and the like)
    are skipped. ``in_use`` is pfSense's usage label (e.g. "DNS Resolver").
    """
    out = []
    for cert in _items(body, "certs"):
        in_use = cert.get("inuse") or None
        if not cert.get("refid") or not (in_use or cert.get("type") == "server"):
            continue
        expires = _cert_time(cert.get("ends"))
        if expires is None:
            continue
        out.append(
            {
                "refid": cert["refid"],
                "name": cert.get("descr") or cert["refid"],
                "type": cert.get("type") or None,
                "in_use": in_use,
                "starts": _cert_time(cert.get("starts")),
                "expires": expires,
                "issuer": cert.get("issuer") or None,
                "can_renew": bool(cert.get("can_renew")),
            }
        )
    return out


def boot_environments(body: Any) -> list[dict]:
    """``/system/bootenv`` → boot environments, newest first.

    ``envs`` is keyed by name. ``creation`` is a unix time as a string,
    ``used`` bytes as a string, and ``descr`` is ``"-"`` when unset.
    """
    envs = body.get("envs") if isinstance(body, dict) else None
    out = []
    for key, env in (envs or {}).items() if isinstance(envs, dict) else []:
        if not isinstance(env, dict):
            continue
        try:
            created = datetime.fromtimestamp(int(env.get("creation")), UTC).isoformat()
        except (TypeError, ValueError):
            created = None
        try:
            used = int(env.get("used"))
        except (TypeError, ValueError):
            used = None
        descr = env.get("descr")
        out.append(
            {
                "name": env.get("name") or key,
                "version": env.get("version") or None,
                "active": bool(env.get("active")),
                "next_boot": bool(env.get("nextboot")),
                "created": created,
                "last_booted": env.get("lastbooted_nice") or None,
                "used_bytes": used,
                "protected": bool(env.get("protect")),
                "description": descr if descr and descr != "-" else None,
                "failed": bool(env.get("failed")),
            }
        )
    out.sort(key=lambda e: e["created"] or "", reverse=True)
    return out


# -------------------------------------------------------- DNS resolver / schedules


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def dns_resolver_status(body: Any) -> list[dict]:
    """``/services/dnsresolver/status`` → one row per upstream server.

    ``speed`` (Unbound's infra cache: smoothed RTT, ping, variance, RTO and
    timeouts, in ms) and ``stats`` (lameness flags) are merged by server.
    The server is ``<address>@<port>`` (853 for DNS over TLS).
    """
    data = body if isinstance(body, dict) else {}
    lame: dict[str, int] = {}
    for row in _items(data, "stats"):
        lame[str(row.get("server"))] = sum(
            int(_num(row.get(k)) or 0)
            for k in ("lame_dnssec", "lame_rec", "lame_a", "lame_other")
        )
    out = []
    for row in _items(data, "speed"):
        server = str(row.get("server") or "")
        if not server:
            continue
        address, _, port = server.rpartition("@") if "@" in server else (server, "", "")
        timeouts = {
            k: int(_num(row.get(f"timeout_{k}")) or 0) for k in ("a", "aaaa", "other")
        }
        out.append(
            {
                "server": server,
                "address": address,
                "port": int(port) if port.isdigit() else None,
                "zone": row.get("zone") or None,
                "rtt_ms": _num(row.get("rtt")),
                "ping_ms": _num(row.get("ping")),
                "variance_ms": _num(row.get("var")),
                "rto_ms": _num(row.get("rto")),
                "timeouts": sum(timeouts.values()),
                "timeouts_a": timeouts["a"],
                "timeouts_aaaa": timeouts["aaaa"],
                "timeouts_other": timeouts["other"],
                "lame": lame.get(server, 0),
                "expired": bool(row.get("expired")),
            }
        )
    return out


def _hhmm(text: str) -> int | None:
    hours, _, minutes = text.strip().partition(":")
    if not (hours.isdigit() and minutes.isdigit()):
        return None
    return int(hours) * 60 + int(minutes)


def _ints(text: Any) -> list[int]:
    return [int(p) for p in str(text or "").split(",") if p.strip().isdigit()]


def schedules(body: Any) -> list[dict]:
    """``/firewall/schedules`` → schedules with parsed time ranges.

    Each range is weekly (``position``: ISO weekdays, 1 = Monday) or on
    specific dates (parallel ``month``/``day`` lists), with ``hour``
    ``"HH:MM-HH:MM"``.
    """
    out = []
    for sched in _items(body, "schedules"):
        if not sched.get("name"):
            continue
        ranges = []
        for tr in sched.get("timerange") or []:
            if not isinstance(tr, dict):
                continue
            start_text, _, end_text = str(tr.get("hour") or "").partition("-")
            start, end = _hhmm(start_text), _hhmm(end_text)
            if start is None or end is None:
                continue
            months, days = _ints(tr.get("month")), _ints(tr.get("day"))
            ranges.append(
                {
                    "weekdays": _ints(tr.get("position")) or None,
                    "dates": list(zip(months, days, strict=False)) or None,
                    "start": start,
                    "end": end,
                    "hours": f"{start_text.strip()}-{end_text.strip()}",
                    "description": tr.get("rangedescr") or None,
                }
            )
        out.append(
            {
                "name": sched["name"],
                "description": sched.get("descr") or None,
                "ranges": ranges,
            }
        )
    return out


def schedule_active(schedule: dict, now: datetime) -> bool:
    """Whether ``schedule`` is active at ``now`` (the firewall's local time).

    Minute resolution, with the end minute included: pfSense treats
    ``00:00-23:59`` as the whole day.
    """
    minute = now.hour * 60 + now.minute
    for rng in schedule.get("ranges") or []:
        if rng["dates"]:
            if (now.month, now.day) not in {tuple(d) for d in rng["dates"]}:
                continue
        elif rng["weekdays"]:
            if now.isoweekday() not in rng["weekdays"]:
                continue
        else:
            continue
        if rng["start"] <= minute <= rng["end"]:
            return True
    return False


# ------------------------------------------------------------------ pf tables

PF_TABLE_ENTRIES_KEPT = 50


def pf_table(body: Any) -> dict | None:
    """``/diag/tables/{name}`` → count plus the first entries.

    Only ``PF_TABLE_ENTRIES_KEPT`` entries are kept: bogons alone has
    ~3,000, and the state is written to disk and diagnostics.
    """
    data = body if isinstance(body, dict) else {}
    name = data.get("table_name")
    if not name:
        return None
    entries = [str(e) for e in data.get("entries") or [] if e not in (None, "")]
    return {
        "name": name,
        "count": len(entries),
        "entries": entries[:PF_TABLE_ENTRIES_KEPT],
        "truncated": len(entries) > PF_TABLE_ENTRIES_KEPT,
        "last_update": data.get("last_update") or None,
        "action": data.get("avail_action") or None,
    }
