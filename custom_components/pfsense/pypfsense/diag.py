"""Parse the text output of pfSense's diagnostics (ping, traceroute, DNS).

The Netgate API returns ping and traceroute as the commands' own text;
these turn it into data an automation can use. The raw text is kept too.
"""

from __future__ import annotations

import re
from typing import Any

_PING_SUMMARY = re.compile(
    r"(\d+) packets transmitted, (\d+) packets received, ([\d.]+)% packet loss"
)
_PING_RTT = re.compile(
    r"round-trip min/avg/max/stddev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms"
)
_HOP = re.compile(r"^\s*(\d+)\s+(.*)$")
_REPLY = re.compile(r"(\S+)\s+((?:[\d.]+\s+ms\s*)+)")
_RTT = re.compile(r"([\d.]+)\s+ms")
_DNS_MS = re.compile(r"(\d+(?:\.\d+)?)\s*msec")


def parse_ping(host: str, output: str) -> dict:
    """``ping`` text → counts, loss and round-trip times (ms)."""
    text = output or ""
    summary = _PING_SUMMARY.search(text)
    rtt = _PING_RTT.search(text)
    sent, received, loss = (
        (int(summary.group(1)), int(summary.group(2)), float(summary.group(3)))
        if summary
        else (None, None, None)
    )
    rtt_min, rtt_avg, rtt_max, rtt_stddev = (
        (float(v) for v in rtt.groups()) if rtt else (None, None, None, None)
    )
    return {
        "host": host,
        "reachable": bool(received),
        "transmitted": sent,
        "received": received,
        "loss_percent": loss,
        "rtt_min_ms": rtt_min,
        "rtt_avg_ms": rtt_avg,
        "rtt_max_ms": rtt_max,
        "rtt_stddev_ms": rtt_stddev,
        "output": text,
    }


def parse_traceroute(host: str, output: str) -> dict:
    """``traceroute`` text → hops with each replying address and its times.

    A hop's continuation lines (other routers answering the same TTL) join
    that hop. ``*`` means no reply. ``reached`` is whether the last hop
    answered from the traced address itself.
    """
    text = output or ""
    hops: list[dict] = []
    target = None
    for line in text.splitlines():
        if line.startswith("traceroute to "):
            match = re.search(r"\(([^)]+)\)", line)
            target = match.group(1) if match else None
            continue
        hop = _HOP.match(line)
        if hop:
            hops.append({"hop": int(hop.group(1)), "replies": []})
            rest = hop.group(2)
        elif hops and line.strip():
            rest = line
        else:
            continue
        for address, times in _REPLY.findall(rest):
            hops[-1]["replies"].append(
                {"address": address, "rtt_ms": [float(t) for t in _RTT.findall(times)]}
            )
    last = hops[-1]["replies"] if hops else []
    return {
        "host": host,
        "address": target,
        "reached": any(r["address"] == target for r in last) if target else False,
        "hops": hops,
        "output": text,
    }


def parse_dns(host: str, body: Any) -> dict:
    """``/diag/dns`` → records plus each DNS server's response time (ms)."""
    data = body if isinstance(body, dict) else {}
    records = [
        {"type": r.get("type"), "data": r.get("data")}
        for r in data.get("results") or []
        if isinstance(r, dict)
    ]
    servers = []
    for timing in data.get("timings") or []:
        if not isinstance(timing, dict):
            continue
        match = _DNS_MS.search(str(timing.get("time") or ""))
        servers.append(
            {
                "server": timing.get("server"),
                "time_ms": float(match.group(1)) if match else None,
            }
        )
    return {
        "host": host,
        "resolved": bool(records),
        "records": records,
        "servers": servers,
    }
