#!/usr/bin/env python3
"""Turn raw API captures from a live pfSense box into redacted test fixtures.

This repository is public. Raw captures contain a home network's layout,
hostnames, people's names (in rule/alias descriptions), public IPs, MACs,
serial numbers and keys. This script produces fixtures that keep the *shape*
and the cross-file relationships the tests need, and nothing identifying.

Usage::

    python3 -I scripts/redact_fixtures.py RAW_DIR OUT_DIR [--max-items 4]
        [--deny-file PATH]

RAW_DIR holds one ``<name>.json`` per endpoint, each ``{"status", "body"}``
(the format written by the read-only capture probe). OUT_DIR receives
``<name>.json`` containing just the redacted body.

What it does, with one mapping shared across all files (so a DHCP lease's
hostname and the same host's ARP ``dnsresolve`` get the same placeholder, and
a rule's ``source`` still names the alias defined in ``aliases.json``):

- Trims every list to ``--max-items`` entries, plus up to 3 "interesting"
  ones (``disabled`` / ``readonly`` / ``update_available`` true) so edge cases
  survive. Large dicts of same-shaped values (alias tables) are trimmed too.
- Replaces values of identifying keys (serial, ``ndi``, keys, hostnames,
  descriptions, DHCP client ids, ...) with stable placeholders.
- Replaces user alias names and every collected identifying string wherever
  it appears inside any other string (``label: "descr=..."`` etc).
- Maps IPv4 addresses per /24 (last octet kept, so subnet relationships hold;
  private -> 10.200.x, public -> TEST-NET ranges); leaves netmasks alone. Maps
  IPv6 into 2001:db8::/32, MACs into 02:00:5e:..., UUIDs, long hex and
  base64-ish tokens into placeholders.

Then it refuses to write anything if (a) any original identifying value it
collected, or (b) any term in ``--deny-file`` (one per line, case-insensitive;
keep that file OUTSIDE the repo) still appears in the output.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys

# Keys whose string values identify the box, its owner, or devices on it.
TOKEN_KEYS = {
    "serial": "SERIAL",
    "ndi": "NDI",
    "device_id": "DEVICEID",
    "hw_uuid": "UUID",
    "crypto_id": "CRYPTOID",
    "pubkey": "PUBKEY",
    "vpn_pubkey": "PUBKEY",
    "public_key": "PUBKEY",
    "license": "LICENSE",
    "my_hostid": "HOSTID",
    "state_sync_hostids": "HOSTID",
    "cid": "CLIENTID",
    "duid": "DUID",
    "iaid": "IAID",
}
HOST_KEYS = {"host", "hostname", "dnsresolve", "name_server"}
DESCR_KEYS = {"descr", "description", "login_message", "detail"}
DOMAIN_KEYS = {"domain"}
# Descriptions that are pfSense's own wording and safe (and useful) to keep.
GENERIC_DESCR = re.compile(
    r"^(|_\w+_|Auto created rule.*|anti-lockout rule|Anti-Lockout Rule|Default .*"
    r"|.*(Daemon|Server|Service|Resolver|Logger|sync|Balancer|daemon|Controller).*)$"
)
INTERESTING = ("disabled", "readonly", "update_available")
# Product/role words that show up as host names but identify nobody.
GENERIC_WORDS = {"pfsense", "localhost", "firewall", "router", "gateway"}

# Hardware serials embedded in free text, e.g. SFP "vendor": "... SN: CSC24... DATE".
SERIAL_IN_TEXT_RE = re.compile(r"(\bSN:\s*)(\S+)")
MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
LONGHEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")
B64_RE = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")
V6_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?:/\d{1,3})?")


class Redactor:
    """Holds the shared original -> placeholder mappings."""

    def __init__(self, max_items: int) -> None:
        """Start with empty mappings; ``max_items`` caps every list."""
        self.max_items = max_items
        self.tokens: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        self.net4: dict[tuple[str, str, str], str] = {}
        self.originals: set[str] = set()  # for the post-redaction leak check
        self.substrings: dict[str, str] = {}  # original -> placeholder, in-string

    # ---------------------------------------------------------------- tokens
    def token(self, kind: str, original: str, *, track: bool = True) -> str:
        """Return the stable placeholder for ``original`` (e.g. ``host-3``)."""
        key = f"{kind}\0{original}"
        if key not in self.tokens:
            n = self.counters.get(kind, 0) + 1
            self.counters[kind] = n
            self.tokens[key] = f"{kind.lower()}-{n}"
        if track and len(original) >= 4:
            self.originals.add(original)
        return self.tokens[key]

    def register_substring(self, kind: str, original: str) -> str | None:
        """Tokenize ``original`` and also replace it wherever it appears in text."""
        if original.lower() in GENERIC_WORDS:
            return None
        placeholder = self.token(kind, original)
        if len(original) >= 3:
            self.substrings[original] = placeholder
        return placeholder

    # ------------------------------------------------------------ collection
    def collect(self, node, key: str | None = None) -> None:
        """First pass: learn every identifying string before rewriting any."""
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "name" and isinstance(v, str) and _looks_user_alias(node):
                    self.register_substring("ALIAS", v)
                self.collect(v, k)
        elif isinstance(node, list):
            for v in node:
                if key == "schedules" and isinstance(v, dict) and v.get("name"):
                    # Firewall schedule names describe the household's routine.
                    self.register_substring("SCHED", v["name"])
                self.collect(v, key)
        elif isinstance(node, str) and node:
            if key in HOST_KEYS and node not in ("?", ""):
                host = node.strip("?")
                if host:
                    short = host.split(".")[0]
                    self.register_substring("HOST", host)
                    if short != host:
                        self.register_substring("HOST", short)
                    if "." in host:
                        self.register_substring("DOMAIN", host.split(".", 1)[1])
            elif key in DOMAIN_KEYS:
                self.register_substring("DOMAIN", node)
            elif key in DESCR_KEYS and not GENERIC_DESCR.match(node):
                if _free_text(node):
                    self.register_substring("DESCR", node)
                else:
                    # Single short words ("Monitor", "PPPoe") are mostly
                    # pfSense's own labels and collide with field names, so
                    # only replace them as values (see rewrite_str); personal
                    # one-word names are caught by the --deny-file check.
                    self.token("DESCR", node, track=False)
            elif key in TOKEN_KEYS:
                self.token(TOKEN_KEYS[key], node)

    # --------------------------------------------------------------- rewrite
    def rewrite(self, node, key: str | None = None):
        """Second pass: return a trimmed, redacted copy of ``node``."""
        if isinstance(node, dict):
            items = list(node.items())
            if _is_table(node) and len(items) > self.max_items * 2:
                items = items[: self.max_items]
            return {k: self.rewrite(v, k) for k, v in items}
        if isinstance(node, list):
            return [self.rewrite(v, key) for v in self._trim(node)]
        if isinstance(node, str):
            return self.rewrite_str(node, key)
        return node

    def _trim(self, items: list) -> list:
        if len(items) <= self.max_items:
            return items
        kept = items[: self.max_items]
        extra = [i for i in items[self.max_items :] if _interesting(i)][:3]
        return kept + extra

    def rewrite_str(self, value: str, key: str | None) -> str:
        """Redact one string value; ``key`` is the dict key it sits under."""
        if not value:
            return value
        if key in TOKEN_KEYS:
            return self.token(TOKEN_KEYS[key], value)
        if key in DESCR_KEYS and not GENERIC_DESCR.match(value):
            return self.token("DESCR", value, track=_free_text(value))
        if key == "label" and value.startswith("descr="):
            inner = value[len("descr=") :]
            if inner and not GENERIC_DESCR.match(inner):
                return "descr=" + self.token("DESCR", inner, track=_free_text(inner))
        out = value
        for original in sorted(self.substrings, key=len, reverse=True):
            if original in out:
                # Whole words only: alias "NAS" must not turn "NASNET" into
                # "alias-2NET".
                out = re.sub(
                    rf"(?<![A-Za-z0-9_]){re.escape(original)}(?![A-Za-z0-9_])",
                    self.substrings[original],
                    out,
                )
        out = SERIAL_IN_TEXT_RE.sub(
            lambda m: m.group(1) + self.token("SERIAL", m.group(2)), out
        )
        out = MAC_RE.sub(lambda m: self._mac(m.group(0)), out)
        out = UUID_RE.sub(lambda m: self.token("UUID", m.group(0)), out)
        out = IPV4_RE.sub(self._ipv4, out)
        out = V6_CANDIDATE_RE.sub(self._ipv6, out)
        out = LONGHEX_RE.sub(lambda m: self.token("HEX", m.group(0)), out)
        return B64_RE.sub(self._b64, out)

    def _mac(self, mac: str) -> str:
        self.originals.add(mac.lower())
        n = int(self.token("MAC", mac.lower()).split("-")[1])
        return f"02:00:5e:{(n >> 16) & 255:02x}:{(n >> 8) & 255:02x}:{n & 255:02x}"

    def _ipv4(self, m: re.Match) -> str:
        octets = m.groups()
        if any(int(o) > 255 or (len(o) > 1 and o[0] == "0") for o in octets):
            return m.group(0)  # not an address, e.g. firmware "03.00.00.03"
        addr = ipaddress.IPv4Address(m.group(0))
        if octets[0] in ("255", "0") or addr.is_loopback or addr.is_multicast:
            return m.group(0)  # netmasks, 0.0.0.0, loopback, multicast
        net = octets[:3]
        if net not in self.net4:
            n = len(self.net4) + 1
            if addr.is_private:
                self.net4[net] = f"10.200.{n}"
            else:
                pool = ("203.0.113", "198.51.100", "192.0.2")
                self.net4[net] = pool[(n - 1) % 3] if n <= 3 else f"10.250.{n}"
        if not addr.is_private:
            self.originals.add(m.group(0))
        return f"{self.net4[net]}.{octets[3]}"

    def _ipv6(self, m: re.Match) -> str:
        text = m.group(0)
        addr_part = text.split("/")[0]
        try:
            addr = ipaddress.IPv6Address(addr_part)
        except ValueError:
            return text  # e.g. "03:58:02"
        if addr.is_loopback or addr == ipaddress.IPv6Address("::"):
            return text
        self.originals.add(addr_part.lower())
        n = int(self.token("V6", addr.exploded).split("-")[1])
        suffix = text[len(addr_part) :]
        return f"2001:db8::{n:x}{suffix}"

    def _b64(self, m: re.Match) -> str:
        text = m.group(0)
        # Only obvious key/token material: mixed case + digit, or padded.
        if text.endswith("=") or (
            re.search(r"[a-z]", text)
            and re.search(r"[A-Z]", text)
            and re.search(r"\d", text)
        ):
            return self.token("KEY", text)
        return text


def _free_text(value: str) -> bool:
    """Multi-word or long text: safe and necessary to replace inside strings."""
    return " " in value.strip() or len(value) >= 12


def _looks_user_alias(node: dict) -> bool:
    """A firewall alias definition the user created (not ``sys:``/``_x_``)."""
    name = node.get("name")
    if not isinstance(name, str) or name.startswith(("_", "sys:")):
        return False
    if "if_ident" in node or "table" in node:  # FWSystemAlias: interface nets etc.
        return False
    return "address" in node and ("targets" in node or "detail" in node)


def _is_table(node: dict) -> bool:
    """A dict used as a keyed table of same-shaped dict values (e.g. aliases)."""
    values = list(node.values())
    return len(values) > 2 and all(isinstance(v, dict) for v in values)


def _interesting(item) -> bool:
    if isinstance(item, dict):
        if any(item.get(k) is True for k in INTERESTING):
            return True
        return any(_interesting(v) for v in item.values() if isinstance(v, dict))
    return False


def main() -> int:
    """Redact RAW_DIR into OUT_DIR; exit 1 (writing nothing) on any leak."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("raw_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--max-items", type=int, default=4)
    parser.add_argument("--deny-file", type=Path)
    args = parser.parse_args()

    raws = {
        p.stem: json.loads(p.read_text())["body"]
        for p in sorted(args.raw_dir.glob("*.json"))
    }
    if not raws:
        print(f"no *.json in {args.raw_dir}", file=sys.stderr)
        return 2

    red = Redactor(args.max_items)
    for body in raws.values():
        red.collect(body)
    out = {name: red.rewrite(body) for name, body in raws.items()}

    deny = []
    if args.deny_file:
        deny = [
            t.strip().lower()
            for t in args.deny_file.read_text().splitlines()
            if t.strip()
        ]

    problems = []
    for name, body in out.items():
        text = json.dumps(body).lower()
        for original in red.originals:
            # Whole-token match: "Monitor" must not trip on "Monitoring".
            if re.search(rf"(?<![\w-]){re.escape(original.lower())}(?![\w-])", text):
                problems.append(f"{name}: an original identifying value survived")
                break
        problems.extend(f"{name}: deny-list term present" for t in deny if t in text)
    if problems:
        # Never print the offending value itself.
        print(
            "REFUSING to write fixtures:",
            *sorted(set(problems)),
            sep="\n  ",
            file=sys.stderr,
        )
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, body in out.items():
        (args.out_dir / f"{name}.json").write_text(
            json.dumps(body, indent=1, sort_keys=True) + "\n"
        )
    total = sum((args.out_dir / f"{n}.json").stat().st_size for n in out)
    print(
        f"wrote {len(out)} fixtures to {args.out_dir} ({total} bytes); "
        f"{len(red.originals)} identifying values replaced"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
