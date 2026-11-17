"""The interface every pfSense API backend implements.

The integration (coordinator, entities, services, config flow) talks to a
backend only through these methods, and the poll-state dict it builds from
them is the contract the entity platforms read (see CLAUDE.md, "Consumer
contracts"). A backend's job is to fill those return shapes from whatever its
API exposes:

- :class:`~.pfrest.PfRestClient` — the community REST API package
  (pfSense-pkg-RESTAPI v2, ``/api/v2``). End-of-life once PHP leaves pfSense.
- :class:`~.netgate.NetgateClient` — Netgate's official API served by the
  Nexus controller (``/api``). Feature-complete; mapping to these shapes lives
  in ``netgate_map.py``.

Return shapes are documented on the pfrest implementation. A backend that
cannot do something raises ``PfSenseUnsupportedError``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

BACKEND_PFREST = "pfrest"
BACKEND_NETGATE = "netgate"
BACKENDS = (BACKEND_PFREST, BACKEND_NETGATE)


@runtime_checkable
class PfSenseBackend(Protocol):
    """Async pfSense client surface consumed by the integration."""

    # identity
    async def get_system_info(self) -> dict:
        """Return hostname, domain, serial, netgate_device_id and platform."""

    async def get_host_firmware_version(self) -> dict:
        """Return ``{"platform", "firmware": {"version"}, "base", "patch", ...}``."""

    async def get_firmware_update_info(self) -> dict | None:
        """Return base-system update info, or ``None`` when unavailable."""

    async def start_firmware_update(self) -> None:
        """Start a base-system upgrade (the firewall reboots during it)."""

    async def get_dns_servers(self) -> list[str]:
        """Return the configured system DNS servers."""

    # telemetry
    async def get_telemetry(self) -> dict:
        """Return the nested legacy ``telemetry`` dict the sensors read."""

    # services
    async def get_services(self) -> list[dict]:
        """Return the pfSense services and their status."""

    async def start_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Start a service by name."""

    async def stop_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Stop a service by name."""

    async def restart_service(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Restart a service by name."""

    async def restart_service_if_running(
        self, service_name: str, service: dict | None = None
    ) -> None:
        """Restart a service only if it is currently running."""

    # dhcp / arp
    async def get_dhcp_leases(self, dns_lookups=None) -> list[dict]:
        """Return the current DHCP leases."""

    async def get_arp_table(self, resolve_hostnames: bool = False) -> list[dict]:
        """Return the ARP table entries."""

    async def delete_arp_entry(self, ip: str) -> None:
        """Delete the ARP entry for an IP address."""

    # gateways
    async def get_gateways_detail(self) -> dict:
        """Return config-side gateway data keyed by gateway name."""

    async def set_default_gateway(self, gateway: str, ip_version: str = "4") -> None:
        """Set the default IPv4/IPv6 gateway and apply."""

    # firewall / nat rules
    async def get_filter_rules(self) -> list[dict]:
        """Return the firewall filter rules."""

    async def get_nat_port_forward_rules(self) -> list[dict]:
        """Return the NAT port-forward rules."""

    async def get_nat_outbound_rules(self) -> list[dict]:
        """Return the NAT outbound mappings."""

    async def enable_filter_rule_by_tracker(self, tracker) -> None:
        """Enable the firewall rule with the given tracker id."""

    async def disable_filter_rule_by_tracker(self, tracker) -> None:
        """Disable the firewall rule with the given tracker id."""

    async def enable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        """Enable the NAT port-forward rule with the given created time."""

    async def disable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        """Disable the NAT port-forward rule with the given created time."""

    async def enable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        """Enable the NAT outbound mapping with the given created time."""

    async def disable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        """Disable the NAT outbound mapping with the given created time."""

    # aliases
    async def update_alias_address(
        self,
        alias_name: str,
        address: str,
        action: str = "add",
        kill_states: bool = True,
    ) -> None:
        """Add or remove an address in a firewall alias and apply."""

    # carp
    async def get_carp_status(self) -> bool:
        """Return True when CARP is enabled and not in maintenance mode."""

    async def get_carp_interfaces(self) -> list[dict]:
        """Return the CARP virtual IPs with their status."""

    # state table
    async def reset_state_table(self) -> None:
        """Flush the entire firewall state table."""

    async def kill_states(self, source: str, destination: str | None = None) -> None:
        """Kill states for a source (and optional destination)."""

    async def kill_states_for_rule(self, rule: dict) -> None:
        """Drop state-table entries for the hosts/networks a rule matches."""

    # system control
    async def system_reboot(self, type: str = "normal") -> None:
        """Reboot the firewall."""

    async def system_halt(self) -> None:
        """Halt (power off) the firewall."""

    # misc
    async def send_wol(self, interface: str, mac: str) -> None:
        """Send a Wake-on-LAN magic packet on an interface."""

    async def exec_command(self, command: str, background: bool = False) -> str:
        """Run a shell command on the firewall and return its output."""
