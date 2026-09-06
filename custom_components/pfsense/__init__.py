"""Support for pfSense REST API"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import copy
from datetime import timedelta
import logging
import re
import time

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_SCAN_INTERVAL, CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import (
    CONF_API_KEY,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_TLS_INSECURE,
    COORDINATOR,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TLS_INSECURE,
    DEFAULT_VERIFY_SSL,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    LOADED_PLATFORMS,
    PFSENSE_CLIENT,
    PLATFORMS,
    SHOULD_RELOAD,
    UNDO_UPDATE_LISTENER,
)
from .pypfsense import Client as pfSenseClient, PfSenseAuthError, PfSensePrivilegeError
from .services import ServiceRegistrar

_LOGGER = logging.getLogger(__name__)

# --- SMART CACHE LOGIC ---
STORAGE_VERSION = 1


async def async_save_cache(hass: HomeAssistant, entry_id: str, data: dict):
    """Save state to local cache."""
    store = Store(hass, STORAGE_VERSION, f"{DOMAIN}_{entry_id}_cache")
    try:
        await store.async_save(data)
    except (OSError, HomeAssistantError, ValueError) as err:
        _LOGGER.error("Failed to save pfSense cache: %s", err)


async def async_load_cache(hass: HomeAssistant, entry_id: str):
    """Load state from local cache."""
    store = Store(hass, STORAGE_VERSION, f"{DOMAIN}_{entry_id}_cache")
    try:
        return await store.async_load()
    except (OSError, HomeAssistantError, ValueError) as err:
        _LOGGER.error("Failed to load pfSense cache: %s", err)
        return None


# -------------------------


def dict_get(data: dict, path: str, default=None):
    """Traverse a nested dict/list by a dotted path; numeric segments index lists."""
    result = data
    try:
        for key in re.split(r"\.", path, flags=re.IGNORECASE):
            key = int(key) if key.isnumeric() else key
            result = result[key]
    except (KeyError, IndexError, TypeError):
        return default
    return result


_INTERFACE_RATE_PROPS = (
    "inbytes",
    "outbytes",
    "inbytespass",
    "outbytespass",
    "inpkts",
    "outpkts",
    "inpktspass",
    "outpktspass",
)


def _compute_interface_rates(new_state, elapsed_time, scan_interval):
    interfaces = dict_get(new_state, "telemetry.interfaces", {})
    for interface_name, interface in interfaces.items():
        previous_interface = dict_get(
            new_state, f"previous_state.telemetry.interfaces.{interface_name}"
        )
        if previous_interface is None:
            continue
        for prop in _INTERFACE_RATE_PROPS:
            current = interface.get(prop)
            previous = previous_interface.get(prop)
            if current is None or previous is None:
                continue
            rate = abs(current - previous) / elapsed_time if elapsed_time > 0 else 0
            if "pkts" in prop:
                label, value = "packets_per_second", rate
            else:
                label, value = "kilobytes_per_second", rate / 1000
            new_property = f"{prop}_{label}"
            if elapsed_time >= scan_interval:
                interface[new_property] = round(value)
            else:
                previous_value = previous_interface.get(new_property)
                interface[new_property] = round(
                    previous_value if previous_value is not None else value
                )


def _compute_openvpn_rates(new_state, elapsed_time):
    servers = dict_get(new_state, "telemetry.openvpn.servers", {})
    previous_servers = dict_get(
        new_state, "previous_state.telemetry.openvpn.servers", {}
    )
    for server_name, server in servers.items():
        previous_server = previous_servers.get(server_name)
        if previous_server is None:
            continue
        for prop in ("total_bytes_recv", "total_bytes_sent"):
            change = abs(server.get(prop, 0) - previous_server.get(prop, 0))
            rate = change / elapsed_time if elapsed_time > 0 else 0
            server[f"{prop}_kilobytes_per_second"] = round(rate / 1000)


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry):
    """Handle options update."""
    if hass.data[DOMAIN][entry.entry_id].get(SHOULD_RELOAD, True):
        hass.async_create_task(hass.config_entries.async_reload(entry.entry_id))
    else:
        hass.data[DOMAIN][entry.entry_id][SHOULD_RELOAD] = True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up pfSense from a config entry."""
    config = entry.data
    options = entry.options

    url = config[CONF_URL]
    api_key = config.get(CONF_API_KEY)
    if not api_key:
        # Migrated-from-password entry that hasn't been re-authed yet.
        raise ConfigEntryAuthFailed("no pfSense REST API key configured")
    verify_ssl = config.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
    device_tracker_enabled = options.get(
        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
    )

    session = async_get_clientsession(hass, verify_ssl)
    client = pfSenseClient(url, api_key, session, {"verify_ssl": verify_ssl})
    data = PfSenseData(client, entry, hass)
    scan_interval = options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)

    async def async_update_data():
        """Fetch data from pfSense, falling back to the on-disk cache on failure."""
        new_state = None
        try:
            async with asyncio.timeout(scan_interval - 1):
                new_state = await data.update()
        except (PfSenseAuthError, PfSensePrivilegeError) as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except Exception:
            _LOGGER.warning(
                "pfSense poll failed; trying the local cache", exc_info=True
            )
        else:
            if new_state:
                await async_save_cache(hass, entry.entry_id, new_state)
                return new_state

        cached_data = await async_load_cache(hass, entry.entry_id)
        if cached_data:
            data.restore_state(cached_data)
            return cached_data
        raise UpdateFailed("pfSense poll failed and no usable cache is available")

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"{entry.title} pfSense state",
        update_method=async_update_data,
        update_interval=timedelta(seconds=scan_interval),
    )

    platforms = PLATFORMS.copy()
    device_tracker_coordinator = None
    if not device_tracker_enabled:
        platforms.remove("device_tracker")
    else:
        device_tracker_data = PfSenseData(client, entry, hass)
        device_tracker_scan_interval = options.get(
            CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
        )

        async def async_update_device_tracker_data():
            """Fetch the ARP table from pfSense."""
            new_dt_state = None
            try:
                async with asyncio.timeout(device_tracker_scan_interval - 1):
                    new_dt_state = await device_tracker_data.update(
                        {"scope": "device_tracker"}
                    )
            except (PfSenseAuthError, PfSensePrivilegeError) as err:
                raise ConfigEntryAuthFailed(str(err)) from err
            except Exception:
                _LOGGER.warning("pfSense device tracker update failed", exc_info=True)
            else:
                if new_dt_state:
                    return new_dt_state

            if device_tracker_data.state:
                return device_tracker_data.state
            raise UpdateFailed("pfSense device tracker update failed")

        device_tracker_coordinator = DataUpdateCoordinator(
            hass,
            _LOGGER,
            name=f"{entry.title} pfSense device tracker state",
            update_method=async_update_device_tracker_data,
            update_interval=timedelta(seconds=device_tracker_scan_interval),
        )

    undo_listener = entry.add_update_listener(_async_update_listener)

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        COORDINATOR: coordinator,
        DEVICE_TRACKER_COORDINATOR: device_tracker_coordinator,
        PFSENSE_CLIENT: client,
        UNDO_UPDATE_LISTENER: [undo_listener],
        LOADED_PLATFORMS: platforms,
    }

    await coordinator.async_config_entry_first_refresh()
    if device_tracker_enabled:
        await device_tracker_coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, platforms)

    service_registar = ServiceRegistrar(hass)
    service_registar.async_register()

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    platforms = hass.data[DOMAIN][entry.entry_id][LOADED_PLATFORMS]
    unload_ok = await hass.config_entries.async_unload_platforms(entry, platforms)

    for listener in hass.data[DOMAIN][entry.entry_id][UNDO_UPDATE_LISTENER]:
        listener()

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate an old config entry.

    v1 -> v2: fold the legacy ``tls_insecure`` flag into ``verify_ssl``.
    v2 -> v3: XML-RPC username/password auth is gone. Strip the stored password
    and force a reauth so the user can enter a REST API key. The unique id
    (``slugify(netgate id)``) is unchanged, so entities re-attach afterwards.
    """
    data = dict(config_entry.data)

    if config_entry.version == 1:
        tls_insecure = data.pop(CONF_TLS_INSECURE, DEFAULT_TLS_INSECURE)
        data.setdefault(CONF_VERIFY_SSL, not tls_insecure)
        hass.config_entries.async_update_entry(config_entry, data=data, version=2)

    if config_entry.version == 2:
        for legacy_key in ("password", "username"):
            data.pop(legacy_key, None)
        hass.config_entries.async_update_entry(config_entry, data=data, version=3)
        # No API key yet: async_setup_entry raises ConfigEntryAuthFailed, which
        # starts the reauth flow so the user can paste a key.

    return True


class PfSenseData:
    def __init__(
        self, client: pfSenseClient, config_entry: ConfigEntry, hass: HomeAssistant
    ):
        """Initialize the data object."""
        self._client = client
        self._config_entry = config_entry
        self._hass = hass
        self._state = {}
        self._firmware_update_info = None

    @property
    def state(self):
        """Return the most recently fetched (or restored) poll state."""
        return self._state

    def restore_state(self, state: dict) -> None:
        """Adopt a state dict loaded from the on-disk cache."""
        self._state = state

    async def update(self, opts=None):
        """Fetch the latest state from pfSense over the REST API."""
        opts = opts or {}
        new_state = {}

        try:
            current_time = time.time()
            previous_state = copy.deepcopy(self._state)
            previous_state.pop("previous_state", None)

            new_state["update_time"] = current_time
            new_state["previous_state"] = previous_state

            if opts.get("scope") == "device_tracker":
                system_info, arp_table = await asyncio.gather(
                    self._client.get_system_info(),
                    self._client.get_arp_table(True),
                )
                new_state["system_info"] = system_info
                new_state["arp_table"] = arp_table
                self._state = new_state
                return new_state

            (
                system_info,
                host_firmware_version,
                telemetry_data,
                services,
                carp_interfaces,
                carp_status,
                dhcp_leases,
                dns_servers,
                filter_rules,
                nat_port_forwards,
                nat_outbound,
            ) = await asyncio.gather(
                self._client.get_system_info(),
                self._client.get_host_firmware_version(),
                self._client.get_telemetry(),
                self._client.get_services(),
                self._client.get_carp_interfaces(),
                self._client.get_carp_status(),
                self._client.get_dhcp_leases(),
                self._client.get_dns_servers(),
                self._client.get_filter_rules(),
                self._client.get_nat_port_forward_rules(),
                self._client.get_nat_outbound_rules(),
            )

            new_state["system_info"] = system_info
            new_state["host_firmware_version"] = host_firmware_version
            new_state["firmware_update_info"] = None
            new_state["telemetry"] = telemetry_data
            new_state["firewall_rules"] = filter_rules
            new_state["nat_port_forward_rules"] = nat_port_forwards
            new_state["nat_outbound_rules"] = nat_outbound
            new_state["dns_servers"] = dns_servers
            new_state["services"] = services
            new_state["carp_interfaces"] = carp_interfaces
            new_state["carp_status"] = carp_status
            new_state["dhcp_leases"] = dhcp_leases
            new_state["dhcp_stats"] = {}

            lease_stats = {"total": 0, "online": 0, "idle_offline": 0}
            for lease in dhcp_leases:
                if lease.get("active_status") == "expired":
                    continue
                lease_stats["total"] += 1
                online = lease.get("online_status")
                if online in ("active", "active/online", "online"):
                    lease_stats["online"] += 1
                elif online in ("offline", "idle/offline", "idle"):
                    lease_stats["idle_offline"] += 1
            new_state["dhcp_stats"]["leases"] = lease_stats

            scan_interval = self._config_entry.options.get(
                CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
            )
            previous_update_time = dict_get(new_state, "previous_state.update_time")
            if previous_update_time is not None:
                elapsed_time = current_time - previous_update_time
                _compute_interface_rates(new_state, elapsed_time, scan_interval)
                _compute_openvpn_rates(new_state, elapsed_time)

        except BaseException:
            self._state = new_state
            raise

        self._state = new_state
        return new_state


class CoordinatorEntityManager:
    """GOUDEN BUILD: Slimme Entity Manager voorkomt duplicaten!"""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: DataUpdateCoordinator,
        config_entry: ConfigEntry,
        process_entities_callback: Callable,
        async_add_entities: AddEntitiesCallback,
    ) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self.config_entry = config_entry
        self.process_entities_callback = process_entities_callback
        self.async_add_entities = async_add_entities

        # Registreer de listener netjes zonder duplicaten te riskeren
        self.hass.data[DOMAIN][config_entry.entry_id][UNDO_UPDATE_LISTENER].append(
            coordinator.async_add_listener(self.process_entities)
        )
        self.entity_unique_ids = set()

    @callback
    def process_entities(self):
        entities = self.process_entities_callback(self.hass, self.config_entry)
        new_entities = []

        for entity in entities:
            if entity.unique_id not in self.entity_unique_ids:
                new_entities.append(entity)
                self.entity_unique_ids.add(entity.unique_id)

        if new_entities:
            self.async_add_entities(new_entities)


class PfSenseEntity(CoordinatorEntity, RestoreEntity):
    """base entity for pfSense"""

    @property
    def coordinator_context(self):
        return None

    @property
    def device_info(self):
        state = self.coordinator.data
        if not state or "host_firmware_version" not in state:
            return None

        return {
            "identifiers": {(DOMAIN, self.pfsense_device_unique_id)},
            "name": self.pfsense_device_name,
            "configuration_url": self.config_entry.data.get("url", None),
            "model": state["host_firmware_version"]["platform"],
            "manufacturer": "netgate",
            "sw_version": state["host_firmware_version"]["firmware"]["version"],
        }

    @property
    def pfsense_device_name(self):
        if self.config_entry.title:
            return self.config_entry.title
        return f"{self._get_pfsense_state_value('system_info.hostname')}.{self._get_pfsense_state_value('system_info.domain')}"

    @property
    def pfsense_device_unique_id(self):
        return self._get_pfsense_state_value("system_info.netgate_device_id")

    def _get_pfsense_state_value(self, path, default=None):
        return dict_get(self.coordinator.data, path, default)

    def _get_pfsense_client(self) -> pfSenseClient:
        return self.hass.data[DOMAIN][self.config_entry.entry_id][PFSENSE_CLIENT]

    async def service_start_service(
        self, service_name: str, service: dict | str | None = None
    ):
        await self._get_pfsense_client().start_service(service_name, service)

    async def service_stop_service(
        self, service_name: str, service: dict | str | None = None
    ):
        await self._get_pfsense_client().stop_service(service_name, service)

    async def service_restart_service(
        self,
        service_name: str,
        only_if_running: int | str | bool | None = False,
        service: dict | str | None = None,
    ):
        client = self._get_pfsense_client()
        if str(only_if_running).lower() in ["true", "1"]:
            await client.restart_service_if_running(service_name, service)
        else:
            await client.restart_service(service_name, service)

    async def service_reset_state_table(self):
        await self._get_pfsense_client().reset_state_table()

    async def service_kill_states(self, source: str, destination: str | None = None):
        await self._get_pfsense_client().kill_states(source, destination)

    async def service_system_halt(self):
        await self._get_pfsense_client().system_halt()

    async def service_system_reboot(self):
        await self._get_pfsense_client().system_reboot()

    async def service_send_wol(self, interface: str, mac: str):
        await self._get_pfsense_client().send_wol(interface, mac)

    async def service_set_default_gateway(self, gateway: str, ip_version: str):
        await self._get_pfsense_client().set_default_gateway(gateway, ip_version)

    async def service_exec_command(self, command: str, background: bool = False):
        await self._get_pfsense_client().exec_command(command, background)
