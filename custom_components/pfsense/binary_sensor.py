"""pfSense integration."""

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify

from . import CoordinatorEntityManager, PfSenseEntity
from .const import COORDINATOR, DOMAIN
from .health_entity import PfSenseApiConnectedBinarySensor

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
):
    """Set up the pfSense binary sensors."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        return [
            PfSenseCarpStatusBinarySensor(
                config_entry,
                coordinator,
                BinarySensorEntityDescription(
                    key="carp.status",
                    name="CARP Status",
                    icon="mdi:gauge",
                ),
                True,
            ),
            PfSensePendingNoticesBinarySensor(
                config_entry,
                coordinator,
                BinarySensorEntityDescription(
                    key="notices.pending_notices_present",
                    name="Pending Notices Present",
                    icon="mdi:bell-alert",
                ),
                True,
            ),
            PfSenseNtpSyncBinarySensor(
                config_entry,
                coordinator,
                BinarySensorEntityDescription(
                    key="ntp.synchronized",
                    name="NTP Synchronized",
                    icon="mdi:clock-check-outline",
                ),
                True,
            ),
            PfSenseApiConnectedBinarySensor(
                config_entry,
                coordinator,
                "api_connected",
                "API Connected",
                "mdi:lan-connect",
            ),
        ]

    cem = CoordinatorEntityManager(
        hass,
        hass.data[DOMAIN][config_entry.entry_id][COORDINATOR],
        config_entry,
        process_entities_callback,
        async_add_entities,
    )
    cem.process_entities()


class PfSenseBinarySensor(PfSenseEntity, BinarySensorEntity):
    """Base class for pfSense binary sensors."""

    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        entity_description: BinarySensorEntityDescription,
        enabled_default: bool,
    ) -> None:
        """Initialize the sensor."""
        self.config_entry = config_entry
        self.entity_description = entity_description
        self.coordinator = coordinator
        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_name = f"{self.pfsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.pfsense_device_unique_id}_{entity_description.key}"
        )

    @property
    def is_on(self):
        """Return true if the entity is on."""
        return False

    @property
    def device_class(self):
        """Return the device class."""
        return None

    @property
    def extra_state_attributes(self):
        """Return the entity's extra state attributes."""
        return None


class PfSenseCarpStatusBinarySensor(PfSenseBinarySensor):
    """Binary sensor for the CARP maintenance/enable state."""

    @property
    def is_on(self):
        """Return true if the entity is on."""
        state = self.coordinator.data
        try:
            return state["carp_status"]
        except KeyError:
            return STATE_UNKNOWN


class PfSensePendingNoticesBinarySensor(PfSenseBinarySensor):
    """On while pfSense has notices pending (the web UI's bell icon)."""

    @property
    def _notices(self) -> dict | None:
        notices = (self.coordinator.data or {}).get("notices")
        return notices if isinstance(notices, dict) else None

    @property
    def available(self):
        """Unavailable when the backend cannot read notices (no shell/PHP)."""
        return self._notices is not None and super().available

    @property
    def is_on(self):
        """Return true while any notice is pending."""
        return bool((self._notices or {}).get("count"))

    @property
    def extra_state_attributes(self):
        """The pending count and the newest notices."""
        notices = self._notices or {}
        return {
            "pending_count": notices.get("count", 0),
            "latest_notices": notices.get("latest", []),
        }


class PfSenseNtpSyncBinarySensor(PfSenseBinarySensor):
    """On while ntpd has selected a peer to sync to."""

    @property
    def _ntp(self) -> dict | None:
        ntp = (self.coordinator.data or {}).get("ntp")
        return ntp if isinstance(ntp, dict) else None

    @property
    def available(self):
        """Unavailable when the backend has no NTP status."""
        return self._ntp is not None and super().available

    @property
    def is_on(self):
        """Return true while a peer is selected."""
        return bool((self._ntp or {}).get("synchronized"))

    @property
    def extra_state_attributes(self):
        """Service state and every peer's status."""
        ntp = self._ntp or {}
        peer = ntp.get("peer") or {}
        return {
            "service_enabled": ntp.get("enabled"),
            "peer": peer.get("server"),
            "peers": [
                {k: p.get(k) for k in ("server", "status", "stratum", "offset_ms")}
                for p in ntp.get("peers") or []
            ],
        }
