"""pfSense integration."""

import logging
import time
from typing import Any

from homeassistant.components.update import (
    UpdateDeviceClass,
    UpdateEntity,
    UpdateEntityDescription,
    UpdateEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_platform
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify

from . import CoordinatorEntityManager, PfSenseEntity, dict_get
from .const import (
    CONF_FIRMWARE_INSTALL_UNVERIFIED,
    COORDINATOR,
    DEFAULT_FIRMWARE_INSTALL_UNVERIFIED,
    DOMAIN,
)
from .pypfsense import BACKEND_NETGATE, CONF_BACKEND, PfSenseError

_LOGGER = logging.getLogger(__name__)

# Give up showing "installing" if the version hasn't changed after this long.
INSTALL_TIMEOUT = 2 * 3600
UNVERIFIED_SUMMARY = (
    "Experimental: installing from Home Assistant has not been verified on "
    "hardware yet. The firewall reboots during the upgrade, and Home Assistant "
    "loses its connection until it is back."
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
):
    """Set up the pfSense update entities."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        entities = []
        entity = PfSenseFirmwareUpdatesAvailableUpdate(
            config_entry,
            coordinator,
            UpdateEntityDescription(
                key="firmware.update_available",
                name="Firmware Updates Available",
                entity_category=EntityCategory.DIAGNOSTIC,
            ),
            True,
        )
        entities.append(entity)

        return entities

    cem = CoordinatorEntityManager(
        hass,
        hass.data[DOMAIN][config_entry.entry_id][COORDINATOR],
        config_entry,
        process_entities_callback,
        async_add_entities,
    )
    cem.process_entities()


class PfSenseUpdate(PfSenseEntity, UpdateEntity):
    """Base class for the pfSense update entity."""

    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        entity_description: UpdateEntityDescription,
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

        # The Netgate API reports installed/latest base-system versions
        # (``/system/update``); pfrest has no such data, so the entity is
        # unavailable there. Install is Netgate-only and opt-in (see
        # CONF_FIRMWARE_INSTALL_UNVERIFIED) until verified on hardware.

    @property
    def device_class(self):
        """Return the device class."""
        return UpdateDeviceClass.FIRMWARE


class PfSenseFirmwareUpdatesAvailableUpdate(PfSenseUpdate):
    """Update entity reporting available package upgrades."""

    @property
    def available(self):
        """Return whether the entity is available."""
        state = self.coordinator.data
        if (
            state["firmware_update_info"] is None
            or dict_get(state, "firmware_update_info.base") is False
            or dict_get(state, "firmware_update_info.base") is None
        ):
            return False

        return super().available

    @property
    def title(self):
        """Return the title."""
        return "pfSense"

    @property
    def installed_version(self):
        """Version installed and in use."""
        state = self.coordinator.data

        try:
            return dict_get(state, "firmware_update_info.base.installed_version")
        except KeyError:
            return None

    @property
    def latest_version(self):
        """Latest version available for install."""
        state = self.coordinator.data

        try:
            # fake a new update
            # return "foobar"
            return dict_get(state, "firmware_update_info.base.version")
        except KeyError:
            return None

    _installing_from: str | None = None
    _install_started: float = 0.0

    @property
    def _install_allowed(self) -> bool:
        return self.config_entry.data.get(
            CONF_BACKEND
        ) == BACKEND_NETGATE and self.config_entry.options.get(
            CONF_FIRMWARE_INSTALL_UNVERIFIED, DEFAULT_FIRMWARE_INSTALL_UNVERIFIED
        )

    @property
    def supported_features(self) -> UpdateEntityFeature:
        """Install only on Netgate entries that opted in."""
        if self._install_allowed:
            # PROGRESS makes HA use ``in_progress`` below; without it, HA only
            # shows "installing" while ``async_install`` runs, which returns
            # as soon as the upgrade has started. No percentage is reported.
            return UpdateEntityFeature.INSTALL | UpdateEntityFeature.PROGRESS
        return UpdateEntityFeature(0)

    @property
    def release_summary(self) -> str | None:
        """Warn next to the Install button while the path is unverified."""
        return UNVERIFIED_SUMMARY if self._install_allowed else None

    @property
    def in_progress(self):
        """Installing until the installed version changes (or it times out)."""
        if self._installing_from is None:
            return False
        if (
            self.installed_version != self._installing_from
            or time.monotonic() - self._install_started > INSTALL_TIMEOUT
        ):
            self._installing_from = None
            return False
        return True

    async def async_install(
        self, version: str | None, backup: bool, **kwargs: Any
    ) -> None:
        """Start the base-system upgrade (Netgate API, opt-in, unverified)."""
        if not self._install_allowed:
            raise HomeAssistantError(
                "Firmware install is not enabled for this pfSense entry"
            )
        _LOGGER.warning(
            "Starting an unverified pfSense firmware upgrade from %s on %s",
            self.installed_version,
            self.config_entry.title,
        )
        try:
            await self._get_pfsense_client().start_firmware_update()
        except PfSenseError as err:
            raise HomeAssistantError(f"Could not start the upgrade: {err}") from err
        self._installing_from = self.installed_version
        self._install_started = time.monotonic()
        self.async_write_ha_state()

    @property
    def extra_state_attributes(self):
        """Return the entity's extra state attributes."""
        state = self.coordinator.data
        attrs = {}
        info = dict_get(state, "firmware_update_info.base", {})

        if not info:
            return attrs

        for key in info:
            attrs[f"pfsense_base_{key}"] = dict_get(
                state, f"firmware_update_info.base.{key}"
            )

        return attrs

    @property
    def release_url(self):
        """Return the release notes URL."""
        return "https://docs.netgate.com/pfsense/en/latest/releases/index.html"
