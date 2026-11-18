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
    CONF_FIRMWARE_SAFE_UPGRADE,
    COORDINATOR,
    DEFAULT_FIRMWARE_INSTALL_UNVERIFIED,
    DEFAULT_FIRMWARE_SAFE_UPGRADE,
    DOMAIN,
    SAFE_UPGRADE,
)
from .pypfsense import BACKEND_NETGATE, CONF_BACKEND, PfSenseError

_LOGGER = logging.getLogger(__name__)

# Give up showing "installing" if the version hasn't changed after this long.
INSTALL_TIMEOUT = 2 * 3600
PACKAGE_INSTALL_TIMEOUT = 30 * 60
UNVERIFIED_SUMMARY = (
    "Experimental: installing from Home Assistant has not been verified on "
    "hardware yet. The firewall reboots during the upgrade, and Home Assistant "
    "loses its connection until it is back."
)
SAFE_UPGRADE_SUMMARY = (
    "Safe upgrade is on: Install takes a boot environment snapshot, saves an "
    "encrypted config backup in Home Assistant, removes the add-on packages "
    "(except the keep list), upgrades, then reinstalls them."
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

        entities.extend(
            PfSensePackageUpdate(
                config_entry,
                coordinator,
                UpdateEntityDescription(
                    key=f"package.{package['name']}",
                    name=f"Package {package['name']}",
                    entity_category=EntityCategory.DIAGNOSTIC,
                ),
                True,
                package["name"],
            )
            for package in data_packages(coordinator.data)
        )

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
            return (
                UpdateEntityFeature.INSTALL
                | UpdateEntityFeature.PROGRESS
                | UpdateEntityFeature.BACKUP
            )
        return UpdateEntityFeature(0)

    @property
    def _safe_upgrade(self):
        """The safe-upgrade manager when that option is on, else ``None``."""
        if not self.config_entry.options.get(
            CONF_FIRMWARE_SAFE_UPGRADE, DEFAULT_FIRMWARE_SAFE_UPGRADE
        ):
            return None
        data = self.hass.data[DOMAIN].get(self.config_entry.entry_id) or {}
        return data.get(SAFE_UPGRADE)

    async def async_added_to_hass(self) -> None:
        """Also refresh when the safe upgrade moves on a stage."""
        await super().async_added_to_hass()
        data = self.hass.data[DOMAIN].get(self.config_entry.entry_id) or {}
        if (manager := data.get(SAFE_UPGRADE)) is not None:
            self.async_on_remove(manager.async_add_listener(self.async_write_ha_state))

    @property
    def release_summary(self) -> str | None:
        """Warn next to the Install button while the path is unverified."""
        if not self._install_allowed:
            return None
        if self._safe_upgrade is not None:
            return f"{UNVERIFIED_SUMMARY} {SAFE_UPGRADE_SUMMARY}"
        return UNVERIFIED_SUMMARY

    @property
    def in_progress(self):
        """Installing until the installed version changes (or it times out)."""
        manager = self._safe_upgrade
        if manager is not None and manager.plan is not None:
            return manager.in_progress
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
        if (manager := self._safe_upgrade) is not None:
            # Snapshot, backup, remove packages, upgrade, reinstall: in the
            # background, since it spans the firewall's reboot.
            await manager.async_start(self.installed_version)
            self.async_write_ha_state()
            return
        if backup:
            await _snapshot_before_install(self._get_pfsense_client())
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

        if (manager := self._safe_upgrade) is not None and manager.plan:
            attrs.update(manager.attributes())

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


async def _snapshot_before_install(client) -> None:
    """Take a boot environment snapshot ("back up first"); abort if it fails."""
    try:
        name = await client.create_boot_environment()
    except PfSenseError as err:
        raise HomeAssistantError(
            f"Could not create a boot environment, so nothing was installed: {err}"
        ) from err
    _LOGGER.info("Created boot environment %s before installing", name)


def data_packages(state: dict | None) -> list[dict]:
    """The poll's package list (empty on backends without it)."""
    packages = (state or {}).get("packages") or []
    return [p for p in packages if isinstance(p, dict) and p.get("name")]


class PfSensePackageUpdate(PfSenseUpdate):
    """Update entity for one add-on package (Netgate API)."""

    _installing_from: str | None = None
    _install_started: float = 0.0

    def __init__(
        self, config_entry, coordinator, entity_description, enabled_default, name
    ):
        """Initialize for package ``name`` (its pfSense internal name)."""
        super().__init__(config_entry, coordinator, entity_description, enabled_default)
        self._package_name = name

    @property
    def _package(self) -> dict | None:
        return next(
            (
                p
                for p in data_packages(self.coordinator.data)
                if p["name"] == self._package_name
            ),
            None,
        )

    @property
    def available(self):
        """Unavailable once the package is no longer installed."""
        return self._package is not None and super().available

    @property
    def title(self):
        """Return the title."""
        return self._package_name

    @property
    def installed_version(self):
        """Version installed and in use."""
        return (self._package or {}).get("installed_version")

    @property
    def latest_version(self):
        """Latest version in pfSense's package catalog."""
        return (self._package or {}).get("latest_version")

    @property
    def supported_features(self) -> UpdateEntityFeature:
        """Install on the Netgate backend; PROGRESS so HA reads in_progress."""
        if self.config_entry.data.get(CONF_BACKEND) == BACKEND_NETGATE:
            return (
                UpdateEntityFeature.INSTALL
                | UpdateEntityFeature.PROGRESS
                | UpdateEntityFeature.BACKUP
            )
        return UpdateEntityFeature(0)

    @property
    def in_progress(self):
        """Installing until the installed version changes (or it times out)."""
        if self._installing_from is None:
            return False
        if (
            self.installed_version != self._installing_from
            or time.monotonic() - self._install_started > PACKAGE_INSTALL_TIMEOUT
        ):
            self._installing_from = None
            return False
        return True

    @property
    def extra_state_attributes(self):
        """Package details."""
        pkg = self._package or {}
        return {
            "package": pkg.get("package"),
            "description": pkg.get("descr"),
            "category": pkg.get("category"),
        }

    @property
    def release_url(self):
        """No per-package release notes URL."""
        return None

    async def async_install(
        self, version: str | None, backup: bool, **kwargs: Any
    ) -> None:
        """Upgrade the package to its latest version."""
        if not self.supported_features & UpdateEntityFeature.INSTALL:
            raise HomeAssistantError("Package install needs the Netgate API")
        if backup:
            await _snapshot_before_install(self._get_pfsense_client())
        try:
            await self._get_pfsense_client().install_package_update(self._package_name)
        except PfSenseError as err:
            raise HomeAssistantError(f"Could not upgrade the package: {err}") from err
        self._installing_from = self.installed_version
        self._install_started = time.monotonic()
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()
