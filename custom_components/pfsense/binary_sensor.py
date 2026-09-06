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
                False,
            )
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
