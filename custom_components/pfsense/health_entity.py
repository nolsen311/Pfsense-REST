"""Diagnostic entities that report the integration's own health (issue #14).

They live on the firewall's device next to its other entities, stay available
while the firewall is unreachable (that is when they matter), and update from
the :class:`~.health.HealthTracker` after every poll, success or failure.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.components.button import ButtonEntity
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.core import callback
from homeassistant.util import dt as dt_util, slugify

from . import PfSenseEntity
from .const import DOMAIN, HEALTH
from .health import STATUS_OPTIONS, HealthTracker


class PfSenseHealthEntity(PfSenseEntity):
    """Base for the health entities."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        config_entry,
        coordinator,
        key: str,
        name: str,
        icon: str,
        *,
        enabled_default: bool = True,
    ) -> None:
        """Bind to the entry's coordinator; ``key`` makes the unique id."""
        self.config_entry = config_entry
        self.coordinator = coordinator
        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_icon = icon
        self._attr_name = f"{self.pfsense_device_name} {name}"
        self._attr_unique_id = slugify(f"{self.pfsense_device_unique_id}_health_{key}")

    @property
    def health(self) -> HealthTracker:
        """The entry's health tracker."""
        return self.hass.data[DOMAIN][self.config_entry.entry_id][HEALTH]

    @property
    def available(self) -> bool:
        """Health entities stay available when everything else is not."""
        return True

    async def async_added_to_hass(self) -> None:
        """Also update after polls the coordinator does not announce."""
        await super().async_added_to_hass()
        self.async_on_remove(self.health.async_add_listener(self._on_health))

    @callback
    def _on_health(self) -> None:
        self.async_write_ha_state()


def _ts(value: float | None) -> str | None:
    return dt_util.utc_from_timestamp(value).isoformat() if value else None


class PfSenseApiConnectedBinarySensor(PfSenseHealthEntity, BinarySensorEntity):
    """On while the latest poll got live data from the firewall."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    @property
    def is_on(self) -> bool:
        """Return whether the API answered the latest poll."""
        return self.health.connected

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Explain an off state."""
        h = self.health
        return {
            "last_success": _ts(h.last_success),
            "error_kind": h.poll_error_kind,
            "using_cache": h.using_cache,
            "cache_age_seconds": round(h.cache_age)
            if h.cache_age is not None
            else None,
        }


class PfSenseIntegrationStatusSensor(PfSenseHealthEntity, SensorEntity):
    """One-word health summary, with the details as attributes."""

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = STATUS_OPTIONS

    @property
    def native_value(self) -> str:
        """Return the overall status."""
        return self.health.status

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return what is failing and why."""
        h = self.health
        return {
            "backend": h.backend,
            "failing_checks": h.failing_checks,
            "error_kind": h.poll_error_kind,
            "error": h.poll_error_message,
            "consecutive_failures": h.consecutive_failures,
            "using_cache": h.using_cache,
            "cache_age_seconds": round(h.cache_age)
            if h.cache_age is not None
            else None,
            "last_success": _ts(h.last_success),
            "checks": {
                name: "ok" if check.ok else check.kind
                for name, check in sorted(h.checks.items())
            },
        }


class PfSenseLastPollSensor(PfSenseHealthEntity, SensorEntity):
    """When the firewall last returned live data."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP

    @property
    def native_value(self) -> datetime | None:
        """Return the time of the last successful poll."""
        value = self.health.last_success
        return dt_util.utc_from_timestamp(value) if value else None


class PfSenseApiLatencySensor(PfSenseHealthEntity, SensorEntity):
    """How long the latest successful poll took."""

    _attr_device_class = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement = UnitOfTime.MILLISECONDS
    _attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def native_value(self) -> int | None:
        """Return the poll latency in milliseconds."""
        return self.health.latency_ms


class PfSenseRunHealthCheckButton(PfSenseHealthEntity, ButtonEntity):
    """Poll now, re-running every check."""

    async def async_press(self) -> None:
        """Refresh the coordinator; the health entities update from the result."""
        await self.coordinator.async_refresh()


def build_health_sensors(config_entry, coordinator) -> list[PfSenseHealthEntity]:
    """The sensor-platform health entities."""
    return [
        PfSenseIntegrationStatusSensor(
            config_entry, coordinator, "status", "Integration Status", "mdi:heart-pulse"
        ),
        PfSenseLastPollSensor(
            config_entry,
            coordinator,
            "last_successful_poll",
            "Last Successful Poll",
            "mdi:clock-check-outline",
        ),
        PfSenseApiLatencySensor(
            config_entry,
            coordinator,
            "api_latency",
            "API Latency",
            "mdi:timer-outline",
            enabled_default=False,
        ),
    ]
