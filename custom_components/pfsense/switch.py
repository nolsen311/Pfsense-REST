"""pfSense integration."""

import logging

from homeassistant.components.switch import (
    SwitchDeviceClass,
    SwitchEntity,
    SwitchEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_UNKNOWN  # ENTITY_CATEGORY_CONFIG,
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify

from . import CoordinatorEntityManager, PfSenseEntity
from .const import (
    CONF_RULE_SWITCH_KILL_STATES,
    COORDINATOR,
    DEFAULT_RULE_SWITCH_KILL_STATES,
    DOMAIN,
)

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
        state = coordinator.data

        entities = []

        # filter rules -- keyed by the pfSense internal `tracker` (stable across
        # REST/XML-RPC), so entity unique_ids survive the migration.
        for rule in state.get("firewall_rules") or []:
            if not isinstance(rule, dict):
                continue
            tracker = rule.get("tracker")
            if tracker is None:
                continue
            # skip NAT-associated rules and the un-disableable anti-lockout rule
            if rule.get("associated_rule_id"):
                continue
            if rule.get("descr") == "Anti-Lockout Rule":
                continue

            tracker = str(tracker)
            entities.append(
                PfSenseFilterSwitch(
                    config_entry,
                    coordinator,
                    SwitchEntityDescription(
                        key="filter.{}".format(tracker),
                        name="Filter Rule {} ({})".format(
                            tracker, rule.get("descr", "")
                        ),
                        icon="mdi:security-network",
                        device_class=SwitchDeviceClass.SWITCH,
                        entity_registry_enabled_default=False,
                    ),
                )
            )

        # nat rules -- keyed by `created_time` (was `created.time` under XML-RPC).
        nat_groups = (
            ("nat_port_forward", state.get("nat_port_forward_rules") or []),
            ("nat_outbound", state.get("nat_outbound_rules") or []),
        )
        for rule_type, rules in nat_groups:
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                tracker = rule.get("created_time")
                if tracker is None:
                    continue
                if rule_type == "nat_outbound" and "Auto created rule" in (
                    rule.get("descr") or ""
                ):
                    continue

                tracker = str(tracker)
                label = (
                    "NAT Port Forward Rule"
                    if rule_type == "nat_port_forward"
                    else "NAT Outbound Rule"
                )
                entities.append(
                    PfSenseNatSwitch(
                        config_entry,
                        coordinator,
                        SwitchEntityDescription(
                            key="{}.{}".format(rule_type, tracker),
                            name="{} {} ({})".format(
                                label, tracker, rule.get("descr", "")
                            ),
                            icon="mdi:network",
                            device_class=SwitchDeviceClass.SWITCH,
                            entity_registry_enabled_default=False,
                        ),
                    )
                )

        # services
        for service in state["services"]:
            for property in ["status"]:
                icon = "mdi:application-cog-outline"
                # likely only want very specific services to manipulate from actions
                enabled_default = False
                # entity_category = ENTITY_CATEGORY_CONFIG
                device_class = SwitchDeviceClass.SWITCH

                if service["name"] == "openvpn" and service.get("vpnid"):
                    key = "service.{}.{}".format(
                        service["name"] + "-" + str(service["vpnid"]),
                        property,
                    )
                    name = "Service {} {}".format(
                        service["name"] + " " + service.get("description", ""), property
                    )
                else:
                    key = "service.{}.{}".format(service["name"], property)
                    name = "Service {} {}".format(service["name"], property)

                entity = PfSenseServiceSwitch(
                    config_entry,
                    coordinator,
                    SwitchEntityDescription(
                        key=key,
                        name=name,
                        icon=icon,
                        # entity_category=entity_category,
                        device_class=device_class,
                        entity_registry_enabled_default=enabled_default,
                    ),
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


class PfSenseSwitch(PfSenseEntity, SwitchEntity):
    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize the entity."""
        self.config_entry = config_entry
        self.entity_description = entity_description
        self.coordinator = coordinator
        self._attr_name = f"{self.pfsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.pfsense_device_unique_id}_{entity_description.key}"
        )

    @property
    def is_on(self):
        return False

    @property
    def extra_state_attributes(self):
        return None

    async def _maybe_kill_rule_states(self, rule):
        """Flush the state table for a rule's hosts after a toggle, if enabled."""
        if not rule:
            return
        if not self.config_entry.options.get(
            CONF_RULE_SWITCH_KILL_STATES, DEFAULT_RULE_SWITCH_KILL_STATES
        ):
            return
        try:
            await self._get_pfsense_client().kill_states_for_rule(rule)
        except Exception:  # noqa: BLE001 - best effort; never fail the toggle
            _LOGGER.warning("failed to kill states for toggled rule", exc_info=True)


class PfSenseFilterSwitch(PfSenseSwitch):
    def _pfsense_get_tracker(self):
        return self.entity_description.key.split(".")[1]

    def _pfsense_get_rule(self):
        state = self.coordinator.data
        tracker = self._pfsense_get_tracker()
        for rule in state.get("firewall_rules") or []:
            if str(rule.get("tracker")) == tracker:
                return rule
        return None

    @property
    def available(self) -> bool:
        rule = self._pfsense_get_rule()
        if rule is None:
            return False

        return super().available

    @property
    def is_on(self):
        rule = self._pfsense_get_rule()
        if rule is None:
            return STATE_UNKNOWN
        return not rule.get("disabled")

    async def async_turn_on(self, **kwargs):
        """Turn the entity on."""
        rule = self._pfsense_get_rule()
        if rule is None:
            return
        tracker = self._pfsense_get_tracker()
        client = self._get_pfsense_client()
        await client.enable_filter_rule_by_tracker(tracker)
        await self._maybe_kill_rule_states(rule)
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs):
        """Turn the entity off."""
        rule = self._pfsense_get_rule()
        if rule is None:
            return
        tracker = self._pfsense_get_tracker()
        client = self._get_pfsense_client()
        await client.disable_filter_rule_by_tracker(tracker)
        await self._maybe_kill_rule_states(rule)
        await self.coordinator.async_refresh()


class PfSenseNatSwitch(PfSenseSwitch):
    def _pfsense_get_rule_type(self):
        return self.entity_description.key.split(".")[0]

    def _pfsense_get_tracker(self):
        return self.entity_description.key.split(".")[1]

    def _pfsense_get_rule(self):
        state = self.coordinator.data
        tracker = self._pfsense_get_tracker()
        rule_type = self._pfsense_get_rule_type()
        if rule_type == "nat_port_forward":
            rules = state.get("nat_port_forward_rules") or []
        else:
            rules = state.get("nat_outbound_rules") or []

        for rule in rules:
            if str(rule.get("created_time")) == tracker:
                return rule
        return None

    @property
    def available(self) -> bool:
        rule = self._pfsense_get_rule()
        if rule is None:
            return False

        return super().available

    @property
    def is_on(self):
        rule = self._pfsense_get_rule()
        if rule is None:
            return STATE_UNKNOWN
        return not rule.get("disabled")

    async def async_turn_on(self, **kwargs):
        """Turn the entity on."""
        rule = self._pfsense_get_rule()
        if rule is None:
            return
        tracker = self._pfsense_get_tracker()
        client = self._get_pfsense_client()
        rule_type = self._pfsense_get_rule_type()
        if rule_type == "nat_port_forward":
            method = client.enable_nat_port_forward_rule_by_created_time
        if rule_type == "nat_outbound":
            method = client.enable_nat_outbound_rule_by_created_time

        await method(tracker)
        await self._maybe_kill_rule_states(rule)
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs):
        """Turn the entity off."""
        rule = self._pfsense_get_rule()
        if rule is None:
            return
        tracker = self._pfsense_get_tracker()
        client = self._get_pfsense_client()
        rule_type = self._pfsense_get_rule_type()
        if rule_type == "nat_port_forward":
            method = client.disable_nat_port_forward_rule_by_created_time
        if rule_type == "nat_outbound":
            method = client.disable_nat_outbound_rule_by_created_time

        await method(tracker)
        await self._maybe_kill_rule_states(rule)
        await self.coordinator.async_refresh()


class PfSenseServiceSwitch(PfSenseSwitch):
    def _pfsense_get_property_name(self):
        return self.entity_description.key.split(".")[2]

    def _pfsense_get_service_name(self):
        return self.entity_description.key.split(".")[1]

    def _pfsense_get_service(self):
        state = self.coordinator.data
        found = None
        service_name = self._pfsense_get_service_name()
        for service in state["services"]:
            if service_name.startswith("openvpn"):
                # [ "openvpn", "<vpnid>""]
                parts = service_name.split("-")
                if service["name"] == parts[0] and str(
                    service.get("vpnid")
                ) == parts[1]:
                    found = service
            elif service["name"] == service_name:
                found = service
                break
        return found

    @property
    def available(self) -> bool:
        service = self._pfsense_get_service()
        property = self._pfsense_get_property_name()
        if service is None or property not in service:
            return False

        return super().available

    @property
    def is_on(self):
        service = self._pfsense_get_service()
        property = self._pfsense_get_property_name()
        try:
            value = service[property]
            return value
        except KeyError:
            return STATE_UNKNOWN

    async def async_turn_on(self, **kwargs):
        """Turn the entity on."""
        service = self._pfsense_get_service()
        client = self._get_pfsense_client()
        await client.start_service(service["name"], service)
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs):
        """Turn the entity off."""
        service = self._pfsense_get_service()
        client = self._get_pfsense_client()
        await client.stop_service(service["name"], service)
        await self.coordinator.async_refresh()
