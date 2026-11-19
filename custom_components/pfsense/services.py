"""Home Assistant service registration for the pfSense integration."""

import logging

import voluptuous as vol

from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import async_get_platforms
from homeassistant.helpers.service import entity_service_call

from .const import (
    DOMAIN,
    PFSENSE_CLIENT,
    SERVICE_EXEC_COMMAND,
    SERVICE_KILL_STATES,
    SERVICE_RESET_STATE_TABLE,
    SERVICE_RESTART_SERVICE,
    SERVICE_SEND_WOL,
    SERVICE_SET_DEFAULT_GATEWAY,
    SERVICE_START_SERVICE,
    SERVICE_STOP_SERVICE,
    SERVICE_SYSTEM_HALT,
    SERVICE_SYSTEM_REBOOT,
)
from .pypfsense import PfSenseError, PfSenseUnsupportedError

_LOGGER = logging.getLogger(__name__)

_data = set()


def async_get_entities(hass: HomeAssistant) -> dict[str, Entity]:
    """Get entities for a domain."""
    entities: dict[str, Entity] = {}
    for platform in async_get_platforms(hass, DOMAIN):
        entities.update(platform.entities)
    return entities


class ServiceRegistrar:
    """Registers the integration's Home Assistant services once."""

    def __init__(
        self,
        hass: HomeAssistant,
    ) -> None:
        """Initialize with hass object."""
        self.hass = hass

    @callback
    def async_register(self):
        """Register the integration's services once."""
        if "loaded" in _data:
            return

        _data.add("loaded")

        # Deferred to break the services <-> __init__ import cycle.
        from . import PfSenseEntity  # noqa: PLC0415

        async def service_update_alias(
            self,
            alias_name: str,
            address: str,
            action: str,
            kill_states: bool = True,
        ):
            """Bind the update_alias service onto PfSenseEntity at runtime."""
            client = self._get_pfsense_client()
            await client.update_alias_address(alias_name, address, action, kill_states)

        if not hasattr(PfSenseEntity, "service_update_alias"):
            PfSenseEntity.service_update_alias = service_update_alias

        async def _async_send_service(call: ServiceCall):
            await entity_service_call(
                self.hass,
                async_get_entities(self.hass),
                f"service_{call.service}",
                call,
            )

        self.hass.services.async_register(
            domain=DOMAIN,
            service="update_alias",
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("alias_name"): vol.Any(cv.string),
                    vol.Required("address"): vol.Any(cv.string),
                    vol.Required("action"): vol.In(["add", "remove"]),
                    vol.Optional("kill_states", default=True): cv.boolean,
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_START_SERVICE,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("service_name"): vol.Any(cv.string),
                    vol.Optional("service"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_STOP_SERVICE,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("service_name"): vol.Any(cv.string),
                    vol.Optional("service"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_RESTART_SERVICE,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("service_name"): vol.Any(cv.string),
                    vol.Optional("only_if_running"): vol.Any(
                        cv.positive_int, cv.string, cv.boolean
                    ),
                    vol.Optional("service"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_RESET_STATE_TABLE,
            schema={},
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_KILL_STATES,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("source"): vol.Any(cv.string),
                    vol.Optional("destination"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_SYSTEM_HALT,
            schema=cv.make_entity_service_schema({}),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_SYSTEM_REBOOT,
            schema=cv.make_entity_service_schema({}),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_SEND_WOL,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("interface"): vol.Any(cv.string),
                    vol.Required("mac"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_SET_DEFAULT_GATEWAY,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("gateway"): vol.Any(cv.string),
                    vol.Required("ip_version"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_EXEC_COMMAND,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("command"): vol.Any(cv.string),
                    vol.Optional("background"): cv.boolean,
                }
            ),
            service_func=_async_send_service,
        )

        self._register_diagnostics()

    @callback
    def _register_diagnostics(self) -> None:
        """Actions that return results: the diagnostics and remove_table_entry.

        The diagnostics only read, so their response is required.
        remove_table_entry changes pf, so it can run without one.
        """
        target = {vol.Optional("config_entry_id"): cv.string}
        host = {vol.Required("host"): cv.string}
        ipv6 = {vol.Optional("ipv6", default=False): cv.boolean}
        source = {vol.Optional("source"): cv.string}
        actions = {
            "ping": (
                {
                    **target,
                    **host,
                    **ipv6,
                    **source,
                    vol.Optional("count", default=3): vol.All(
                        vol.Coerce(int), vol.Range(min=1, max=20)
                    ),
                },
                lambda c, d: c.ping(d["host"], d["count"], d.get("source"), d["ipv6"]),
            ),
            "traceroute": (
                {
                    **target,
                    **host,
                    **ipv6,
                    **source,
                    vol.Optional("max_hops", default=15): vol.All(
                        vol.Coerce(int), vol.Range(min=1, max=30)
                    ),
                },
                lambda c, d: c.traceroute(
                    d["host"], d["max_hops"], d.get("source"), d["ipv6"]
                ),
            ),
            "test_port": (
                {
                    **target,
                    **host,
                    **ipv6,
                    vol.Required("port"): vol.All(
                        vol.Coerce(int), vol.Range(min=1, max=65535)
                    ),
                },
                lambda c, d: c.test_port(d["host"], d["port"], d["ipv6"]),
            ),
            "dns_lookup": (
                {**target, **host},
                lambda c, d: c.dns_lookup(d["host"]),
            ),
            "remove_table_entry": (
                {
                    **target,
                    vol.Required("table"): cv.string,
                    vol.Required("entry"): cv.string,
                },
                lambda c, d: c.remove_pf_table_entry(d["table"], d["entry"]),
            ),
        }
        for name, (schema, run) in actions.items():

            async def handler(call: ServiceCall, run=run, name=name) -> ServiceResponse:
                client = _client_for(self.hass, call.data.get("config_entry_id"))
                try:
                    return await run(client, call.data)
                except PfSenseUnsupportedError as err:
                    raise ServiceValidationError(str(err)) from err
                except PfSenseError as err:
                    raise HomeAssistantError(f"pfSense {name} failed: {err}") from err

            self.hass.services.async_register(
                DOMAIN,
                name,
                handler,
                schema=vol.Schema(schema),
                supports_response=(
                    SupportsResponse.OPTIONAL
                    if name in _WRITE_ACTIONS
                    else SupportsResponse.ONLY
                ),
            )


_WRITE_ACTIONS = frozenset({"remove_table_entry"})


def _client_for(hass: HomeAssistant, entry_id: str | None):
    """The client of ``entry_id``, or of the only loaded firewall."""
    loaded = {
        eid: data[PFSENSE_CLIENT]
        for eid, data in (hass.data.get(DOMAIN) or {}).items()
        if isinstance(data, dict) and PFSENSE_CLIENT in data
    }
    if entry_id:
        if entry_id not in loaded:
            raise ServiceValidationError(f"No loaded pfSense entry {entry_id}")
        return loaded[entry_id]
    if len(loaded) != 1:
        raise ServiceValidationError(
            "Pick the firewall with config_entry_id"
            if loaded
            else "No pfSense firewall is loaded"
        )
    return next(iter(loaded.values()))
