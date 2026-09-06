"""Config flow for the pfSense integration (REST API v2)."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_NAME, CONF_SCAN_INTERVAL, CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv
from homeassistant.util import slugify

from .const import (
    CONF_API_KEY,
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICES,
    CONF_RULE_SWITCH_KILL_STATES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_RULE_SWITCH_KILL_STATES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)
from .pypfsense import (
    Client,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
)

_LOGGER = logging.getLogger(__name__)


class InvalidURL(Exception):
    """The URL is missing a scheme or host."""


def _normalize_url(raw: str) -> str:
    parts = urlparse(raw.strip())
    if not parts.scheme or not parts.netloc:
        raise InvalidURL
    return f"{parts.scheme}://{parts.netloc}"


async def _validate(hass, url: str, api_key: str, verify_ssl: bool) -> dict:
    """Return the system_info dict, or raise a typed pypfsense error."""
    session = async_get_clientsession(hass, verify_ssl)
    client = Client(url, api_key, session, {"verify_ssl": verify_ssl})
    return await client.get_system_info()


class ConfigFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for pfSense."""

    # Bumping this triggers async_migrate_entry. v3 == XML-RPC -> REST API v2.
    VERSION = 3

    def __init__(self) -> None:
        self._reauth_entry: config_entries.ConfigEntry | None = None

    async def async_step_user(self, user_input=None):
        """Initial setup step."""
        errors: dict[str, str] = {}
        user_input = user_input or {}

        if user_input:
            try:
                url = _normalize_url(user_input[CONF_URL])
                api_key = user_input[CONF_API_KEY].strip()
                verify_ssl = user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
                name = user_input.get(CONF_NAME) or None

                system_info = await _validate(self.hass, url, api_key, verify_ssl)

                await self.async_set_unique_id(
                    slugify(system_info["netgate_device_id"])
                )
                self._abort_if_unique_id_configured()

                if name is None:
                    name = "{}.{}".format(
                        system_info.get("hostname"), system_info.get("domain")
                    )

                return self.async_create_entry(
                    title=name,
                    data={
                        CONF_URL: url,
                        CONF_API_KEY: api_key,
                        CONF_VERIFY_SSL: verify_ssl,
                    },
                )
            except InvalidURL:
                errors["base"] = "invalid_url_format"
            except PfSenseAuthError:
                errors["base"] = "invalid_auth"
            except PfSensePrivilegeError:
                errors["base"] = "privilege_missing"
            except PfSenseNotFoundError:
                errors["base"] = "api_not_found"
            except PfSenseConnectionError as err:
                if "certificate" in str(err).lower() or "ssl" in str(err).lower():
                    errors["base"] = "cannot_connect_ssl"
                else:
                    errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error validating pfSense connection")
                errors["base"] = "unknown"

        schema = vol.Schema(
            {
                vol.Required(CONF_URL, default=user_input.get(CONF_URL, "")): str,
                vol.Required(
                    CONF_API_KEY, default=user_input.get(CONF_API_KEY, "")
                ): str,
                vol.Optional(
                    CONF_VERIFY_SSL,
                    default=user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                ): bool,
                vol.Optional(CONF_NAME, default=user_input.get(CONF_NAME, "")): str,
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={"example_url": "https://pfsense.local:8444"},
        )

    async def async_step_import(self, user_input):
        """Handle YAML import."""
        return await self.async_step_user(user_input)

    async def async_step_reauth(self, entry_data):
        """Triggered when auth fails, or by the v2 -> v3 migration."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        """Ask the user for an API key for an existing entry."""
        errors: dict[str, str] = {}
        entry = self._reauth_entry
        assert entry is not None

        if user_input is not None:
            api_key = user_input[CONF_API_KEY].strip()
            url = entry.data[CONF_URL]
            verify_ssl = entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
            try:
                system_info = await _validate(self.hass, url, api_key, verify_ssl)
            except PfSenseAuthError:
                errors["base"] = "invalid_auth"
            except PfSensePrivilegeError:
                errors["base"] = "privilege_missing"
            except (PfSenseConnectionError, PfSenseNotFoundError):
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during pfSense reauth")
                errors["base"] = "unknown"
            else:
                new_unique_id = slugify(system_info["netgate_device_id"])
                if entry.unique_id and entry.unique_id != new_unique_id:
                    return self.async_abort(reason="wrong_device")
                new_data = {
                    CONF_URL: url,
                    CONF_API_KEY: api_key,
                    CONF_VERIFY_SSL: verify_ssl,
                }
                self.hass.config_entries.async_update_entry(entry, data=new_data)
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_API_KEY): str}),
            errors=errors,
            description_placeholders={"name": entry.title},
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return OptionsFlowHandler()


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle the pfSense options flow."""

    def __init__(self) -> None:
        self.new_options: dict | None = None

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            if user_input.get(CONF_DEVICE_TRACKER_ENABLED):
                self.new_options = user_input
                return await self.async_step_device_tracker()
            return self.async_create_entry(title="", data=user_input)

        opts = self.config_entry.options
        base_schema = {
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=opts.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=10, max=300)),
            vol.Optional(
                CONF_DEVICE_TRACKER_ENABLED,
                default=opts.get(
                    CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
                ),
            ): bool,
            vol.Optional(
                CONF_DEVICE_TRACKER_SCAN_INTERVAL,
                default=opts.get(
                    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
                    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
                ),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=30, max=300)),
            vol.Optional(
                CONF_DEVICE_TRACKER_CONSIDER_HOME,
                default=opts.get(
                    CONF_DEVICE_TRACKER_CONSIDER_HOME,
                    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
                ),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=0, max=600)),
            vol.Optional(
                CONF_RULE_SWITCH_KILL_STATES,
                default=opts.get(
                    CONF_RULE_SWITCH_KILL_STATES,
                    DEFAULT_RULE_SWITCH_KILL_STATES,
                ),
            ): bool,
        }
        return self.async_show_form(step_id="init", data_schema=vol.Schema(base_schema))

    async def async_step_device_tracker(self, user_input=None):
        """Let the user pick which MACs to track from the live ARP table."""
        entry = self.config_entry
        url = entry.data[CONF_URL]
        api_key = entry.data[CONF_API_KEY]
        verify_ssl = entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
        session = async_get_clientsession(self.hass, verify_ssl)
        client = Client(url, api_key, session, {"verify_ssl": verify_ssl})

        if user_input is None and (arp_table := await client.get_arp_table(True)):
            selected_devices = entry.options.get(CONF_DEVICES, [])
            entries = {device: device for device in selected_devices}
            for row in arp_table:
                mac = (row.get("mac_address") or "").lower()
                if not mac:
                    continue
                hostname = (row.get("hostname") or "").strip("?").strip()
                ip = (row.get("ip_address") or "").strip()
                entries[mac] = f"{mac} - {hostname} ({ip})"

            return self.async_show_form(
                step_id="device_tracker",
                data_schema=vol.Schema(
                    {
                        vol.Optional(
                            CONF_DEVICES, default=selected_devices
                        ): cv.multi_select(entries),
                    }
                ),
            )

        if user_input:
            self.new_options[CONF_DEVICES] = user_input[CONF_DEVICES]
        return self.async_create_entry(title="", data=self.new_options)
